use crate::ctx::{Ctx, Out};
use crate::pipeline;
use anyhow::Result;
use rusqlite::params;
use rustc_hash::FxHashMap;
use std::time::{Duration, Instant};
use stella_core::store::Row;
use stella_dns::engine::Config;
use stella_net::client::{self, Options};
use stella_probe::rules::REVIEW;
use stella_sources::cname::{self, Tally, Vendor};
use stella_sources::toplist;

const SEED_CAP: usize = 64 * 1024 * 1024;
pub const PRODUCT: &str = "cname-vendor";

pub struct Learn {
    pub sample: usize,
    pub top: usize,
    pub list: String,
    pub min_zones: usize,
    pub min_lift: f64,
}

async fn seeds(ctx: &Ctx) -> Result<Vec<Vendor>> {
    let c = client::build(&Options {
        timeout: Duration::from_secs(120),
        ..Options::default()
    })?;
    let known = ctx.known();
    let mut out = Vec::new();
    match client::fetch(&c, cname::ADGUARD_TRACKERS, SEED_CAP).await {
        Ok(p) if p.status == 200 => out.extend(
            cname::plain_domains(&String::from_utf8_lossy(&p.body))
                .into_iter()
                .map(|s| Vendor {
                    suffix: s,
                    listed: 0,
                    background: 0,
                    source: "adguard-trackers",
                }),
        ),
        Ok(p) => eprintln!("cname seeds trackers: http {}", p.status),
        Err(e) => eprintln!("cname seeds trackers: {e}"),
    }
    match client::fetch(&c, cname::ADGUARD_ADS, SEED_CAP).await {
        Ok(p) if p.status == 200 => out.extend(
            cname::disguised_targets(&p.body, cname::ADGUARD_ADS_MIN)
                .into_iter()
                .map(|(s, _)| Vendor {
                    suffix: s,
                    listed: 0,
                    background: 0,
                    source: "adguard-ads",
                }),
        ),
        Ok(p) => eprintln!("cname seeds ads: http {}", p.status),
        Err(e) => eprintln!("cname seeds ads: {e}"),
    }
    out.retain(|v| !known.contains(&v.suffix) && !cname::generic(&v.suffix));
    Ok(out)
}

async fn risky() -> Result<Vec<String>> {
    let c = client::build(&Options {
        timeout: Duration::from_secs(120),
        ..Options::default()
    })?;
    let mut out = Vec::new();
    for url in cname::ADGUARD_RISKY {
        match client::fetch(&c, url, SEED_CAP).await {
            Ok(p) if p.status == 200 => out.extend(
                cname::disguised_targets(&p.body, cname::ADGUARD_RISKY_MIN)
                    .into_iter()
                    .map(|(s, _)| s)
                    .filter(|s| !cname::generic(s)),
            ),
            Ok(p) => eprintln!("cname risky {url}: http {}", p.status),
            Err(e) => eprintln!("cname risky {url}: {e}"),
        }
    }
    Ok(out)
}

pub async fn learn(ctx: &mut Ctx, dns: &Config, args: &Learn) -> Result<usize> {
    let started = Instant::now();
    let seeded = seeds(ctx).await?;
    let mut listed: Vec<String> = ctx.known().domains().map(str::to_string).collect();
    listed.sort_unstable();
    let step = (listed.len() / args.sample.max(1)).max(1);
    let mut names: Vec<String> = listed.into_iter().step_by(step).collect();
    let c = client::build(&Options::default())?;
    let path = toplist::fetch(&c, &args.list, &ctx.paths.cache()).await?;
    for (_, n) in toplist::read(&path, args.top)? {
        names.push(format!("www.{n}"));
        names.push(n);
    }
    names.sort_unstable();
    names.dedup();
    let w = ctx.store.writer()?;
    let res = pipeline::resolve(ctx, &w, dns, names, false).await?;
    w.finish()?;
    let known = ctx.known();
    let mut tally = Tally::default();
    for n in res.iter().filter(|n| !n.res.chain.is_empty()) {
        let chain: Vec<&str> = n.res.chain.iter().map(String::as_str).collect();
        tally.add(&ctx.psl, &n.res.host, &chain, known.contains(&n.res.host));
    }
    let learned = tally.vendors(known, args.min_zones, args.min_lift);
    let mut all: FxHashMap<String, Vendor> = FxHashMap::default();
    let before = seeded.len();
    let seeded: Vec<Vendor> = seeded
        .into_iter()
        .filter(|v| tally.background_of(&v.suffix) <= cname::SEED_MAX_BACKGROUND)
        .collect();
    eprintln!(
        "cname seeds: {} of {before} kept, the rest are common on top sites",
        seeded.len()
    );
    for v in seeded {
        all.insert(v.suffix.clone(), v);
    }
    for v in learned {
        all.entry(v.suffix.clone())
            .and_modify(|s| {
                s.listed = v.listed;
                s.background = v.background;
            })
            .or_insert(v);
    }
    let risky = risky().await?;
    let before = all.len();
    all.retain(|s, _| !risky.iter().any(|r| cname::overlaps(s, r)));
    eprintln!(
        "cname vendors: {} dropped as click-through or landing page hosts",
        before - all.len()
    );
    let tx = ctx.store.conn.unchecked_transaction()?;
    tx.execute("DELETE FROM vendor", [])?;
    {
        let mut ins = tx.prepare_cached("INSERT INTO vendor VALUES(?1, ?2, ?3, ?4)")?;
        for v in all.values() {
            ins.execute(params![
                v.suffix,
                v.listed as i64,
                v.background as i64,
                v.source
            ])?;
        }
    }
    tx.commit()?;
    ctx.store.conn.execute(
        "INSERT OR REPLACE INTO done VALUES('cname-learn', 'all', ?1)",
        [stella_core::now()],
    )?;
    let by = |s: &str| all.values().filter(|v| v.source == s).count();
    eprintln!(
        "cname vendors: resolved={} learned={} adguard-trackers={} adguard-ads={} secs={:.1}",
        res.len(),
        by("learned"),
        by("adguard-trackers"),
        by("adguard-ads"),
        started.elapsed().as_secs_f64()
    );
    Ok(all.len())
}

fn vendors(ctx: &Ctx) -> Result<FxHashMap<String, Vendor>> {
    Ok(ctx
        .store
        .rows("SELECT suffix, listed, background, source FROM vendor")?
        .into_iter()
        .filter_map(|r| {
            let source = match r[3].as_str() {
                "adguard-trackers" => "adguard-trackers",
                "adguard-ads" => "adguard-ads",
                _ => "learned",
            };
            Some((
                r[0].clone(),
                Vendor {
                    suffix: r[0].clone(),
                    listed: r[1].parse().ok()?,
                    background: r[2].parse().ok()?,
                    source,
                },
            ))
        })
        .collect())
}

fn why(link: &str, v: &Vendor) -> String {
    match v.source {
        "learned" => format!(
            "CNAME to {link}, under {} where {} included zones point",
            v.suffix, v.listed
        ),
        s => format!("CNAME to {link}, under {} from {s}", v.suffix),
    }
}

pub fn matches(ctx: &Ctx) -> Result<Vec<(String, String)>> {
    let vendors = vendors(ctx)?;
    if vendors.is_empty() {
        eprintln!("cname vendors: none stored, run stella source cname-vendors first");
        return Ok(Vec::new());
    }
    let rows = ctx.store.rows(
        "SELECT host, chain FROM resolution WHERE known = '' AND chain != '' AND addrs != '' AND wild != 'WILD'",
    )?;
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    let mut found = Vec::new();
    for r in &rows {
        let zone = ctx.psl.icann_regdom_or_self(&r[0]);
        if r[0] == zone || r[0].strip_prefix("www.") == Some(zone) {
            continue;
        }
        let chain: Vec<&str> = r[1].split('>').collect();
        let Some((link, v)) = cname::matched(&ctx.psl, &r[0], &chain, &vendors) else {
            continue;
        };
        let evidence = why(link, v);
        out.row(&[&r[0], &v.suffix, v.source, &evidence]);
        w.send(Row::Origin {
            host: r[0].clone(),
            source: PRODUCT.into(),
            detail: v.suffix.clone(),
        });
        w.send(Row::Hit {
            host: r[0].clone(),
            product: PRODUCT.into(),
            evidence: evidence.clone(),
            verdict: REVIEW.into(),
        });
        found.push((r[0].clone(), evidence));
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "cname vendors: vendors={} resolved-unknown={} matched={}",
        vendors.len(),
        rows.len(),
        found.len()
    );
    Ok(found)
}
