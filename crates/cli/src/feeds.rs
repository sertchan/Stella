use crate::ctx::{Ctx, Out, stdin_names, stdin_rows};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use std::time::{Duration, Instant};
use stella_core::store::Row;
use stella_net::client::{self, Options};
use stella_sources::{adtech, scripts, vendors};
use tokio::task::JoinSet;

const PREBID_CAP: u64 = 400 * 1024 * 1024;
const GVL_CAP: usize = 64 * 1024 * 1024;
const DISCLOSURE_CAP: usize = 4 * 1024 * 1024;
const SCRIPT_CAP: usize = 6 * 1024 * 1024;
const REPORT_CAP: usize = 20 * 1024 * 1024;
const PASSIVE_CAP: usize = 64 * 1024 * 1024;
const PASSIVE_TRIES: u64 = 3;

fn web(timeout: u64) -> Result<reqwest::Client> {
    client::build(&Options {
        timeout: Duration::from_secs(timeout),
        redirects: 3,
        insecure: true,
        http1_only: true,
    })
}

async fn each<T: Send + 'static, F, Fut>(
    items: Vec<String>,
    par: usize,
    f: F,
    mut sink: impl FnMut(String, T),
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = T> + Send + 'static,
{
    let mut set = JoinSet::new();
    let mut it = items.into_iter();
    loop {
        while set.len() < par.max(1) {
            let Some(item) = it.next() else { break };
            let fut = f(item.clone());
            set.spawn(async move { (item, fut.await) });
        }
        match set.join_next().await {
            Some(Ok((item, r))) => sink(item, r),
            Some(Err(_)) => {}
            None => break,
        }
    }
}

pub async fn adtech(ctx: &mut Ctx, par: usize, min_intermediary: usize) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("adstxt")?;
    let sites: Vec<String> = stdin_names()
        .into_iter()
        .filter(|s| !done.contains(s))
        .collect();
    let c = web(20)?;
    let w = ctx.store.writer()?;
    let mut systems: FxHashMap<String, usize> = FxHashMap::default();
    let (mut with_ads, mut with_app_ads, total) = (0usize, 0usize, sites.len());
    let cc = c.clone();
    each(
        sites,
        par,
        move |s| {
            let c = cc.clone();
            async move {
                (
                    adtech::well_known(&c, &s, "ads.txt").await,
                    adtech::well_known(&c, &s, "app-ads.txt").await,
                )
            }
        },
        |site, (web, app)| {
            for (body, count) in [(web, &mut with_ads), (app, &mut with_app_ads)] {
                let Some(b) = body else { continue };
                let list = adtech::parse_ads_txt(&String::from_utf8_lossy(&b));
                *count += usize::from(!list.is_empty());
                for d in list {
                    *systems.entry(d).or_default() += 1;
                }
            }
            w.send(Row::Done {
                kind: "adstxt".into(),
                key: site,
            });
        },
    )
    .await;
    let names: Vec<String> = systems.keys().cloned().collect();
    let mut sellers: FxHashSet<String> = FxHashSet::default();
    let mut inter: FxHashMap<String, usize> = FxHashMap::default();
    let cc = c.clone();
    each(
        names,
        par,
        move |s| {
            let c = cc.clone();
            async move { adtech::well_known(&c, &s, "sellers.json").await }
        },
        |sys, body| {
            if let Some(list) = body.as_deref().and_then(adtech::parse_sellers) {
                sellers.insert(sys);
                for d in list {
                    *inter.entry(d).or_default() += 1;
                }
            }
        },
    )
    .await;
    let known = ctx.known();
    let mut companies: FxHashMap<String, (String, usize)> = FxHashMap::default();
    for s in &sellers {
        companies.insert(
            ctx.psl.icann_regdom_or_self(s).to_string(),
            ("sellers.json".into(), systems[s]),
        );
    }
    for (d, n) in inter.iter().filter(|(_, n)| **n >= min_intermediary) {
        companies
            .entry(ctx.psl.icann_regdom_or_self(d).to_string())
            .or_insert(("intermediary".into(), *n));
    }
    let mut rows: Vec<_> = companies
        .into_iter()
        .filter(|(z, _)| !known.contains(z))
        .collect();
    rows.sort_unstable_by(|a, b| b.1.1.cmp(&a.1.1).then_with(|| a.0.cmp(&b.0)));
    let mut attested: FxHashSet<String> = FxHashSet::default();
    let cc = c.clone();
    each(
        rows.iter().map(|(z, _)| z.clone()).collect(),
        par,
        move |z| {
            let c = cc.clone();
            async move { adtech::well_known(&c, &z, adtech::ATTESTATIONS).await }
        },
        |zone, body| {
            if body.as_deref().is_some_and(adtech::is_attestation) {
                attested.insert(zone);
            }
        },
    )
    .await;
    let mut out = Out::new();
    for (zone, (kind, n)) in &rows {
        let mark = if attested.contains(zone) {
            "attested"
        } else {
            ""
        };
        out.row(&[zone, kind, &n.to_string(), mark]);
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "sites={total} ads.txt={with_ads} app-ads.txt={with_app_ads} ad-systems={} with-sellers.json={} zones={} attested={} secs={:.1}",
        systems.len(),
        sellers.len(),
        rows.len(),
        attested.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub async fn prebid(ctx: &mut Ctx) -> Result<()> {
    let c = client::build(&Options {
        timeout: Duration::from_secs(600),
        ..Options::default()
    })?;
    let mut found: Vec<(String, String)> = Vec::new();
    for (url, file) in [
        (adtech::PREBID_JS, "prebid-js.tar.gz"),
        (adtech::PREBID_SERVER, "prebid-server.tar.gz"),
    ] {
        let path = ctx.paths.cache().join(file);
        client::download(&c, url, &path, PREBID_CAP).await?;
        let p = path.clone();
        found.extend(
            tokio::task::spawn_blocking(move || {
                adtech::hosts_in_tarball(&p, adtech::prebid_member)
            })
            .await??,
        );
    }
    found.sort_unstable();
    found.dedup_by(|a, b| a.0 == b.0);
    let known = ctx.known();
    let mut out = Out::new();
    let mut n = 0usize;
    for (h, file) in found.iter().filter(|(h, _)| !known.contains(h)) {
        n += 1;
        out.row(&[h, file]);
    }
    eprintln!("hosts={} unlisted={n}", found.len());
    Ok(())
}

pub async fn cmp(ctx: &mut Ctx, par: usize) -> Result<()> {
    let started = Instant::now();
    let c = web(20)?;
    let gvl = client::fetch(&c, vendors::GVL, GVL_CAP).await?;
    let list = vendors::gvl_vendors(&gvl.body);
    let names: FxHashMap<String, String> = list
        .iter()
        .map(|v| (v.disclosure.clone(), v.name.clone()))
        .collect();
    let urls: Vec<String> = names.keys().cloned().collect();
    let mut hosts: FxHashMap<String, String> = FxHashMap::default();
    let cc = c.clone();
    each(
        urls,
        par,
        move |u| {
            let c = cc.clone();
            async move {
                client::fetch(&c, &u, DISCLOSURE_CAP)
                    .await
                    .ok()
                    .map(|p| p.body)
            }
        },
        |u, body| {
            if let Some(b) = body {
                for h in vendors::disclosure_hosts(&b) {
                    hosts.entry(h).or_insert_with(|| names[&u].clone());
                }
            }
        },
    )
    .await;
    let known = ctx.known();
    let mut rows: Vec<_> = hosts
        .into_iter()
        .filter(|(h, _)| !known.contains(h))
        .collect();
    rows.sort_unstable();
    let mut out = Out::new();
    for (h, vendor) in &rows {
        out.row(&[h, vendor]);
    }
    eprintln!(
        "vendors={} hosts-unlisted={} secs={:.1}",
        list.len(),
        rows.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub async fn scripts(ctx: &mut Ctx, par: usize) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("script")?;
    let urls: Vec<String> = ctx
        .store
        .all("SELECT DISTINCT url FROM request WHERE method = 'GET'")?
        .into_iter()
        .filter(|u| scripts::script_url(u) && !done.contains(u))
        .collect();
    let total = urls.len();
    let c = web(20)?;
    let w = ctx.store.writer()?;
    let mut seen: FxHashMap<String, (usize, String)> = FxHashMap::default();
    let cc = c.clone();
    each(
        urls,
        par,
        move |u| {
            let c = cc.clone();
            async move { client::fetch(&c, &u, SCRIPT_CAP).await.ok().map(|p| p.body) }
        },
        |u, body| {
            if let Some(b) = body {
                for h in scripts::hosts_in_script(&b) {
                    let e = seen.entry(h).or_insert_with(|| (0, u.clone()));
                    e.0 += 1;
                }
            }
            w.send(Row::Done {
                kind: "script".into(),
                key: u,
            });
        },
    )
    .await;
    let known = ctx.known();
    let mut rows: Vec<_> = seen
        .into_iter()
        .filter(|(h, _)| !known.contains(h))
        .collect();
    rows.sort_unstable_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
    let mut out = Out::new();
    for (h, (n, example)) in &rows {
        out.row(&[h, &n.to_string(), example]);
        w.send(Row::Origin {
            host: h.clone(),
            source: "script".into(),
            detail: example.clone(),
        });
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "scripts={total} hosts-unlisted={} secs={:.1}",
        rows.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub async fn extract(ctx: &mut Ctx) -> Result<()> {
    let c = web(30)?;
    let known = ctx.known();
    let mut out = Out::new();
    for row in stdin_rows() {
        let Some(src) = row.first().map(|s| s.trim().to_string()) else {
            continue;
        };
        let body = if src.starts_with("http://") || src.starts_with("https://") {
            match client::fetch(&c, &src, REPORT_CAP).await {
                Ok(p) => p.body,
                Err(e) => {
                    eprintln!("{src}: {e}");
                    continue;
                }
            }
        } else {
            match std::fs::read(&src) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{src}: {e}");
                    continue;
                }
            }
        };
        let text = String::from_utf8_lossy(&body);
        let mut hosts: FxHashMap<String, bool> =
            scripts::hosts_in_report(&text, |h| ctx.psl.listed_tld(h))
                .into_iter()
                .collect();
        for h in scripts::hosts_in_script(&body) {
            hosts.entry(h).or_insert(false);
        }
        let mut hosts: Vec<(String, bool)> = hosts.into_iter().collect();
        hosts.sort_unstable();
        for (h, defanged) in &hosts {
            let form = if *defanged { "defanged" } else { "plain" };
            out.row(&[h, &src, form, &known.labels(known.mask(h))]);
        }
    }
    Ok(())
}

pub async fn passive(ctx: &mut Ctx, par: usize) -> Result<()> {
    passive_zones(ctx, stdin_names(), par).await
}

pub async fn passive_zones(ctx: &mut Ctx, input: Vec<String>, par: usize) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("passive")?;
    let zones: Vec<String> = input.into_iter().filter(|z| !done.contains(z)).collect();
    let total = zones.len();
    let c = web(60)?;
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    let (mut ok, mut names) = (0usize, 0usize);
    let cc = c.clone();
    each(
        zones,
        par,
        move |z| {
            let c = cc.clone();
            async move {
                for t in 0..PASSIVE_TRIES {
                    if t > 0 {
                        tokio::time::sleep(Duration::from_secs(5 * t)).await;
                    }
                    if let Ok(p) = client::fetch(
                        &c,
                        &format!("{}{z}", vendors::SUBDOMAIN_CENTER),
                        PASSIVE_CAP,
                    )
                    .await
                        && let Some(list) = vendors::passive_names(&p.body, &z)
                    {
                        return Some(list);
                    }
                }
                None
            }
        },
        |zone, list| {
            let Some(list) = list else {
                eprintln!("passive {zone}: no answer");
                return;
            };
            ok += 1;
            names += list.len();
            for n in list {
                out.row(&[&n, "passive", &zone]);
                w.send(Row::Origin {
                    host: n,
                    source: "passive".into(),
                    detail: zone.clone(),
                });
            }
            w.send(Row::Done {
                kind: "passive".into(),
                key: zone,
            });
        },
    )
    .await;
    drop(out);
    w.finish()?;
    eprintln!(
        "zones={total} ok={ok} names={names} secs={:.1}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
