use crate::ctx::{Ctx, Out, stdin_rows};
use crate::pipeline::{self, DnsArgs, ProbeArgs};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::IpAddr;
use std::time::Instant;
use stella_core::store::Row;
use stella_dns::chase;
use stella_dns::wild::Verdict;
use stella_probe::battery::{self, Battery, HostProbe, RANDOM};
use stella_probe::rules;

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    dns: DnsArgs,
    #[command(flatten)]
    probe: ProbeArgs,
}

const SIGNATURE_BYTES: usize = 160;
const SIGNATURE_CAP: usize = 8 * 1024;

fn mask(body: &[u8]) -> String {
    let text =
        String::from_utf8_lossy(&body[..body.len().min(SIGNATURE_BYTES)]).to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.is_empty() {
            return;
        }
        let hex = run.len() >= 8 && run.chars().all(|c| c.is_ascii_hexdigit());
        let digits = run.chars().all(|c| c.is_ascii_digit());
        if digits {
            out.push('N');
        } else if hex {
            out.push('H');
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

fn signature(p: &HostProbe) -> Option<String> {
    let mut parts = Vec::new();
    for path in ["/", RANDOM] {
        let r = p.get(path)?;
        let ctype = r
            .ctype
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        parts.push(format!(
            "{}|{}|{}|{}",
            r.status,
            r.server.to_ascii_lowercase(),
            ctype,
            mask(&r.body)
        ));
    }
    Some(parts.join("||"))
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    verify(ctx, &args.dns, &args.probe, stdin_rows())
        .await
        .map(|_| ())
}

pub async fn verify(
    ctx: &mut Ctx,
    dns: &DnsArgs,
    probe: &ProbeArgs,
    rows: Vec<Vec<String>>,
) -> Result<usize> {
    let started = Instant::now();
    let known = ctx.known();
    let mut pairs: Vec<(String, Option<String>)> = Vec::new();
    let mut seen = FxHashSet::default();
    for row in rows {
        let Some(c) = row.first().and_then(|h| stella_core::name::normalize(h)) else {
            continue;
        };
        if known.contains(&c) || !seen.insert(c.clone()) {
            continue;
        }
        let seed = row.get(1).and_then(|s| stella_core::name::normalize(s));
        pairs.push((c, seed));
    }
    if pairs.iter().any(|(_, s)| s.is_none()) {
        let zones: FxHashMap<String, Vec<String>> =
            stella_sources::variants::partial_zones(known, &ctx.psl)
                .into_iter()
                .map(|z| (z.zone, z.listed))
                .collect();
        for (c, s) in pairs.iter_mut().filter(|(_, s)| s.is_none()) {
            let zone = ctx.psl.icann_regdom_or_self(c);
            *s = zones
                .get(zone)
                .and_then(|l| stella_sources::variants::sibling_seed(l))
                .cloned();
        }
    }
    let pairs: Vec<(String, String)> = pairs
        .into_iter()
        .filter_map(|(c, s)| s.map(|s| (c, s)))
        .collect();
    let mut names: Vec<String> = pairs.iter().map(|(c, _)| c.clone()).collect();
    names.extend(pairs.iter().map(|(_, s)| s.clone()));
    names.sort_unstable();
    names.dedup();
    let w = ctx.store.writer()?;
    let res = pipeline::resolve(ctx, &w, &dns.config(), names, true).await?;
    let mut addr: FxHashMap<String, (IpAddr, bool)> = FxHashMap::default();
    for n in &res {
        if let Some(a) = n.res.addrs.iter().find(|a| chase::public(a)) {
            addr.insert(
                n.res.host.clone(),
                (IpAddr::V4(*a), n.wild == Some(Verdict::Wild)),
            );
        }
    }
    let live: Vec<&(String, String)> = pairs
        .iter()
        .filter(|(c, s)| addr.get(c).is_some_and(|(_, wild)| !wild) && addr.contains_key(s))
        .collect();
    let mut targets: Vec<(String, IpAddr, Battery)> = Vec::new();
    let mut queued = FxHashSet::default();
    for (c, s) in &live {
        for h in [c, s] {
            if queued.insert(h.clone())
                && let Some((ip, _)) = addr.get(h)
            {
                targets.push((h.clone(), *ip, Battery::Lite));
            }
        }
    }
    let mut prober = probe.prober();
    prober.cap = SIGNATURE_CAP;
    let mut sig: FxHashMap<String, String> = FxHashMap::default();
    let mut app: FxHashMap<String, String> = FxHashMap::default();
    battery::probe_all(&prober, targets, probe.conc, |p| {
        if let Some(s) = signature(&p) {
            sig.insert(p.host.clone(), s);
        }
        if let Some(t) = rules::html_app(&p) {
            app.insert(p.host.clone(), t);
        }
    })
    .await;
    let same: Vec<&(String, String)> = live
        .into_iter()
        .filter(|(c, s)| matches!((sig.get(c), sig.get(s)), (Some(a), Some(b)) if a == b))
        .collect();
    let covered = pipeline::covered_elsewhere(
        ctx,
        &dns.config(),
        same.iter().map(|(c, _)| c.clone()).collect(),
    )
    .await?;
    let mut out = Out::new();
    let (mut picks, mut reviews) = (0usize, 0usize);
    for (c, s) in same {
        let same_ip = addr.get(c).map(|x| x.0) == addr.get(s).map(|x| x.0);
        let zone = ctx.psl.icann_regdom_or_self(c);
        let sub = stella_core::name::subdomain(c, zone);
        let mut evidence = format!("same reply as {s}");
        if same_ip {
            evidence.push_str(", same address");
        }
        let verdict = if let Some(why) = covered.get(c) {
            evidence.push_str(&format!("; {why}"));
            rules::DROP
        } else if let Some(t) = app.get(c) {
            evidence.push_str(&format!(
                "; the shared reply is a web app: {}",
                battery::head(t.as_bytes(), 60)
            ));
            rules::REVIEW
        } else if stella_core::token::skipped(sub) {
            evidence.push_str("; staging or dev name");
            rules::DROP
        } else if stella_core::token::tracking(sub) {
            rules::PICK
        } else {
            evidence.push_str("; no tracking word in the name");
            rules::REVIEW
        };
        picks += usize::from(verdict == rules::PICK);
        reviews += usize::from(verdict == rules::REVIEW);
        out.row(&[c, s, verdict, &evidence]);
        w.send(Row::Origin {
            host: c.clone(),
            source: "twin".into(),
            detail: s.clone(),
        });
        w.send(Row::Hit {
            host: c.clone(),
            product: "twin".into(),
            evidence,
            verdict: verdict.into(),
        });
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "pairs={} live={} probed={} pick={picks} review={reviews} secs={:.1}",
        pairs.len(),
        live_count(&addr, &pairs),
        sig.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(picks)
}

fn live_count(addr: &FxHashMap<String, (IpAddr, bool)>, pairs: &[(String, String)]) -> usize {
    pairs
        .iter()
        .filter(|(c, _)| addr.get(c).is_some_and(|(_, wild)| !wild))
        .count()
}

#[cfg(test)]
mod tests {
    #[test]
    fn masks_numbers_and_hex() {
        assert_eq!(
            super::mask(b"Request 12345 id=deadbeef01"),
            "request N id=H"
        );
    }
}
