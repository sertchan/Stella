use crate::context::{Context, Out};
use crate::pipeline::{DnsArgs, ProbeArgs};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use stella_core::store::Row;
use stella_dns::resolver;
use stella_probe::battery::{self, Battery};
use stella_probe::rules;

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    dns: DnsArgs,
    #[command(flatten)]
    probe: ProbeArgs,
    #[arg(long, help = "Use the picked hosts instead of the names on stdin")]
    picks: bool,
}

pub fn regional(
    local: &FxHashMap<String, FxHashSet<Ipv4Addr>>,
    placed: &[(String, &'static str, Vec<Ipv4Addr>)],
) -> Vec<(String, &'static str, Ipv4Addr)> {
    let mut seen: FxHashSet<(String, Ipv4Addr)> = FxHashSet::default();
    let mut out = Vec::new();
    for (host, region, addrs) in placed {
        let here = local.get(host);
        if let Some(a) = addrs
            .iter()
            .find(|a| resolver::public(a) && here.is_none_or(|h| !h.contains(a)))
            && seen.insert((host.clone(), *a))
        {
            out.push((host.clone(), *region, *a));
        }
    }
    out.sort_unstable();
    out
}

pub async fn run(ctx: &mut Context, args: Args) -> Result<()> {
    let started = Instant::now();
    let hosts: Vec<String> = if args.picks {
        ctx.store
            .all("SELECT DISTINCT host FROM hit WHERE verdict = 'PICK'")?
            .into_iter()
            .collect()
    } else {
        ctx.names()
    };
    let cfg = args.dns.config();
    let mut local: FxHashMap<String, FxHashSet<Ipv4Addr>> = FxHashMap::default();
    for r in resolver::resolve(&cfg, hosts.clone()).await? {
        local.entry(r.host).or_default().extend(r.addrs);
    }
    let placed: Vec<(String, &'static str, Vec<Ipv4Addr>)> =
        stella_dns::ecs::addresses(&cfg, &hosts)
            .await?
            .into_iter()
            .map(|p| (p.host, p.region, p.addrs))
            .collect();
    let targets = regional(&local, &placed);
    let region_of: FxHashMap<(String, IpAddr), &'static str> = targets
        .iter()
        .map(|(h, r, a)| ((h.clone(), IpAddr::V4(*a)), *r))
        .collect();
    let hit_before: FxHashSet<String> = ctx
        .store
        .all("SELECT DISTINCT host FROM hit WHERE verdict IN ('PICK', 'REVIEW')")?;
    let prober = args.probe.prober();
    let items: Vec<(String, IpAddr, Battery)> = targets
        .iter()
        .map(|(h, _, a)| (h.clone(), IpAddr::V4(*a), Battery::Lite))
        .collect();
    let probed = items.len();
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    let mut fresh = 0usize;
    battery::probe_all(&prober, items, args.probe.conc, |p| {
        let region = region_of
            .get(&(p.host.clone(), p.ip))
            .copied()
            .unwrap_or("-");
        let rd = ctx.psl.icann_regdom_or_self(&p.host);
        let mut any = false;
        for h in rules::classify(&p, rd)
            .into_iter()
            .filter(|h| h.verdict != rules::DROP)
        {
            any = true;
            out.row(&[&p.host, region, &p.ip.to_string(), h.product, h.verdict]);
            if !hit_before.contains(&p.host) && ctx.allowed(&p.host).is_none() {
                fresh += 1;
                w.send(Row::Hit {
                    host: p.host.clone(),
                    product: h.product.to_string(),
                    evidence: format!("{}; seen only at the {region} address {}", h.evidence, p.ip),
                    verdict: rules::REVIEW.into(),
                });
            }
        }
        any
    })
    .await;
    drop(out);
    w.finish()?;
    eprintln!(
        "hosts={} regional-addresses={probed} new-reviews={fresh} secs={:.2}",
        hosts.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_regional_addresses_not_seen_here() {
        let a = |s: &str| s.parse::<Ipv4Addr>().expect("ip");
        let local: FxHashMap<String, FxHashSet<Ipv4Addr>> =
            [("t.io".to_string(), [a("8.8.4.4")].into_iter().collect())]
                .into_iter()
                .collect();
        let placed = vec![
            ("t.io".to_string(), "eu", vec![a("8.8.4.4")]),
            ("t.io".to_string(), "us", vec![a("1.1.1.1")]),
            ("t.io".to_string(), "asia", vec![a("1.1.1.1")]),
            ("u.io".to_string(), "eu", vec![a("10.0.0.1"), a("9.9.9.9")]),
        ];
        assert_eq!(
            regional(&local, &placed),
            [
                ("t.io".to_string(), "us", a("1.1.1.1")),
                ("u.io".to_string(), "eu", a("9.9.9.9")),
            ]
        );
    }
}
