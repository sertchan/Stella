use crate::ctx::{Ctx, Out, stdin_rows};
use crate::pipeline::{self, DnsArgs, ProbeArgs};
use anyhow::Result;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::time::Instant;
use stella_dns::chase;

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    dns: DnsArgs,
    #[command(flatten)]
    probe: ProbeArgs,
    #[arg(
        long,
        default_value = "auto",
        help = "Path set: lite, full, or auto (second stage picked from the first replies)"
    )]
    battery: String,
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    let started = Instant::now();
    let w = ctx.store.writer()?;
    let mut pinned: Vec<(String, IpAddr)> = Vec::new();
    let mut unresolved = Vec::new();
    for row in stdin_rows() {
        let Some(host) = row.first().and_then(|h| stella_core::name::normalize(h)) else {
            continue;
        };
        match row.get(1).and_then(|ip| ip.trim().parse::<IpAddr>().ok()) {
            Some(ip) => pinned.push((host, ip)),
            None => unresolved.push(host),
        }
    }
    if !unresolved.is_empty() {
        let res = pipeline::resolve(ctx, &w, &args.dns.config(), unresolved, false).await?;
        for r in res {
            if let Some(a) = r.res.addrs.iter().find(|a| chase::public(a)) {
                pinned.push((r.res.host, IpAddr::V4(*a)));
            }
        }
    }
    let mut seen: FxHashMap<String, ()> = FxHashMap::default();
    let items: Vec<_> = pinned
        .into_iter()
        .filter(|(h, _)| seen.insert(h.clone(), ()).is_none())
        .map(|(h, ip)| {
            let b = pipeline::battery_for(ctx, &h, &args.battery);
            (h, ip, b)
        })
        .collect();
    let prober = args.probe.prober();
    let mut out = Out::new();
    let mut verdicts: FxHashMap<&'static str, usize> = FxHashMap::default();
    let st = pipeline::probe(ctx, &w, &prober, items, args.probe.conc, |p, h| {
        *verdicts.entry(h.verdict).or_default() += 1;
        out.row(&[&p.host, h.product, h.verdict, &h.evidence]);
    })
    .await;
    drop(out);
    let rows = w.finish()?;
    eprintln!(
        "{} pick={} review={} drop={} rows={rows} secs={:.1}",
        st.line(),
        verdicts.get("PICK").unwrap_or(&0),
        verdicts.get("REVIEW").unwrap_or(&0),
        verdicts.get("DROP").unwrap_or(&0),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
