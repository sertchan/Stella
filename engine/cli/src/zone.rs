use crate::ctx::{Ctx, Out};
use crate::pipeline::DnsArgs;
use anyhow::Result;
use std::time::{Duration, Instant};
use stella_core::store::Row;
use stella_dns::zone;
use tokio::task::JoinSet;

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    dns: DnsArgs,
    #[arg(
        long,
        default_value_t = 64,
        help = "Zone transfers and walks in parallel"
    )]
    par: usize,
    #[arg(long, help = "Walk every zone that answers with real NSEC records")]
    walk: bool,
    #[arg(long, default_value_t = 120, help = "Seconds per NSEC walk")]
    walk_secs: u64,
    #[arg(long, default_value_t = 200_000, help = "Names per NSEC walk at most")]
    walk_max: usize,
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("zone")?;
    let zones: Vec<String> = ctx
        .names()
        .into_iter()
        .filter(|z| !done.contains(z))
        .collect();
    let cfg = args.dns.config();
    let pairs = zone::selfhosted(&cfg, zones.clone()).await?;
    eprintln!("zones={} selfhosted-pairs={}", zones.len(), pairs.len());
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    let mut axfr_zones = 0usize;
    let mut by_zone: std::collections::BTreeMap<String, Vec<std::net::SocketAddr>> =
        Default::default();
    for p in &pairs {
        by_zone.entry(p.zone.clone()).or_default().push(p.server);
    }
    let mut set = JoinSet::new();
    let mut it = by_zone.into_iter();
    loop {
        while set.len() < args.par.max(1) {
            let Some((z, ips)) = it.next() else { break };
            set.spawn(async move {
                for server in ips {
                    let names = zone::axfr(&z, server).await;
                    if !names.is_empty() {
                        return (z, names);
                    }
                }
                (z, Vec::new())
            });
        }
        let Some(Ok((z, names))) = set.join_next().await else {
            break;
        };
        if !names.is_empty() {
            axfr_zones += 1;
        }
        for n in names {
            if let Some(n) = stella_core::name::normalize(&n) {
                out.row(&[&n, "axfr", &z]);
                w.send(Row::Origin {
                    host: n,
                    source: "axfr".into(),
                    detail: z.clone(),
                });
            }
        }
    }
    let walkable = zone::nsec_probe(&cfg, &pairs).await?;
    let mut nsec_names = 0usize;
    let mut walked = std::collections::BTreeMap::new();
    for (i, next) in &walkable {
        walked
            .entry(pairs[*i].zone.clone())
            .or_insert((pairs[*i].server, next.clone()));
    }
    eprintln!("axfr-zones={axfr_zones} nsec-zones={}", walked.len());
    if args.walk {
        let mut set = JoinSet::new();
        let mut it = walked.iter().map(|(z, (ip, _))| (z.clone(), *ip));
        let budget = Duration::from_secs(args.walk_secs);
        loop {
            while set.len() < args.par.max(1) {
                let Some((z, ip)) = it.next() else { break };
                let max = args.walk_max;
                set.spawn(async move {
                    let names = zone::walk(&z, ip, budget, max).await;
                    (z, names)
                });
            }
            let Some(Ok((z, names))) = set.join_next().await else {
                break;
            };
            for n in names {
                if let Some(n) = stella_core::name::normalize(&n) {
                    nsec_names += 1;
                    out.row(&[&n, "nsec", &z]);
                    w.send(Row::Origin {
                        host: n,
                        source: "nsec".into(),
                        detail: z.clone(),
                    });
                }
            }
        }
    } else {
        for (z, (ip, next)) in &walked {
            out.row(&[next, "nsec-next", z, &ip.to_string()]);
        }
    }
    for z in &zones {
        w.send(Row::Done {
            kind: "zone".into(),
            key: z.clone(),
        });
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "nsec-names={nsec_names} secs={:.1}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
