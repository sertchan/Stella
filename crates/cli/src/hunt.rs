use crate::ctx::{Ctx, Out, stdin_names};
use crate::pipeline::{self, DnsArgs, ProbeArgs};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::IpAddr;
use std::time::Instant;
use stella_core::store::Row;
use stella_dns::chase;
use stella_dns::wild::Verdict;
use stella_probe::battery::Battery;

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    dns: DnsArgs,
    #[command(flatten)]
    probe: ProbeArgs,
    #[arg(
        long,
        default_value = "input",
        help = "Origin label recorded for the names on stdin"
    )]
    tag: String,
    #[arg(
        long,
        default_value_t = 5,
        help = "Hosts probed per registrable domain and address"
    )]
    cap: usize,
    #[arg(
        long,
        default_value_t = 2,
        help = "Rounds, each one fed by the pivots of the last"
    )]
    rounds: usize,
    #[arg(
        long,
        default_value_t = 10,
        help = "Hosts probed per registrable domain before the rest of that zone is probed only if it had a hit, 0 probes all"
    )]
    zone_sample: usize,
    #[arg(
        long,
        default_value_t = 40,
        help = "Skip pivot addresses shared by more hosts than this"
    )]
    max_ip: i64,
    #[arg(long, help = "Also probe names resolved in an earlier run")]
    again: bool,
    #[arg(long, help = "Pivot from REVIEW hits too, not only from picks")]
    pivot_review: bool,
    #[arg(
        long,
        help = "Skip the check for CNAMEs to included hosts seen from EU, US and Asia client subnets"
    )]
    no_ecs: bool,
    #[arg(long, default_value = "auto", help = "Path set: lite, full, or auto")]
    battery: String,
}

struct Round {
    names: Vec<String>,
    pinned: Vec<(String, IpAddr)>,
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    let started = Instant::now();
    let w = ctx.store.writer()?;
    let cfg = args.dns.config();
    let prober = args.probe.prober();
    let mut resolved_before = if args.again {
        FxHashSet::default()
    } else {
        ctx.store.resolved()?
    };
    let mut probed = ctx.store.probed()?;
    let input = stdin_names();
    for n in &input {
        w.send(Row::Origin {
            host: n.clone(),
            source: args.tag.clone(),
            detail: String::new(),
        });
    }
    let mut round = Round {
        names: input,
        pinned: Vec::new(),
    };
    let mut out = Out::new();
    let mut picks = 0usize;
    for r in 0..args.rounds.max(1) {
        let known = ctx.known();
        let fresh: Vec<String> = round
            .names
            .drain(..)
            .filter(|n| !resolved_before.contains(n) && !known.contains(n))
            .collect();
        let fresh_count = fresh.len();
        let named = pipeline::resolve(ctx, &w, &cfg, fresh, true).await?;
        let mut per_key: FxHashMap<(String, IpAddr), usize> = FxHashMap::default();
        let mut items: Vec<(String, IpAddr, Battery)> = Vec::new();
        let mut live = 0usize;
        let candidates = named.into_iter().filter_map(|n| {
            resolved_before.insert(n.res.host.clone());
            let addr = n.res.addrs.iter().find(|a| chase::public(a))?;
            let ok = n.known.is_empty() && n.wild != Some(Verdict::Wild);
            ok.then_some((n.res.host, IpAddr::V4(*addr)))
        });
        for (host, ip) in candidates.chain(round.pinned.drain(..)) {
            if !probed.insert(host.clone()) {
                continue;
            }
            live += 1;
            let key = (ctx.psl.regdom_or_self(&host).to_string(), ip);
            let c = per_key.entry(key).or_default();
            *c += 1;
            if *c > args.cap {
                continue;
            }
            let b = pipeline::battery_for(ctx, &host, &args.battery);
            items.push((host, ip, b));
        }
        let probing = items.len();
        let mut seen_in_zone: FxHashMap<String, usize> = FxHashMap::default();
        let (first, deferred): (Vec<_>, Vec<_>) = items.into_iter().partition(|(h, _, _)| {
            let n = seen_in_zone
                .entry(ctx.psl.regdom_or_self(h).to_string())
                .or_default();
            *n += 1;
            args.zone_sample == 0 || *n <= args.zone_sample
        });
        let mut hit_zones: FxHashSet<String> = FxHashSet::default();
        let mut found: Vec<pipeline::Found> = Vec::new();
        let st = pipeline::probe(ctx, &w, &prober, first, args.probe.conc, |p, h| {
            if h.verdict != stella_probe::rules::DROP {
                hit_zones.insert(ctx.psl.regdom_or_self(&p.host).to_string());
            }
            found.push(pipeline::Found::new(p, h));
        })
        .await;
        let (follow, skipped): (Vec<_>, Vec<_>) = deferred
            .into_iter()
            .partition(|(h, _, _)| hit_zones.contains(ctx.psl.regdom_or_self(h)));
        for (h, _, _) in &skipped {
            w.send(Row::Done {
                kind: "sampled-out".into(),
                key: h.clone(),
            });
        }
        let followed = follow.len();
        let more = pipeline::probe(ctx, &w, &prober, follow, args.probe.conc, |p, h| {
            found.push(pipeline::Found::new(p, h));
        })
        .await;
        let covered = if args.no_ecs {
            0
        } else {
            pipeline::drop_covered(ctx, &w, &cfg, &mut found).await?
        };
        for f in &found {
            picks += usize::from(f.verdict == stella_probe::rules::PICK);
            out.row(&[&f.host, f.product, f.verdict, &f.evidence]);
        }
        if covered > 0 {
            eprintln!("round={} covered-by-cname-elsewhere={covered}", r + 1);
        }
        eprintln!(
            "round={} fresh={fresh_count} live={live} probed={} zone-followups={followed} sampled-out={} picks={picks} secs={:.1} {}",
            r + 1,
            probing - skipped.len(),
            skipped.len(),
            started.elapsed().as_secs_f64(),
            st.line()
        );
        if followed > 0 {
            eprintln!("round={} follow-ups: {}", r + 1, more.line());
        }
        if r + 1 >= args.rounds {
            break;
        }
        tokio::task::block_in_place(|| w.flush());
        let p = stella_sources::pivot::collect(
            &ctx.store.conn,
            &ctx.psl,
            args.max_ip,
            args.pivot_review,
        )?;
        for (host, addr, via) in &p.neighbours {
            if let Ok(ip) = addr.parse::<IpAddr>() {
                round.pinned.push((host.clone(), ip));
                w.send(Row::Origin {
                    host: host.clone(),
                    source: "pivot-ip".into(),
                    detail: via.clone(),
                });
            }
        }
        for (san, host) in &p.sans {
            round.names.push(san.clone());
            w.send(Row::Origin {
                host: san.clone(),
                source: "pivot-san".into(),
                detail: host.clone(),
            });
        }
        if round.names.is_empty() && round.pinned.is_empty() {
            break;
        }
    }
    drop(out);
    w.finish()?;
    eprintln!("picks={picks} secs={:.1}", started.elapsed().as_secs_f64());
    Ok(())
}
