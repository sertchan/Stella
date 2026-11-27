use crate::context::{Context, Out};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use stella_core::store::Row;
use stella_net::limiter::Limiter;
use stella_net::tls;
use tokio::task::JoinSet;

#[derive(clap::Args)]
pub struct Args {
    #[arg(
        long,
        default_value_t = 5,
        help = "Picks a /24 block needs before it is swept"
    )]
    min_picks: usize,
    #[arg(
        long,
        default_value_t = 0.5,
        help = "Share of the known hosts of a block that must be picks"
    )]
    min_share: f64,
    #[arg(long, default_value_t = 20, help = "Blocks swept at most")]
    max_blocks: usize,
    #[arg(long, default_value_t = 64, help = "Handshakes open at the same time")]
    conc: usize,
    #[arg(
        long,
        default_value_t = 50,
        help = "New connections per second at most"
    )]
    rate: u32,
    #[arg(
        long,
        default_value_t = 3,
        help = "Connect and handshake timeout in seconds"
    )]
    timeout: u64,
}

const LAST_HOST: u8 = 254;

pub fn block(a: &Ipv4Addr) -> [u8; 3] {
    let o = a.octets();
    [o[0], o[1], o[2]]
}

pub fn blocks(
    rows: &[(Ipv4Addr, String)],
    picks: &FxHashSet<String>,
    min_picks: usize,
    min_share: f64,
    max_blocks: usize,
) -> Vec<([u8; 3], usize)> {
    let mut by: FxHashMap<[u8; 3], (FxHashSet<&str>, FxHashSet<&str>)> = FxHashMap::default();
    for (a, h) in rows {
        let e = by.entry(block(a)).or_default();
        e.0.insert(h.as_str());
        if picks.contains(h) {
            e.1.insert(h.as_str());
        }
    }
    let mut out: Vec<([u8; 3], usize)> = by
        .into_iter()
        .filter(|(_, (all, p))| {
            p.len() >= min_picks && p.len() as f64 >= min_share * all.len() as f64
        })
        .map(|(b, (_, p))| (b, p.len()))
        .collect();
    out.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out.truncate(max_blocks);
    out
}

pub async fn run(ctx: &mut Context, args: Args) -> Result<()> {
    let started = Instant::now();
    let picks = ctx
        .store
        .all("SELECT DISTINCT host FROM hit WHERE verdict = 'PICK'")?;
    let rows: Vec<(Ipv4Addr, String)> = ctx
        .store
        .rows("SELECT addr, host FROM addr")?
        .into_iter()
        .filter_map(|r| Some((r[0].parse().ok()?, r[1].clone())))
        .collect();
    let chosen = blocks(
        &rows,
        &picks,
        args.min_picks,
        args.min_share,
        args.max_blocks,
    );
    let limiter = Limiter::with_handshakes(args.conc, args.rate, args.conc);
    let connector = tls::insecure_connector();
    let wait = Duration::from_secs(args.timeout);
    let mut set = JoinSet::new();
    let mut names: FxHashMap<String, IpAddr> = FxHashMap::default();
    let mut answered = 0usize;
    let targets: Vec<IpAddr> = chosen
        .iter()
        .flat_map(|(b, _)| {
            (1..=LAST_HOST).map(move |d| IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], d)))
        })
        .collect();
    let total = targets.len();
    let mut it = targets.into_iter();
    loop {
        while set.len() < args.conc.max(1) {
            let Some(ip) = it.next() else { break };
            let (limiter, connector) = (limiter.clone(), connector.clone());
            set.spawn(async move {
                let _slot = limiter.slot().await?;
                let _hs = limiter.handshake().await?;
                let s = tls::connect(
                    &connector,
                    &ip.to_string(),
                    std::net::SocketAddr::new(ip, tls::TLS_PORT),
                    wait,
                    wait,
                )
                .await
                .ok()?;
                Some((ip, tls::sans(&s)))
            });
        }
        match set.join_next().await {
            Some(Ok(Some((ip, sans)))) => {
                answered += 1;
                for n in sans {
                    names.entry(n).or_insert(ip);
                }
            }
            Some(_) => {}
            None => break,
        }
    }
    let known = ctx.known();
    let shared: FxHashSet<String> = ctx
        .store
        .all("SELECT DISTINCT host FROM origin WHERE source = 'control'")?
        .iter()
        .map(|h| ctx.regdom(h))
        .chain(
            crate::commands::mates::SHARED_DNS
                .iter()
                .map(std::string::ToString::to_string),
        )
        .collect();
    let mut fresh: Vec<(String, IpAddr)> = names
        .into_iter()
        .filter(|(n, _)| {
            let zone = ctx.regdom(n);
            let sub = stella_core::name::subdomain(n, &zone);
            ctx.psl.listed_tld(n)
                && ctx.psl.regdom(n).is_some()
                && !known.contains(n)
                && !picks.contains(n)
                && !shared.contains(&zone)
                && !stella_core::token::skipped(sub)
        })
        .collect();
    fresh.sort_unstable();
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    for (n, ip) in &fresh {
        out.row(&[n, &ip.to_string()]);
        w.send(Row::Origin {
            host: n.clone(),
            source: "sweep".into(),
            detail: ip.to_string(),
        });
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "blocks={} addresses={total} answered={answered} names-unlisted={} secs={:.2}",
        chosen.len(),
        fresh.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_dense_blocks_only() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().expect("ip");
        let mut rows = Vec::new();
        let mut picks = FxHashSet::default();
        for i in 0..6 {
            let h = format!("sst{i}.shop{i}.com");
            rows.push((ip(&format!("203.0.113.{}", 10 + i)), h.clone()));
            picks.insert(h);
        }
        rows.push((ip("203.0.113.99"), "www.other.com".into()));
        for i in 0..20 {
            rows.push((ip(&format!("198.51.100.{i}")), format!("site{i}.cdn.net")));
        }
        for i in 0..6 {
            let h = format!("t{i}.pick.com");
            rows.push((ip("198.51.100.200"), h.clone()));
            picks.insert(h);
        }
        let got = blocks(&rows, &picks, 5, 0.5, 20);
        assert_eq!(got, [([203, 0, 113], 6)]);
        assert!(blocks(&rows, &picks, 7, 0.5, 20).is_empty());
    }
}
