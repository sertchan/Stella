use crate::chase::follow;
use crate::engine::{self, Config, Query};
use crate::wire;
use anyhow::Result;
use rustc_hash::FxHashMap;
use std::net::SocketAddr;

pub const SERVER: ([u8; 4], u16) = ([8, 8, 8, 8], 53);
pub const REGIONS: &[(&str, [u8; 3])] = &[
    ("eu", [81, 2, 69]),
    ("us", [72, 229, 28]),
    ("asia", [1, 201, 0]),
];
const QPS: u32 = 1000;
const HOPS: usize = 4;
const MAX_CHAIN: usize = 12;

pub struct Seen {
    pub host: String,
    pub region: &'static str,
    pub chain: Vec<String>,
}

pub async fn chains(cfg: &Config, names: &[String]) -> Result<Vec<Seen>> {
    let cfg = Config {
        qps: cfg.qps.min(QPS),
        ..cfg.clone()
    };
    let server = SocketAddr::from(SERVER);
    let query = |name: &str, subnet: [u8; 3]| Query {
        server: Some(server),
        subnet: Some(subnet),
        ..Query::recursive(name.to_string(), wire::A)
    };
    let mut out = Vec::new();
    for (region, subnet) in REGIONS {
        let qs: Vec<Query> = names.iter().map(|n| query(n, *subnet)).collect();
        let mut seen: FxHashMap<String, (Vec<String>, bool)> = FxHashMap::default();
        engine::run(&cfg, &qs, |r| {
            if let Some(m) = r.msg {
                let (chain, addrs) = follow(&m, &r.query.name);
                if !chain.is_empty() {
                    seen.insert(r.query.name.clone(), (chain, addrs.is_empty()));
                }
            }
        })
        .await?;
        for _ in 0..HOPS {
            let open: Vec<Query> = seen
                .values()
                .filter(|(c, open)| *open && c.len() < MAX_CHAIN)
                .filter_map(|(c, _)| c.last())
                .map(|t| query(t, *subnet))
                .collect();
            if open.is_empty() {
                break;
            }
            let mut tails: FxHashMap<String, (Vec<String>, bool)> = FxHashMap::default();
            engine::run(&cfg, &open, |r| {
                if let Some(m) = r.msg {
                    let (chain, addrs) = follow(&m, &r.query.name);
                    tails.insert(r.query.name.clone(), (chain, addrs.is_empty()));
                }
            })
            .await?;
            for (chain, open) in seen.values_mut().filter(|(_, o)| *o) {
                let Some((more, still)) = chain.last().and_then(|t| tails.get(t)) else {
                    *open = false;
                    continue;
                };
                let before = chain.len();
                for c in more {
                    if chain.len() < MAX_CHAIN && !chain.contains(c) {
                        chain.push(c.clone());
                    }
                }
                *open = *still && chain.len() > before;
            }
        }
        out.extend(seen.into_iter().map(|(host, (chain, _))| Seen {
            host,
            region,
            chain,
        }));
    }
    Ok(out)
}
