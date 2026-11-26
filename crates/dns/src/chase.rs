use crate::engine::{self, Config, Query};
use crate::wire::{self, Data, Message};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::Ipv4Addr;

pub const TIMEOUT: i64 = -1;
const MAX_CHAIN: usize = 12;
const ROUNDS: usize = 4;
const RETRY_SLOWDOWN: u32 = 4;
const RETRY_MIN_QPS: u32 = 200;

#[derive(Clone, Debug, Default)]
pub struct Resolved {
    pub host: String,
    pub rcode: i64,
    pub chain: Vec<String>,
    pub addrs: Vec<Ipv4Addr>,
}

impl Resolved {
    pub fn last(&self) -> &str {
        self.chain.last().map_or(self.host.as_str(), String::as_str)
    }

    pub fn answered(&self) -> bool {
        self.rcode == i64::from(wire::NOERROR) && (!self.addrs.is_empty() || !self.chain.is_empty())
    }
}

pub fn follow(msg: &Message, name: &str) -> (Vec<String>, Vec<Ipv4Addr>) {
    let cnames: FxHashMap<&str, &str> = msg
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            Data::Name(t) if r.rtype == wire::CNAME => Some((r.owner.as_str(), t.as_str())),
            _ => None,
        })
        .collect();
    let mut chain = Vec::new();
    let mut cur = name;
    while let Some(t) = cnames.get(cur) {
        if chain.len() >= MAX_CHAIN || chain.iter().any(|c| c == t) {
            break;
        }
        chain.push((*t).to_string());
        cur = t;
    }
    let mut addrs: Vec<Ipv4Addr> = msg
        .answers
        .iter()
        .filter_map(|r| match r.data {
            Data::A(a) if r.owner == cur => Some(a),
            _ => None,
        })
        .collect();
    addrs.sort_unstable();
    addrs.dedup();
    (chain, addrs)
}

pub async fn lookup(
    cfg: &Config,
    names: &[String],
    qtype: u16,
) -> Result<FxHashMap<String, Vec<Data>>> {
    let queries: Vec<Query> = names
        .iter()
        .map(|n| Query::recursive(n.clone(), qtype))
        .collect();
    let mut out: FxHashMap<String, Vec<Data>> = FxHashMap::default();
    engine::run(cfg, &queries, |r| {
        let Some(m) = r.msg else { return };
        let data: Vec<Data> = m
            .answers
            .into_iter()
            .filter(|a| a.rtype == qtype)
            .map(|a| a.data)
            .collect();
        if !data.is_empty() {
            out.insert(r.query.name.clone(), data);
        }
    })
    .await?;
    Ok(out)
}

pub fn public(a: &Ipv4Addr) -> bool {
    !(a.is_private()
        || a.is_loopback()
        || a.is_unspecified()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || a.octets()[0] == 0
        || (a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64))
}

pub async fn resolve(cfg: &Config, names: Vec<String>) -> Result<Vec<Resolved>> {
    let queries: Vec<Query> = names
        .iter()
        .map(|n| Query::recursive(n.clone(), wire::A))
        .collect();
    let mut out: Vec<Resolved> = Vec::with_capacity(names.len());
    engine::run(cfg, &queries, |r| {
        let host = r.query.name.clone();
        let res = match r.msg {
            Some(m) => {
                let (chain, addrs) = follow(&m, &host);
                Resolved {
                    host: host.clone(),
                    rcode: i64::from(m.rcode),
                    chain,
                    addrs,
                }
            }
            None => Resolved {
                host: host.clone(),
                rcode: TIMEOUT,
                ..Resolved::default()
            },
        };
        out.push(res);
    })
    .await?;
    drop(queries);

    let lost: Vec<Query> = out
        .iter()
        .filter(|r| r.rcode == TIMEOUT)
        .map(|r| Query::recursive(r.host.clone(), wire::A))
        .collect();
    if !lost.is_empty() {
        let slow = Config {
            qps: (cfg.qps / RETRY_SLOWDOWN).max(RETRY_MIN_QPS),
            ..cfg.clone()
        };
        let mut again: FxHashMap<String, Resolved> = FxHashMap::default();
        engine::run(&slow, &lost, |r| {
            if let Some(m) = r.msg {
                let host = r.query.name.clone();
                let (chain, addrs) = follow(&m, &host);
                again.insert(
                    host.clone(),
                    Resolved {
                        host,
                        rcode: i64::from(m.rcode),
                        chain,
                        addrs,
                    },
                );
            }
        })
        .await?;
        for r in out.iter_mut().filter(|r| r.rcode == TIMEOUT) {
            if let Some(a) = again.remove(&r.host) {
                *r = a;
            }
        }
    }

    for _ in 0..ROUNDS {
        let open: FxHashSet<String> = out
            .iter()
            .filter(|r| {
                r.rcode == i64::from(wire::NOERROR) && r.addrs.is_empty() && !r.chain.is_empty()
            })
            .map(|r| r.last().to_string())
            .collect();
        if open.is_empty() {
            break;
        }
        let qs: Vec<Query> = open
            .into_iter()
            .map(|n| Query::recursive(n, wire::A))
            .collect();
        let mut tails: FxHashMap<String, (Vec<String>, Vec<Ipv4Addr>)> = FxHashMap::default();
        engine::run(cfg, &qs, |r| {
            if let Some(m) = r.msg {
                tails.insert(r.query.name.clone(), follow(&m, &r.query.name));
            }
        })
        .await?;
        let mut progressed = false;
        for r in out
            .iter_mut()
            .filter(|r| r.addrs.is_empty() && !r.chain.is_empty())
        {
            if let Some((chain, addrs)) = tails.get(r.last()) {
                if chain.is_empty() && addrs.is_empty() {
                    continue;
                }
                for c in chain {
                    if r.chain.len() < MAX_CHAIN && !r.chain.contains(c) {
                        r.chain.push(c.clone());
                    }
                }
                r.addrs.clone_from(addrs);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Record;

    #[test]
    fn follows_chain_to_addresses() {
        let msg = Message {
            answers: vec![
                Record {
                    owner: "a.site.com".into(),
                    rtype: wire::CNAME,
                    data: Data::Name("x.cdn.net".into()),
                },
                Record {
                    owner: "x.cdn.net".into(),
                    rtype: wire::CNAME,
                    data: Data::Name("y.cdn.net".into()),
                },
                Record {
                    owner: "y.cdn.net".into(),
                    rtype: wire::A,
                    data: Data::A(Ipv4Addr::new(1, 2, 3, 4)),
                },
            ],
            ..Message::default()
        };
        let (chain, addrs) = follow(&msg, "a.site.com");
        assert_eq!(chain, ["x.cdn.net", "y.cdn.net"]);
        assert_eq!(addrs, [Ipv4Addr::new(1, 2, 3, 4)]);
        assert!(!public(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!public(&Ipv4Addr::new(100, 64, 1, 1)));
        assert!(public(&Ipv4Addr::new(1, 1, 1, 1)));
    }
}
