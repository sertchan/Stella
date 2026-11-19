use crate::chase;
use crate::engine::{self, Config, Query};
use crate::stub::Stub;
use crate::wire::{self, Data, Message};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const MANAGED: &[&str] = &[
    "cloudflare.com",
    "awsdns",
    "azure-dns",
    "googledomains.com",
    "google.com",
    "domaincontrol.com",
    "nsone.net",
    "ultradns",
    "akam",
    "dynect",
    "registrar-servers.com",
    "dnsmadeeasy",
    "cloudns",
    "digitalocean.com",
    "linode.com",
    "hetzner",
    "ovh.net",
    "gandi.net",
    "name-services.com",
    "wixdns",
    "squarespacedns",
    "vercel-dns",
    "netlify",
    "dns.jp",
    "nic.ru",
    "yandex",
    "alidns",
    "hichina",
    "dnspod",
    "dnsv",
    "huaweicloud",
    "bdydns",
    "he.net",
    "afternic",
    "parkingcrew",
    "sedoparking",
    "bodis",
    "1and1",
    "ui-dns",
    "hostgator",
    "bluehost",
    "websitewelcome",
    "namecheaphosting",
    "easydns",
    "constellix",
    "dnsimple",
    "rackspace",
    "cscdns",
    "markmonitor",
    "safenames",
    "nsonedns",
    "edgedns",
    "edgecastdns",
    "verisigndns",
    "ztomy",
    "dns.com",
];

const SERVERS_PER_ZONE: usize = 2;
const AXFR_CONNECT: Duration = Duration::from_secs(4);
const AXFR_TOTAL: Duration = Duration::from_secs(15);
const AXFR_MIN_NAMES: usize = 3;
const WALK_QUERY: Duration = Duration::from_secs(3);
const BLACK_LIE: &str = "\\000";

#[derive(Clone, Debug)]
pub struct Pair {
    pub zone: String,
    pub ip: Ipv4Addr,
}

fn managed(ns: &str) -> bool {
    MANAGED.iter().any(|m| ns.contains(m))
}

pub async fn selfhosted(cfg: &Config, zones: Vec<String>) -> Result<Vec<Pair>> {
    let qs: Vec<Query> = zones
        .into_iter()
        .map(|z| Query::recursive(z, wire::NS))
        .collect();
    let mut ns_of: FxHashMap<String, Vec<String>> = FxHashMap::default();
    engine::run(cfg, &qs, |r| {
        let Some(m) = r.msg else { return };
        let z = r.query.name.as_str();
        let list: Vec<String> = m
            .answers
            .iter()
            .filter(|rec| rec.rtype == wire::NS && rec.owner == z)
            .filter_map(|rec| match &rec.data {
                Data::Name(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        if !list.is_empty() && !list.iter().any(|n| managed(n)) {
            ns_of.insert(z.to_string(), list);
        }
    })
    .await?;
    let hosts: FxHashSet<String> = ns_of.values().flatten().cloned().collect();
    let resolved = chase::resolve(cfg, hosts.into_iter().collect()).await?;
    let ip_of: FxHashMap<&str, Ipv4Addr> = resolved
        .iter()
        .filter_map(|r| {
            r.addrs
                .iter()
                .find(|a| chase::public(a))
                .map(|a| (r.host.as_str(), *a))
        })
        .collect();
    let mut pairs = Vec::new();
    for (zone, list) in &ns_of {
        let mut ips: Vec<Ipv4Addr> = list
            .iter()
            .filter_map(|n| ip_of.get(n.as_str()).copied())
            .collect();
        ips.dedup();
        for ip in ips.into_iter().take(SERVERS_PER_ZONE) {
            pairs.push(Pair {
                zone: zone.clone(),
                ip,
            });
        }
    }
    Ok(pairs)
}

async fn read_message(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Message> {
    let len = stream.read_u16().await.ok()? as usize;
    buf.resize(len, 0);
    stream.read_exact(buf).await.ok()?;
    wire::parse(buf)
}

pub async fn axfr(zone: &str, ip: Ipv4Addr) -> Vec<String> {
    let run = async {
        let addr = SocketAddr::from((ip, 53));
        let mut stream = tokio::time::timeout(AXFR_CONNECT, TcpStream::connect(addr))
            .await
            .ok()?
            .ok()?;
        let mut q = Vec::new();
        if !wire::encode_query(&mut q, 0x5a5a, zone, wire::AXFR, false, false) {
            return None;
        }
        let mut framed = (q.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&q);
        stream.write_all(&framed).await.ok()?;
        let mut names = FxHashSet::default();
        let mut soas = 0;
        let mut buf = Vec::new();
        while soas < 2 {
            let Some(m) = read_message(&mut stream, &mut buf).await else {
                break;
            };
            if m.rcode != wire::NOERROR || m.answers.is_empty() {
                break;
            }
            for r in m.answers {
                soas += usize::from(r.rtype == wire::SOA);
                names.insert(r.owner);
            }
        }
        Some(names)
    };
    match tokio::time::timeout(AXFR_TOTAL, run).await {
        Ok(Some(names)) if names.len() >= AXFR_MIN_NAMES => {
            let mut v: Vec<String> = names.into_iter().filter(|n| !n.contains('\\')).collect();
            v.sort_unstable();
            v
        }
        _ => Vec::new(),
    }
}

fn nsec_next<'a>(m: &'a Message, owner: Option<&str>) -> Option<&'a str> {
    m.answers
        .iter()
        .chain(m.authority.iter())
        .filter(|r| owner.is_none_or(|o| r.owner == o))
        .find_map(|r| match &r.data {
            Data::Nsec(n) => Some(n.as_str()),
            _ => None,
        })
}

pub async fn nsec_probe(cfg: &Config, pairs: &[Pair]) -> Result<Vec<(usize, String)>> {
    let mut rng = stella_core::rng::Rng::seeded();
    let qs: Vec<Query> = pairs
        .iter()
        .map(|p| Query {
            name: format!("{}.{}", rng.label(), p.zone),
            qtype: wire::A,
            server: Some(SocketAddr::from((p.ip, 53))),
            rd: false,
            dnssec: true,
        })
        .collect();
    let mut index: FxHashMap<String, usize> = FxHashMap::default();
    for (i, q) in qs.iter().enumerate() {
        index.insert(format!("{}|{}", q.name, pairs[i].ip), i);
    }
    let mut out = Vec::new();
    engine::run(cfg, &qs, |r| {
        let Some(m) = r.msg else { return };
        let Some(next) = nsec_next(&m, None) else {
            return;
        };
        if next.starts_with(BLACK_LIE) {
            return;
        }
        let ip = r
            .query
            .server
            .map(|s| s.ip().to_string())
            .unwrap_or_default();
        if let Some(i) = index.get(&format!("{}|{ip}", r.query.name)) {
            out.push((*i, next.to_string()));
        }
    })
    .await?;
    Ok(out)
}

pub async fn walk(zone: &str, ip: Ipv4Addr, budget: Duration, max_names: usize) -> Vec<String> {
    let Ok(mut stub) = Stub::new().await else {
        return Vec::new();
    };
    let server = SocketAddr::from((ip, 53));
    let suffix = format!(".{zone}");
    let deadline = tokio::time::Instant::now() + budget;
    let mut names: FxHashSet<String> = FxHashSet::default();
    let mut cur = zone.to_string();
    while names.len() < max_names && tokio::time::Instant::now() < deadline {
        let mut next = None;
        for _ in 0..2 {
            if let Some(m) = stub
                .ask(server, &cur, wire::NSEC, false, true, WALK_QUERY)
                .await
            {
                next = nsec_next(&m, Some(&cur)).map(str::to_string);
                if next.is_none() {
                    let probe = format!("{BLACK_LIE}.{cur}");
                    if let Some(m) = stub
                        .ask(server, &probe, wire::A, false, true, WALK_QUERY)
                        .await
                    {
                        next = nsec_next(&m, Some(&cur))
                            .or_else(|| nsec_next(&m, None))
                            .map(str::to_string);
                    }
                }
                break;
            }
        }
        let Some(next) = next else { break };
        if next.starts_with(BLACK_LIE)
            || next == zone
            || !next.ends_with(&suffix)
            || !names.insert(next.clone())
        {
            break;
        }
        cur = next;
    }
    let mut v: Vec<String> = names.into_iter().filter(|n| !n.contains('\\')).collect();
    v.sort_unstable();
    v
}
