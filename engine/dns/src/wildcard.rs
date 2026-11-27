use crate::resolver::{self, Resolved};
use crate::transport::Config;
use crate::wire;
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use stella_core::random::Rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Real,
    WildDiff,
    Wild,
    Unsure,
    Nx,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Real => "REAL",
            Self::WildDiff => "WILDDIFF",
            Self::Wild => "WILD",
            Self::Unsure => "UNSURE",
            Self::Nx => "NX",
        }
    }
}

fn zones(host: &str) -> impl Iterator<Item = &str> {
    let first = stella_core::name::parent(host);
    let second = first.and_then(stella_core::name::parent);
    first.into_iter().chain(second)
}

fn nets(r: &Resolved) -> FxHashSet<[u8; 3]> {
    r.addrs
        .iter()
        .map(|a| {
            let o = a.octets();
            [o[0], o[1], o[2]]
        })
        .collect()
}

pub fn same(h: &Resolved, c: &Resolved) -> bool {
    match (h.chain.is_empty(), c.chain.is_empty()) {
        (false, false) => h.last() == c.last(),
        (true, true) => {
            let cn = nets(c);
            nets(h).iter().any(|n| cn.contains(n))
        }
        _ => false,
    }
}

pub fn judge(h: &Resolved, controls: &[&Resolved]) -> Verdict {
    if !h.answered() {
        return Verdict::Nx;
    }
    let mut v = Verdict::Unsure;
    for c in controls {
        if c.rcode == i64::from(wire::NXDOMAIN) {
            if v == Verdict::Unsure {
                v = Verdict::Real;
            }
            continue;
        }
        if !c.answered() {
            continue;
        }
        if same(h, c) {
            return Verdict::Wild;
        }
        v = Verdict::WildDiff;
    }
    v
}

pub async fn check(cfg: &Config, hosts: &[Resolved]) -> Result<FxHashMap<String, Verdict>> {
    let mut rng = Rng::seeded();
    let mut control_of: FxHashMap<&str, String> = FxHashMap::default();
    for h in hosts.iter().filter(|h| h.answered()) {
        for z in zones(&h.host) {
            control_of
                .entry(z)
                .or_insert_with(|| format!("{}.{z}", rng.label()));
        }
    }
    let names: Vec<String> = control_of.values().cloned().collect();
    let answers = resolver::resolve(cfg, names).await?;
    let by_name: FxHashMap<&str, &Resolved> =
        answers.iter().map(|r| (r.host.as_str(), r)).collect();
    let mut out = FxHashMap::default();
    for h in hosts {
        let controls: Vec<&Resolved> = zones(&h.host)
            .filter_map(|z| control_of.get(z))
            .filter_map(|c| by_name.get(c.as_str()).copied())
            .collect();
        out.insert(h.host.clone(), judge(h, &controls));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn r(host: &str, rcode: u8, chain: &[&str], addrs: &[[u8; 4]]) -> Resolved {
        Resolved {
            host: host.into(),
            rcode: i64::from(rcode),
            chain: chain.iter().map(std::string::ToString::to_string).collect(),
            addrs: addrs.iter().map(|a| Ipv4Addr::from(*a)).collect(),
        }
    }

    #[test]
    fn judges_controls() {
        let host = r("t.a.com", 0, &["x.cdn.net"], &[[1, 2, 3, 4]]);
        let nx = r("zq1.a.com", wire::NXDOMAIN, &[], &[]);
        let wild = r("zq2.a.com", 0, &["x.cdn.net"], &[[1, 2, 3, 9]]);
        let diff = r("zq3.a.com", 0, &[], &[[9, 9, 9, 9]]);
        assert_eq!(judge(&host, &[&nx]), Verdict::Real);
        assert_eq!(judge(&host, &[&nx, &wild]), Verdict::Wild);
        assert_eq!(judge(&host, &[&diff]), Verdict::WildDiff);
        assert_eq!(judge(&host, &[]), Verdict::Unsure);
        assert_eq!(judge(&nx, &[]), Verdict::Nx);
    }
}
