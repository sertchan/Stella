use crate::context::Context;
use anyhow::Result;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::time::Duration;
use stella_core::store::{Row, Writer};
use stella_dns::resolver::{self, Resolved};
use stella_dns::transport::Config;
use stella_dns::wildcard::{self, Verdict};
use stella_net::limiter::Limiter;
use stella_probe::battery::{self, Battery, HostProbe, Prober, RANDOM};
use stella_probe::rules::{self, Hit};

#[derive(Clone, clap::Args)]
pub struct DnsArgs {
    #[arg(
        long = "resolver",
        value_name = "ADDR",
        help = "DNS server to ask instead of the public resolvers, as ip:port, repeatable"
    )]
    pub resolvers: Vec<std::net::SocketAddr>,
    #[arg(long, default_value_t = 6000, help = "DNS queries per second")]
    pub qps: u32,
    #[arg(long, default_value_t = 4, help = "Tries per DNS query")]
    pub tries: u8,
    #[arg(
        long,
        default_value_t = 2500,
        help = "DNS query timeout in milliseconds"
    )]
    pub timeout_ms: u64,
}

impl DnsArgs {
    pub fn config(&self) -> Config {
        let mut cfg = Config {
            qps: self.qps,
            tries: self.tries,
            timeout: Duration::from_millis(self.timeout_ms),
            ..Config::default()
        };
        if let Some(first) = self.resolvers.first() {
            cfg.servers.clone_from(&self.resolvers);
            cfg.ecs_server = *first;
        }
        cfg
    }
}

#[derive(Clone, clap::Args)]
pub struct ProbeArgs {
    #[arg(long, default_value_t = 300, help = "Open connections at most")]
    pub conc: usize,
    #[arg(
        long,
        default_value_t = 1000,
        help = "New connections per second at most"
    )]
    pub rate: u32,
    #[arg(
        long,
        default_value_t = 200,
        help = "Connections in their TCP and TLS handshake at the same time"
    )]
    pub handshakes: usize,
    #[arg(
        long,
        default_value_t = 6,
        help = "Connect and request timeout in seconds"
    )]
    pub timeout: u64,
    #[arg(
        long,
        default_value_t = 20,
        help = "Seconds per host for all paths and retries"
    )]
    pub budget: u64,
    #[arg(
        long,
        default_value_t = 64,
        help = "Kilobytes read from each reply at most"
    )]
    pub body_kb: usize,
}

impl ProbeArgs {
    pub fn prober(&self) -> Prober {
        let mut p = Prober::new(Limiter::with_handshakes(
            self.conc,
            self.rate,
            self.handshakes,
        ));
        p.timeout = Duration::from_secs(self.timeout);
        p.budget = Duration::from_secs(self.budget);
        p.cap = self.body_kb * 1024;
        p
    }
}

pub struct Named {
    pub res: Resolved,
    pub wild: Option<Verdict>,
    pub known: String,
}

pub async fn resolve(
    ctx: &mut Context,
    w: &Writer,
    cfg: &Config,
    names: Vec<String>,
    check_wild: bool,
) -> Result<Vec<Named>> {
    let resolved = resolver::resolve(cfg, names).await?;
    let verdicts = if check_wild {
        wildcard::check(cfg, &resolved).await?
    } else {
        FxHashMap::default()
    };
    let known = ctx.known();
    let mut out = Vec::with_capacity(resolved.len());
    for r in resolved {
        let mask = known
            .chain_mask(std::iter::once(r.host.as_str()).chain(r.chain.iter().map(String::as_str)));
        out.push(Named {
            wild: verdicts.get(&r.host).copied(),
            known: known.labels(mask),
            res: r,
        });
    }
    for n in &out {
        let r = &n.res;
        w.send(Row::Name {
            host: r.host.clone(),
            regdom: ctx.regdom(&r.host),
            known: n.known.clone(),
        });
        w.send(Row::Resolution {
            host: r.host.clone(),
            rcode: r.rcode,
            chain: r.chain.join(">"),
            addrs: join_addrs(&r.addrs),
            wild: n.wild.map_or("", Verdict::as_str).to_string(),
            known: n.known.clone(),
        });
        for a in r.addrs.iter().filter(|a| resolver::public(a)) {
            w.send(Row::Addr {
                addr: a.to_string(),
                host: r.host.clone(),
            });
        }
    }
    Ok(out)
}

pub struct Found {
    pub host: String,
    pub product: &'static str,
    pub verdict: &'static str,
    pub evidence: String,
}

impl Found {
    pub fn new(p: &HostProbe, h: &Hit) -> Self {
        Self {
            host: p.host.clone(),
            product: h.product,
            verdict: h.verdict,
            evidence: h.evidence.clone(),
        }
    }
}

pub async fn covered_elsewhere(
    ctx: &Context,
    cfg: &Config,
    hosts: Vec<String>,
) -> Result<FxHashMap<String, String>> {
    let mut out = FxHashMap::default();
    if hosts.is_empty() {
        return Ok(out);
    }
    let known = ctx.known();
    for s in stella_dns::ecs::chains(cfg, &hosts).await? {
        if let Some(t) = s.chain.iter().find(|c| known.contains(c)) {
            out.entry(s.host).or_insert_with(|| {
                format!(
                    "CNAME to included {t} seen from a {} client subnet",
                    s.region
                )
            });
        }
    }
    Ok(out)
}

pub async fn drop_covered(
    ctx: &Context,
    w: &Writer,
    cfg: &Config,
    found: &mut [Found],
) -> Result<usize> {
    let mut hosts: Vec<String> = found
        .iter()
        .filter(|f| f.verdict != rules::DROP)
        .map(|f| f.host.clone())
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    let covered = covered_elsewhere(ctx, cfg, hosts).await?;
    let mut n = 0usize;
    for f in found.iter_mut().filter(|f| f.verdict != rules::DROP) {
        let Some(why) = covered.get(&f.host) else {
            continue;
        };
        n += 1;
        f.verdict = rules::DROP;
        f.evidence = format!("{}; {why}", f.evidence);
        w.send(Row::Hit {
            host: f.host.clone(),
            product: f.product.into(),
            evidence: f.evidence.clone(),
            verdict: f.verdict.into(),
        });
    }
    Ok(n)
}

pub fn join_addrs(addrs: &[std::net::Ipv4Addr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub fn battery_for(ctx: &Context, host: &str, mode: &str) -> Battery {
    match mode {
        "full" => Battery::Full,
        "lite" => Battery::Lite,
        _ => {
            let rd = ctx.psl.regdom_or_self(host);
            Battery::Staged {
                tracking: stella_core::token::tracking(stella_core::name::subdomain(host, rd)),
            }
        }
    }
}

pub async fn probe(
    ctx: &Context,
    w: &Writer,
    prober: &Prober,
    items: Vec<(String, IpAddr, Battery)>,
    conc: usize,
    mut on_hit: impl FnMut(&HostProbe, &Hit),
) -> Stats {
    let mut st = Stats::default();
    battery::probe_all(prober, items, conc, |p| {
        st.total += 1;
        st.requests += p.requests;
        st.busy += p.elapsed;
        if p.answered() {
            st.live.push(p.elapsed);
        } else {
            st.dead_secs += p.elapsed.as_secs_f64();
        }
        st.sequential += usize::from(p.sequential);
        st.plain_http += usize::from(p.plain_http);
        st.connects += p.connects;
        if !p.answered() {
            let why = p.fails.last().map_or("no-answer", |f| f.as_str());
            *st.dead.entry(why).or_default() += 1;
            return false;
        }
        st.answered += 1;
        if p.fails.contains(&stella_net::tls::Fail::TlsReset) {
            st.dpi_retried += 1;
        }
        for (path, r) in &p.results {
            let Some(r) = r else { continue };
            w.send(Row::Probe {
                host: p.host.clone(),
                path: (*path).to_string(),
                addr: p.ip.to_string(),
                status: i64::from(r.status),
                ctype: r.ctype.clone(),
                server: r.server.clone(),
                cookies: r.cookies.join(","),
                length: r.length,
                head: battery::head(&r.body, if *path == RANDOM { 300 } else { 160 }),
                digest: stella_core::digest::digest(&r.body, &p.host),
            });
        }
        if !p.tls.is_empty() {
            w.send(Row::TlsPrint {
                host: p.host.clone(),
                print: p.tls.clone(),
            });
        }
        for san in &p.sans {
            w.send(Row::Cert {
                host: p.host.clone(),
                san: san.clone(),
            });
        }
        let rd = ctx.psl.icann_regdom_or_self(&p.host);
        let allowed = ctx.allowed(&p.host);
        let mut hit = false;
        for mut h in rules::classify(&p, rd) {
            apply_allow(&mut h, allowed);
            if p.plain_http {
                h.evidence.push_str("; over plain http");
            }
            hit |= h.verdict != rules::DROP;
            on_hit(&p, &h);
            w.send(Row::Hit {
                host: p.host.clone(),
                product: h.product.to_string(),
                evidence: h.evidence.clone(),
                verdict: h.verdict.to_string(),
            });
        }
        hit
    })
    .await;
    st
}

pub fn apply_allow(h: &mut Hit, reason: Option<&str>) {
    if let Some(reason) = reason {
        h.verdict = rules::DROP;
        h.evidence = format!("{}; allowlisted: {reason}", h.evidence);
    }
}

#[derive(Default)]
pub struct Stats {
    pub total: usize,
    pub answered: usize,
    pub requests: usize,
    pub dpi_retried: usize,
    pub sequential: usize,
    pub connects: usize,
    pub plain_http: usize,
    pub busy: Duration,
    pub live: Vec<Duration>,
    pub dead_secs: f64,
    pub dead: FxHashMap<&'static str, usize>,
}

impl Stats {
    pub fn line(&self) -> String {
        let mut dead: Vec<_> = self.dead.iter().collect();
        dead.sort_unstable();
        let dead = dead
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut live = self.live.clone();
        live.sort_unstable();
        let pct = |q: usize| {
            live.get(live.len() * q / 100)
                .map_or(0.0, Duration::as_secs_f64)
        };
        format!(
            "hosts={} answered={} requests={} connects={} dpi-retried={} no-pipelining={} plain-http={} host-secs={:.2} dead-secs={:.2} live-p50={:.2} p90={:.2} p99={:.2} dead: {dead}",
            self.total,
            self.answered,
            self.requests,
            self.connects,
            self.dpi_retried,
            self.sequential,
            self.plain_http,
            self.busy.as_secs_f64(),
            self.dead_secs,
            pct(50),
            pct(90),
            pct(99)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit() -> Hit {
        Hit {
            product: "sgtm",
            evidence: "healthy ok, random 400".into(),
            verdict: rules::PICK,
        }
    }

    #[test]
    fn allowlist_turns_any_verdict_into_drop_with_reason() {
        let mut h = hit();
        apply_allow(&mut h, None);
        assert_eq!(h, hit());
        apply_allow(&mut h, Some("fraud vendor"));
        assert_eq!(h.verdict, rules::DROP);
        assert_eq!(
            h.evidence,
            "healthy ok, random 400; allowlisted: fraud vendor"
        );
    }

    #[test]
    fn joins_addresses_with_commas() {
        assert_eq!(join_addrs(&[]), "");
        assert_eq!(
            join_addrs(&[
                "192.0.2.1".parse().expect("addr"),
                "198.51.100.7".parse().expect("addr")
            ]),
            "192.0.2.1,198.51.100.7"
        );
    }
}
