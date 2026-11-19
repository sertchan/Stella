use crate::ctx::Ctx;
use anyhow::Result;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::time::Duration;
use stella_core::store::{Row, Writer};
use stella_dns::chase::{self, Resolved};
use stella_dns::engine::Config;
use stella_dns::wild::{self, Verdict};
use stella_net::limit::Limiter;
use stella_probe::battery::{self, Battery, HostProbe, Prober, RANDOM};
use stella_probe::rules::{self, Hit};

#[derive(Clone, clap::Args)]
pub struct DnsArgs {
    #[arg(long, default_value_t = 2000, help = "DNS queries per second")]
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
        Config {
            qps: self.qps,
            tries: self.tries,
            timeout: Duration::from_millis(self.timeout_ms),
            ..Config::default()
        }
    }
}

#[derive(Clone, clap::Args)]
pub struct ProbeArgs {
    #[arg(long, default_value_t = 300, help = "Open connections at most")]
    pub conc: usize,
    #[arg(
        long,
        default_value_t = 250,
        help = "New connections per second at most"
    )]
    pub rate: u32,
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
}

impl ProbeArgs {
    pub fn prober(&self) -> Prober {
        let mut p = Prober::new(Limiter::new(self.conc, self.rate));
        p.timeout = Duration::from_secs(self.timeout);
        p.budget = Duration::from_secs(self.budget);
        p
    }
}

pub struct Named {
    pub res: Resolved,
    pub wild: Option<Verdict>,
    pub known: String,
}

pub async fn resolve(
    ctx: &mut Ctx,
    w: &Writer,
    cfg: &Config,
    names: Vec<String>,
    check_wild: bool,
) -> Result<Vec<Named>> {
    let resolved = chase::resolve(cfg, names).await?;
    let verdicts = if check_wild {
        wild::check(cfg, &resolved).await?
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
        for a in r.addrs.iter().filter(|a| chase::public(a)) {
            w.send(Row::Addr {
                addr: a.to_string(),
                host: r.host.clone(),
            });
        }
    }
    Ok(out)
}

pub fn join_addrs(addrs: &[std::net::Ipv4Addr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub fn battery_for(ctx: &Ctx, host: &str, mode: &str) -> Battery {
    match mode {
        "full" => Battery::Full,
        "lite" => Battery::Lite,
        _ => {
            let rd = ctx.psl.regdom_or_self(host);
            if stella_core::token::tracking(stella_core::name::subdomain(host, rd)) {
                Battery::Full
            } else {
                Battery::Lite
            }
        }
    }
}

pub async fn probe(
    ctx: &Ctx,
    w: &Writer,
    prober: &Prober,
    items: Vec<(String, IpAddr, Battery)>,
    conc: usize,
    mut on_hit: impl FnMut(&HostProbe, &Hit),
) -> (usize, usize) {
    let mut total = 0;
    let mut answered = 0;
    battery::probe_all(prober, items, conc, |p| {
        total += 1;
        if !p.answered() {
            return;
        }
        answered += 1;
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
            });
        }
        for san in &p.sans {
            w.send(Row::Cert {
                host: p.host.clone(),
                san: san.clone(),
            });
        }
        let rd = ctx.psl.regdom_or_self(&p.host);
        let allowed = ctx.allowed(&p.host);
        for mut h in rules::classify(&p, stella_core::name::subdomain(&p.host, rd)) {
            if let Some(reason) = allowed {
                h.verdict = rules::DROP;
                h.evidence = format!("{}; allowlisted: {reason}", h.evidence);
            }
            on_hit(&p, &h);
            w.send(Row::Hit {
                host: p.host.clone(),
                product: h.product.to_string(),
                evidence: h.evidence.clone(),
                verdict: h.verdict.to_string(),
            });
        }
    })
    .await;
    (total, answered)
}
