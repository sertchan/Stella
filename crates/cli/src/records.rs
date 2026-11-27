use crate::ctx::{Ctx, Out};
use crate::pipeline::DnsArgs;
use anyhow::Result;
use rustc_hash::FxHashSet;
use std::net::Ipv6Addr;
use stella_core::store::Row;
use stella_dns::chase;
use stella_dns::wire::{self, Data};

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    dns: DnsArgs,
    #[arg(long, help = "Use the picked hosts instead of the names on stdin")]
    picks: bool,
    #[arg(long, help = "Skip the NS, SOA and TXT lookups of the zones")]
    no_zones: bool,
}

const VERIFICATION_MARKS: &[&str] = &["-verification=", "-verify=", "verification-code="];

pub fn global_v6(a: &Ipv6Addr) -> bool {
    let first = a.segments()[0];
    !(a.is_loopback()
        || a.is_unspecified()
        || a.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || first == 0x2001 && a.segments()[1] == 0x0db8)
}

pub fn verification(txt: &str) -> Option<String> {
    let t = txt.trim().to_ascii_lowercase();
    VERIFICATION_MARKS
        .iter()
        .any(|m| t.contains(m))
        .then_some(t)
}

pub fn svcb_target(owner: &str, data: &Data) -> Option<String> {
    let Data::Svcb { target, .. } = data else {
        return None;
    };
    let t = target.trim_end_matches('.');
    (!t.is_empty() && !t.eq_ignore_ascii_case(owner)).then(|| t.to_ascii_lowercase())
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    let mut hosts: Vec<String> = if args.picks {
        ctx.store
            .all("SELECT DISTINCT host FROM hit WHERE verdict = 'PICK'")?
            .into_iter()
            .collect()
    } else {
        ctx.names()
    };
    hosts.sort_unstable();
    hosts.dedup();
    let cfg = args.dns.config();
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    let known = ctx.known();
    let (mut v6, mut targets, mut covered) = (0usize, 0usize, 0usize);
    for (host, data) in chase::lookup(&cfg, &hosts, wire::AAAA).await? {
        for d in data {
            if let Data::Aaaa(a) = d
                && global_v6(&a)
            {
                v6 += 1;
                w.send(Row::Addr {
                    addr: a.to_string(),
                    host: host.clone(),
                });
            }
        }
    }
    for (host, data) in chase::lookup(&cfg, &hosts, wire::HTTPS).await? {
        for t in data.iter().filter_map(|d| svcb_target(&host, d)) {
            targets += 1;
            let label = known.labels(known.chain_mask(std::iter::once(t.as_str())));
            covered += usize::from(!label.is_empty());
            out.row(&[&host, "https", &t, &label]);
            w.send(Row::Origin {
                host: t,
                source: "svcb".into(),
                detail: host.clone(),
            });
        }
    }
    let mut zones_done = 0usize;
    if !args.no_zones {
        let zones: Vec<String> = hosts
            .iter()
            .map(|h| ctx.regdom(h))
            .collect::<FxHashSet<_>>()
            .into_iter()
            .collect();
        zones_done = zones.len();
        let mut send = |zone: &str, kind: &'static str, value: String| {
            out.row(&[zone, kind, &value, ""]);
            w.send(Row::ZoneDns {
                zone: zone.to_string(),
                kind,
                value,
            });
        };
        for (zone, data) in chase::lookup(&cfg, &zones, wire::NS).await? {
            for d in data {
                if let Data::Name(ns) = d {
                    send(&zone, "ns", ns.trim_end_matches('.').to_ascii_lowercase());
                }
            }
        }
        for (zone, data) in chase::lookup(&cfg, &zones, wire::SOA).await? {
            for d in data {
                if let Data::Soa { mname, rname } = d {
                    send(
                        &zone,
                        "mname",
                        mname.trim_end_matches('.').to_ascii_lowercase(),
                    );
                    send(
                        &zone,
                        "rname",
                        rname.trim_end_matches('.').to_ascii_lowercase(),
                    );
                }
            }
        }
        for (zone, data) in chase::lookup(&cfg, &zones, wire::TXT).await? {
            for d in data {
                if let Data::Txt(parts) = d
                    && let Some(token) = verification(&parts.concat())
                {
                    send(&zone, "txt", token);
                }
            }
        }
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "hosts={} v6-addresses={v6} https-targets={targets} listed-targets={covered} zones={zones_done}",
        hosts.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_global_v6_only() {
        let ok: Ipv6Addr = "2606:4700::6810:84e5".parse().expect("v6");
        assert!(global_v6(&ok));
        for bad in ["::1", "fe80::1", "fd00::1", "2001:db8::1", "ff02::1"] {
            assert!(!global_v6(&bad.parse().expect("v6")), "{bad}");
        }
    }

    #[test]
    fn reads_targets_and_verification_tokens() {
        let svc = |t: &str| Data::Svcb {
            priority: 1,
            target: t.into(),
            alpn: Vec::new(),
        };
        assert_eq!(
            svcb_target("shop.com", &svc("sgtm.Vendor.net.")).as_deref(),
            Some("sgtm.vendor.net")
        );
        assert!(svcb_target("shop.com", &svc(".")).is_none());
        assert!(svcb_target("shop.com", &svc("")).is_none());
        assert!(svcb_target("shop.com", &svc("shop.com")).is_none());
        assert_eq!(
            verification(" google-site-verification=AbC123 ").as_deref(),
            Some("google-site-verification=abc123")
        );
        assert!(verification("v=spf1 include:_spf.google.com ~all").is_none());
    }
}
