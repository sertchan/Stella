use crate::ctx::{Ctx, Out};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};

#[derive(clap::Args)]
pub struct Args {
    #[arg(
        long,
        default_value_t = 25,
        help = "Skip a name server, SOA mailbox or TXT token shared by more zones than this"
    )]
    max_share: usize,
    #[arg(
        long,
        default_value_t = 0.5,
        help = "Share of the zones behind one value that must be pick zones"
    )]
    min_pick_share: f64,
}

const SHARED_DNS: &[&str] = &[
    "akam.net",
    "akamai.com",
    "akamaiedge.net",
    "amazon.com",
    "amazonaws.com",
    "awsdns-hostmaster.amazon.com",
    "azure-dns.com",
    "azure-dns.net",
    "azure-dns.org",
    "azure-dns.info",
    "cloudflare.com",
    "cloudflare.net",
    "cloudns.net",
    "digitalocean.com",
    "dnsimple.com",
    "dnsmadeeasy.com",
    "domaincontrol.com",
    "dynect.net",
    "gandi.net",
    "godaddy.com",
    "google.com",
    "googledomains.com",
    "hetzner.com",
    "linode.com",
    "microsoft.com",
    "name-services.com",
    "netlify.com",
    "nsone.net",
    "ovh.net",
    "registrar-servers.com",
    "squarespacedns.com",
    "ultradns.com",
    "ultradns.net",
    "ultradns.org",
    "ultradns.biz",
    "vercel-dns.com",
    "wixdns.net",
];

#[derive(Debug, PartialEq)]
pub struct Mate {
    pub zone: String,
    pub kind: String,
    pub key: String,
    pub pick_zones: usize,
    pub example: String,
}

pub fn key(kind: &str, value: &str, regdom: impl Fn(&str) -> String) -> Option<String> {
    let key = match kind {
        "ns" => regdom(value),
        "rname" | "txt" => value.to_string(),
        _ => return None,
    };
    let owner = if kind == "txt" {
        String::new()
    } else {
        regdom(value)
    };
    let shared = SHARED_DNS
        .iter()
        .any(|s| owner == *s || value == *s || value.ends_with(&format!(".{s}")));
    (!shared && !key.is_empty()).then_some(key)
}

pub fn mates(
    rows: &[(String, String, String)],
    pick_zones: &FxHashSet<String>,
    max_share: usize,
    min_pick_share: f64,
    regdom: impl Fn(&str) -> String,
) -> Vec<Mate> {
    let mut groups: FxHashMap<(String, String), FxHashSet<&str>> = FxHashMap::default();
    for (zone, kind, value) in rows {
        if let Some(k) = key(kind, value, &regdom) {
            groups
                .entry((kind.clone(), k))
                .or_default()
                .insert(zone.as_str());
        }
    }
    let mut out = Vec::new();
    for ((kind, key), zones) in groups {
        if zones.len() < 2 || zones.len() > max_share {
            continue;
        }
        let mut picks: Vec<&str> = zones
            .iter()
            .copied()
            .filter(|z| pick_zones.contains(*z))
            .collect();
        if picks.is_empty() || (picks.len() as f64) < min_pick_share * zones.len() as f64 {
            continue;
        }
        picks.sort_unstable();
        for z in zones.iter().filter(|z| !pick_zones.contains(**z)) {
            out.push(Mate {
                zone: (*z).to_string(),
                kind: kind.clone(),
                key: key.clone(),
                pick_zones: picks.len(),
                example: picks[0].to_string(),
            });
        }
    }
    out.sort_unstable_by(|a, b| {
        b.pick_zones
            .cmp(&a.pick_zones)
            .then_with(|| a.zone.cmp(&b.zone))
            .then_with(|| a.kind.cmp(&b.kind))
    });
    out
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    let rows: Vec<(String, String, String)> = ctx
        .store
        .rows("SELECT zone, kind, value FROM zonedns")?
        .into_iter()
        .filter_map(|mut r| {
            let value = r.pop()?;
            let kind = r.pop()?;
            let zone = r.pop()?;
            Some((zone, kind, value))
        })
        .collect();
    let pick_zones: FxHashSet<String> = ctx
        .store
        .all("SELECT DISTINCT host FROM hit WHERE verdict = 'PICK'")?
        .iter()
        .map(|h| ctx.regdom(h))
        .collect();
    let found = mates(
        &rows,
        &pick_zones,
        args.max_share,
        args.min_pick_share,
        |h| ctx.regdom(h),
    );
    let mut out = Out::new();
    for m in &found {
        out.row(&[
            &m.zone,
            &m.kind,
            &m.key,
            &m.pick_zones.to_string(),
            &m.example,
        ]);
    }
    let zones: FxHashSet<&str> = found.iter().map(|m| m.zone.as_str()).collect();
    eprintln!(
        "rows={} pick-zones={} mates={} zones={}",
        rows.len(),
        pick_zones.len(),
        found.len(),
        zones.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regdom(h: &str) -> String {
        let parts: Vec<&str> = h.split('.').collect();
        parts[parts.len().saturating_sub(2)..].join(".")
    }

    fn row(z: &str, k: &str, v: &str) -> (String, String, String) {
        (z.into(), k.into(), v.into())
    }

    #[test]
    fn finds_zones_sharing_private_dns_with_picks() {
        let rows = vec![
            row("adnet.com", "ns", "ns1.adnet-dns.com"),
            row("adnet2.com", "ns", "ns2.adnet-dns.com"),
            row("shop.com", "ns", "ns1.cloudflare.com"),
            row("adnet.com", "ns", "ns1.cloudflare.com"),
            row("other.com", "ns", "ns2.cloudflare.com"),
            row("adnet.com", "rname", "ops.adnet-group.com"),
            row("trk.io", "rname", "ops.adnet-group.com"),
            row("trk.io", "rname", "awsdns-hostmaster.amazon.com"),
            row("x.com", "rname", "awsdns-hostmaster.amazon.com"),
            row("adnet.com", "txt", "google-site-verification=abc"),
            row("lonely.com", "txt", "google-site-verification=zzz"),
        ];
        let picks: FxHashSet<String> = ["adnet.com".to_string()].into_iter().collect();
        let got = mates(&rows, &picks, 25, 0.5, regdom);
        let pairs: Vec<(&str, &str)> = got
            .iter()
            .map(|m| (m.zone.as_str(), m.kind.as_str()))
            .collect();
        assert_eq!(pairs, [("adnet2.com", "ns"), ("trk.io", "rname")]);
        assert_eq!(got[0].key, "adnet-dns.com");
        assert_eq!(got[0].example, "adnet.com");
        assert!(mates(&rows, &picks, 1, 0.5, regdom).is_empty());
        let mut hosted = rows.clone();
        for i in 0..5 {
            hosted.push(row(&format!("client{i}.com"), "ns", "ns1.adnet-dns.com"));
        }
        assert!(
            mates(&hosted, &picks, 25, 0.5, regdom)
                .iter()
                .all(|m| m.kind != "ns")
        );
    }
}
