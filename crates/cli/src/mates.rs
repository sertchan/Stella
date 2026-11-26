use crate::ctx::{Ctx, Out};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};

pub const DEFAULT_MAX_SHARE: usize = 25;
pub const DEFAULT_PICK_SHARE: f64 = 0.5;

#[derive(clap::Args)]
pub struct Args {
    #[arg(
        long,
        default_value_t = DEFAULT_MAX_SHARE,
        help = "Skip a name server, SOA mailbox or TXT token shared by more zones than this"
    )]
    max_share: usize,
    #[arg(
        long,
        default_value_t = DEFAULT_PICK_SHARE,
        help = "Share of the zones behind one value that must be pick zones"
    )]
    min_pick_share: f64,
}

pub const SHARED_DNS: &[&str] = &[
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
        "rname" | "txt" | "tag" | "cert" => value.to_string(),
        _ => return None,
    };
    let owner = if matches!(kind, "txt" | "tag" | "cert") {
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
    let mut kept: Vec<(String, String, Vec<&str>)> = Vec::new();
    for ((kind, key), zones) in groups {
        if zones.len() < 2 || zones.len() > max_share {
            continue;
        }
        let picks = zones.iter().filter(|z| pick_zones.contains(**z)).count();
        if picks == 0 || (picks as f64) < min_pick_share * zones.len() as f64 {
            continue;
        }
        let mut zones: Vec<&str> = zones.into_iter().collect();
        zones.sort_unstable();
        kept.push((kind, key, zones));
    }
    kept.sort_unstable();
    let mut index: FxHashMap<&str, usize> = FxHashMap::default();
    for (_, _, zones) in &kept {
        for z in zones {
            let n = index.len();
            index.entry(z).or_insert(n);
        }
    }
    let mut parent: Vec<usize> = (0..index.len()).collect();
    fn root(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    for (_, _, zones) in &kept {
        let first = index[zones[0]];
        for z in &zones[1..] {
            let (a, b) = (root(&mut parent, first), root(&mut parent, index[z]));
            parent[a] = b;
        }
    }
    let mut picks_in: FxHashMap<usize, Vec<&str>> = FxHashMap::default();
    for (z, i) in &index {
        if pick_zones.contains(*z) {
            let r = root(&mut parent, *i);
            picks_in.entry(r).or_default().push(z);
        }
    }
    for v in picks_in.values_mut() {
        v.sort_unstable();
    }
    let mut first_link: FxHashMap<&str, (&str, &str)> = FxHashMap::default();
    for (kind, key, zones) in &kept {
        for z in zones {
            first_link.entry(z).or_insert((kind.as_str(), key.as_str()));
        }
    }
    let mut out = Vec::new();
    for (z, i) in &index {
        if pick_zones.contains(*z) {
            continue;
        }
        let r = root(&mut parent, *i);
        let Some(picks) = picks_in.get(&r) else {
            continue;
        };
        let (kind, key) = first_link[z];
        out.push(Mate {
            zone: (*z).to_string(),
            kind: kind.to_string(),
            key: key.to_string(),
            pick_zones: picks.len(),
            example: picks[0].to_string(),
        });
    }
    out.sort_unstable_by(|a, b| {
        b.pick_zones
            .cmp(&a.pick_zones)
            .then_with(|| a.zone.cmp(&b.zone))
            .then_with(|| a.kind.cmp(&b.kind))
    });
    out
}

pub fn zones(ctx: &Ctx) -> Result<Vec<String>> {
    let rows = edges(ctx)?;
    let pick_zones = pick_zones(ctx)?;
    let mut out: Vec<String> = mates(
        &rows,
        &pick_zones,
        DEFAULT_MAX_SHARE,
        DEFAULT_PICK_SHARE,
        |h| ctx.regdom(h),
    )
    .into_iter()
    .map(|m| m.zone)
    .collect::<FxHashSet<_>>()
    .into_iter()
    .collect();
    out.sort_unstable();
    Ok(out)
}

fn pick_zones(ctx: &Ctx) -> Result<FxHashSet<String>> {
    Ok(ctx
        .store
        .all("SELECT DISTINCT host FROM hit WHERE verdict = 'PICK'")?
        .iter()
        .map(|h| ctx.regdom(h))
        .collect())
}

fn edges(ctx: &Ctx) -> Result<Vec<(String, String, String)>> {
    let mut rows: Vec<(String, String, String)> = ctx
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
    for r in ctx.store.rows("SELECT site, id FROM tag")? {
        rows.push((ctx.regdom(&r[0]), "tag".into(), r[1].clone()));
    }
    for r in ctx.store.rows("SELECT host, san FROM cert")? {
        let san = r[1].trim_start_matches("*.");
        rows.push((ctx.regdom(&r[0]), "cert".into(), r[0].clone()));
        rows.push((ctx.regdom(san), "cert".into(), r[0].clone()));
    }
    Ok(rows)
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    let rows = edges(ctx)?;
    let pick_zones = pick_zones(ctx)?;
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
            row("adnet.com", "tag", "GTM-AAA111"),
            row("adnet-brand.de", "tag", "GTM-AAA111"),
            row("adnet.com", "cert", "sgtm.adnet.com"),
            row("adnet-cdn.net", "cert", "sgtm.adnet.com"),
        ];
        let picks: FxHashSet<String> = ["adnet.com".to_string()].into_iter().collect();
        let got = mates(&rows, &picks, 25, 0.5, regdom);
        let pairs: Vec<(&str, &str)> = got
            .iter()
            .map(|m| (m.zone.as_str(), m.kind.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("adnet-brand.de", "tag"),
                ("adnet-cdn.net", "cert"),
                ("adnet2.com", "ns"),
                ("trk.io", "rname")
            ]
        );
        assert_eq!(got[2].key, "adnet-dns.com");
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
