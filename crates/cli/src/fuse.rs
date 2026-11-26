use crate::ctx::{Ctx, Out};
use anyhow::Result;
use rusqlite::params;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeSet;
use stella_probe::rules::{PICK, REVIEW};

#[derive(clap::Args)]
pub struct Args {
    #[arg(
        long,
        default_value_t = 2,
        help = "Independent signal kinds a host needs before a REVIEW becomes a PICK"
    )]
    min_kinds: usize,
    #[arg(
        long,
        default_value_t = 40,
        help = "Skip addresses shared by more hosts than this as neighbour evidence"
    )]
    max_ip: usize,
    #[arg(long, help = "Print the changes without writing them")]
    dry_run: bool,
}

pub const FUSED: &str = "fused";
const BEHAVIOUR_MIN_SCORE: i64 = 2;
const APPS_MIN: usize = 2;
const FINGERPRINT_SITES: usize = 2;

const KEEP_REVIEW: &[&str] = &[
    "main site of its zone",
    "html app at /",
    "allowlisted",
    "staging or dev name",
    "allow request",
    "unblocked in allow",
    "deny request",
    "allowed by",
    "already requested",
];

pub fn kind_of(product: &str) -> Option<&'static str> {
    match product {
        FUSED => None,
        "collector" | "pixel" => Some("collector"),
        "behaviour" => Some("behaviour"),
        crate::cname::PRODUCT => Some("vendor-cname"),
        "twin" => Some("twin"),
        _ => Some("product"),
    }
}

pub struct HitRow {
    pub host: String,
    pub product: String,
    pub verdict: String,
    pub evidence: String,
}

#[derive(Debug, PartialEq)]
pub enum Change {
    Upgrade {
        host: String,
        product: String,
        evidence: String,
    },
    New {
        host: String,
        evidence: String,
    },
}

pub fn independent(kinds: &BTreeSet<&str>) -> usize {
    kinds
        .iter()
        .map(|k| match *k {
            "vendor-cname" | "neighbour" => "infrastructure",
            k => k,
        })
        .collect::<FxHashSet<_>>()
        .len()
}

fn note(kinds: &BTreeSet<&str>) -> String {
    format!(
        "fused: {}",
        kinds.iter().copied().collect::<Vec<_>>().join(", ")
    )
}

pub fn fuse(
    mut signals: FxHashMap<String, BTreeSet<&'static str>>,
    hits: &[HitRow],
    min_kinds: usize,
    blocked: impl Fn(&str) -> bool,
) -> Vec<Change> {
    for h in hits {
        if let Some(k) = kind_of(&h.product) {
            signals.entry(h.host.clone()).or_default().insert(k);
        }
    }
    let with_hit: FxHashSet<&str> = hits.iter().map(|h| h.host.as_str()).collect();
    let mut out = Vec::new();
    for h in hits.iter().filter(|h| h.verdict == REVIEW) {
        let Some(kinds) = signals.get(&h.host) else {
            continue;
        };
        if independent(kinds) < min_kinds
            || h.product == FUSED
            || KEEP_REVIEW.iter().any(|m| h.evidence.contains(m))
            || h.evidence.contains("fused:")
        {
            continue;
        }
        out.push(Change::Upgrade {
            host: h.host.clone(),
            product: h.product.clone(),
            evidence: format!("{}; {}", h.evidence, note(kinds)),
        });
    }
    let mut fresh: Vec<(&String, &BTreeSet<&str>)> = signals
        .iter()
        .filter(|(host, kinds)| {
            independent(kinds) >= min_kinds && !with_hit.contains(host.as_str()) && !blocked(host)
        })
        .collect();
    fresh.sort_unstable_by(|a, b| a.0.cmp(b.0));
    for (host, kinds) in fresh {
        out.push(Change::New {
            host: host.clone(),
            evidence: note(kinds),
        });
    }
    out
}

fn add(signals: &mut FxHashMap<String, BTreeSet<&'static str>>, host: &str, kind: &'static str) {
    signals.entry(host.to_string()).or_default().insert(kind);
}

pub fn gather(ctx: &Ctx, max_ip: usize) -> Result<FxHashMap<String, BTreeSet<&'static str>>> {
    let mut signals: FxHashMap<String, BTreeSet<&'static str>> = FxHashMap::default();
    for r in ctx.store.rows(&format!(
        "SELECT host FROM score WHERE score >= {BEHAVIOUR_MIN_SCORE} AND known = ''"
    ))? {
        add(&mut signals, &r[0], "behaviour");
    }
    let mut apps: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();
    for r in ctx.store.rows("SELECT url, pkg FROM apk_url")? {
        if let Some(h) = stella_core::name::host_of_url(&r[0]) {
            apps.entry(h.to_ascii_lowercase())
                .or_default()
                .insert(r[1].clone());
        }
    }
    for (h, pkgs) in &apps {
        if pkgs.len() >= APPS_MIN {
            add(&mut signals, h, "apps");
        }
    }
    for r in ctx.store.rows(&format!(
        "SELECT script FROM hook WHERE api IN ('canvas', 'webgl', 'audio') AND script <> ''
         GROUP BY script HAVING count(DISTINCT site) >= {FINGERPRINT_SITES}"
    ))? {
        add(&mut signals, &r[0], "fingerprint");
    }
    let picks = ctx.store.all(&format!(
        "SELECT DISTINCT host FROM hit WHERE verdict = '{PICK}'"
    ))?;
    let mut by_addr: FxHashMap<String, Vec<String>> = FxHashMap::default();
    for r in ctx.store.rows("SELECT addr, host FROM addr")? {
        by_addr.entry(r[0].clone()).or_default().push(r[1].clone());
    }
    for hosts in by_addr.values() {
        if hosts.len() > max_ip || !hosts.iter().any(|h| picks.contains(h)) {
            continue;
        }
        for h in hosts.iter().filter(|h| !picks.contains(*h)) {
            add(&mut signals, h, "neighbour");
        }
    }
    for r in ctx.store.rows("SELECT host, san FROM cert")? {
        let san = r[1].trim_start_matches("*.");
        if picks.contains(&r[0]) && san != r[0] && !picks.contains(san) {
            add(&mut signals, san, "neighbour");
        }
    }
    Ok(signals)
}

pub fn apply(ctx: &Ctx, min_kinds: usize, max_ip: usize, dry_run: bool) -> Result<usize> {
    let signals = gather(ctx, max_ip)?;
    let hits: Vec<HitRow> = ctx
        .store
        .rows(&format!(
            "SELECT host, product, verdict, evidence FROM hit WHERE verdict IN ('{PICK}', '{REVIEW}')"
        ))?
        .into_iter()
        .filter_map(|mut r| {
            let evidence = r.pop()?;
            let verdict = r.pop()?;
            let product = r.pop()?;
            let host = r.pop()?;
            Some(HitRow {
                host,
                product,
                verdict,
                evidence,
            })
        })
        .collect();
    let dropped: FxHashSet<String> = ctx
        .store
        .all("SELECT DISTINCT host FROM hit WHERE verdict = 'DROP'")?;
    let listed: FxHashSet<String> = ctx.store.all("SELECT host FROM name WHERE known <> ''")?;
    let changes = fuse(signals, &hits, min_kinds, |h| {
        dropped.contains(h) || listed.contains(h) || ctx.allowed(h).is_some()
    });
    let mut out = Out::new();
    let tx = ctx.store.conn.unchecked_transaction()?;
    for c in &changes {
        match c {
            Change::Upgrade {
                host,
                product,
                evidence,
            } => {
                out.row(&[host, product, REVIEW, PICK, evidence]);
                if !dry_run {
                    tx.execute(
                        "UPDATE hit SET verdict = ?1, evidence = ?2 WHERE host = ?3 AND product = ?4",
                        params![PICK, evidence, host, product],
                    )?;
                }
            }
            Change::New { host, evidence } => {
                out.row(&[host, FUSED, "", REVIEW, evidence]);
                if !dry_run {
                    tx.execute(
                        "INSERT OR REPLACE INTO hit VALUES(?1, ?2, ?3, ?4, ?5)",
                        params![host, FUSED, evidence, REVIEW, stella_core::now()],
                    )?;
                }
            }
        }
    }
    tx.commit()?;
    Ok(changes.len())
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    let n = apply(ctx, args.min_kinds, args.max_ip, args.dry_run)?;
    eprintln!("changes={n} dry-run={}", args.dry_run);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(host: &str, product: &str, verdict: &str, evidence: &str) -> HitRow {
        HitRow {
            host: host.into(),
            product: product.into(),
            verdict: verdict.into(),
            evidence: evidence.into(),
        }
    }

    fn signals(rows: &[(&str, &'static str)]) -> FxHashMap<String, BTreeSet<&'static str>> {
        let mut m: FxHashMap<String, BTreeSet<&'static str>> = FxHashMap::default();
        for (h, k) in rows {
            m.entry((*h).to_string()).or_default().insert(*k);
        }
        m
    }

    #[test]
    fn upgrades_reviews_with_two_independent_kinds() {
        let hits = [
            hit("c.vendor.io", "collector", REVIEW, "/ empty 204"),
            hit("solo.vendor.io", "collector", REVIEW, "/ empty 204"),
            hit(
                "www.shop.com",
                "sgtm",
                REVIEW,
                "healthy ok; main site of its zone",
            ),
            hit(
                "t.vendor.io",
                "collector",
                REVIEW,
                "x; allow request #9 is open",
            ),
        ];
        let s = signals(&[
            ("c.vendor.io", "apps"),
            ("www.shop.com", "behaviour"),
            ("t.vendor.io", "neighbour"),
        ]);
        let got = fuse(s, &hits, 2, |_| false);
        assert_eq!(
            got,
            [Change::Upgrade {
                host: "c.vendor.io".into(),
                product: "collector".into(),
                evidence: "/ empty 204; fused: apps, collector".into(),
            }]
        );
    }

    #[test]
    fn hosts_without_hits_only_reach_review() {
        let s = signals(&[
            ("x.io", "apps"),
            ("x.io", "behaviour"),
            ("y.io", "apps"),
            ("z.io", "apps"),
            ("z.io", "neighbour"),
        ]);
        let got = fuse(s, &[], 2, |h| h == "z.io");
        assert_eq!(
            got,
            [Change::New {
                host: "x.io".into(),
                evidence: "fused: apps, behaviour".into(),
            }]
        );
    }

    #[test]
    fn same_kind_twice_does_not_count() {
        let hits = [
            hit("p.io", "pixel", REVIEW, "tiny gif"),
            hit("p.io", "collector", REVIEW, "empty 204"),
        ];
        assert!(fuse(FxHashMap::default(), &hits, 2, |_| false).is_empty());
        let infra = [hit(
            "v.io",
            crate::cname::PRODUCT,
            REVIEW,
            "CNAME to cdn.vendor.net",
        )];
        let s = signals(&[("v.io", "neighbour")]);
        assert!(fuse(s, &infra, 2, |_| false).is_empty());
        assert_eq!(kind_of(FUSED), None);
        assert_eq!(kind_of("matomo"), Some("product"));
    }
}
