use crate::context::{Context, Out};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use stella_core::category::{self, Category};
use stella_core::list::{self, BREAKAGE_OK, Tier};

pub fn parse_tier(s: &str) -> Result<Tier, String> {
    Tier::from_slug(s).ok_or_else(|| format!("{s} is not a tier, use standard or aggressive"))
}

pub fn parse_category(s: &str) -> Result<Category, String> {
    Category::from_slug(s).ok_or_else(|| {
        format!("{s} is not a category, use ads, tracker, telemetry or self-hosted-telemetry")
    })
}

#[derive(clap::Args)]
pub struct ExportArgs {
    #[arg(long, help = "Leave out hosts that a reference list already covers")]
    unknown_only: bool,
    #[arg(long, help = "Skip hosts already named in a HaGeZi deny issue")]
    unfiled: bool,
    #[arg(long, value_parser = parse_tier, help = "Only this tier: standard or aggressive")]
    tier: Option<Tier>,
    #[arg(long, value_parser = parse_category, help = "Only this list: ads, tracker, telemetry or self-hosted-telemetry")]
    category: Option<Category>,
    #[arg(long, help = "Only this subcategory, such as umami or server-side-gtm")]
    subcategory: Option<String>,
    #[arg(
        long,
        default_value_t = 0,
        help = "Export the whole zone instead of its hosts when it has this many picks and no titled site at its apex, 0 turns it off"
    )]
    zones: usize,
    #[arg(
        long,
        help = "Write every column of metadata.tsv for the chosen entries to this file"
    )]
    metadata: Option<std::path::PathBuf>,
}

pub const METADATA_HEADER: &str = "entry\tsubcategory\tadded\ttier\tkind\tproducts\tevidence\tsources\tchain\taddresses\tmembers\n";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub category: Option<Category>,
    pub tier: Tier,
    pub tier_reason: &'static str,
    pub subcategory: String,
    pub zone: bool,
    pub members: Vec<String>,
    pub products: Vec<String>,
    pub evidence: Vec<String>,
    pub sources: Vec<String>,
    pub chain: String,
    pub addrs: String,
}

impl Entry {
    pub fn list(&self) -> String {
        self.category
            .map_or_else(|| "-".to_string(), |c| list::list_id(self.tier, c))
    }

    pub fn place(&mut self, verified: bool) {
        if let Some(c) = self.category {
            (self.tier, self.tier_reason) = Tier::place(c, verified);
        }
    }

    pub fn reason(&self) -> String {
        let mut parts = vec![if self.zone {
            format!(
                "zone with {} picks: {}",
                self.members.len(),
                self.members.join(", ")
            )
        } else {
            format!("product {}", self.products.join(", "))
        }];
        if !self.tier_reason.is_empty() {
            parts.push(self.tier_reason.to_string());
        }
        parts.extend(self.evidence.iter().cloned());
        if !self.sources.is_empty() {
            parts.push(format!("found by {}", self.sources.join(", ")));
        }
        if !self.chain.is_empty() {
            parts.push(format!("CNAME {}", self.chain));
        }
        if !self.addrs.is_empty() {
            parts.push(format!("resolves to {}", self.addrs));
        }
        parts.join(" | ")
    }

    pub fn metadata(&self, added: &str) -> String {
        let cols = [
            self.name.as_str(),
            self.subcategory.as_str(),
            added,
            self.tier_reason,
            if self.zone { "zone" } else { "host" },
            &self.products.join(","),
            &self.evidence.join(" | "),
            &self.sources.join(" | "),
            self.chain.as_str(),
            self.addrs.as_str(),
            &self.members.join(","),
        ];
        let mut line = cols
            .iter()
            .map(|c| c.replace(['\t', '\n'], " "))
            .collect::<Vec<_>>()
            .join("\t");
        line.push('\n');
        line
    }
}

pub type Candidate = (String, bool);
pub type Scored = (Entry, Candidate);

pub struct Picks {
    pub entries: Vec<Entry>,
    pub skipped: usize,
}

impl Picks {
    pub fn chosen(
        &self,
        tier: Option<Tier>,
        category: Option<Category>,
        subcategory: Option<&str>,
    ) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| tier.is_none_or(|t| e.tier == t))
            .filter(|e| category.is_none_or(|c| e.category == Some(c)))
            .filter(|e| subcategory.is_none_or(|s| e.subcategory == s))
            .collect()
    }
}

pub fn promoted<'a>(
    hosts: &[&'a str],
    regdom: impl Fn(&str) -> String,
    min: usize,
    titled_apex: impl Fn(&str) -> bool,
) -> FxHashMap<String, Vec<&'a str>> {
    let mut by_zone: FxHashMap<String, Vec<&str>> = FxHashMap::default();
    for h in hosts {
        by_zone.entry(regdom(h)).or_default().push(h);
    }
    by_zone.retain(|zone, picks| min > 0 && picks.len() >= min && !titled_apex(zone));
    by_zone
}

pub fn verified(e: &Entry) -> bool {
    e.evidence.iter().any(|v| v.contains(BREAKAGE_OK))
}

fn grouped(rows: &[Vec<String>]) -> FxHashMap<&str, Vec<&str>> {
    let mut by: FxHashMap<&str, Vec<&str>> = FxHashMap::default();
    for r in rows {
        by.entry(r[0].as_str()).or_default().push(r[1].as_str());
    }
    by
}

pub fn settle_subcategories(entries: &mut [Entry], candidates: &[Candidate]) {
    let mut count: FxHashMap<(Tier, Option<Category>, &str), usize> = FxHashMap::default();
    for (e, (c, _)) in entries.iter().zip(candidates) {
        *count.entry((e.tier, e.category, c.as_str())).or_default() += 1;
    }
    let names: Vec<String> = entries
        .iter()
        .zip(candidates)
        .map(|(e, (c, product))| {
            if *product || count[&(e.tier, e.category, c.as_str())] >= category::MIN_COMPANY_ENTRIES
            {
                c.clone()
            } else {
                category::OTHER.to_string()
            }
        })
        .collect();
    for (e, n) in entries.iter_mut().zip(names) {
        e.subcategory = n;
    }
}

pub fn select(ctx: &Context, with_known: bool, unfiled: bool, zones_min: usize) -> Result<Picks> {
    let filter = if with_known {
        ""
    } else {
        "AND coalesce(name.known, '') = ''"
    };
    let rows = ctx.store.rows(&format!(
        "SELECT DISTINCT hit.host FROM hit LEFT JOIN name USING(host) WHERE hit.verdict = 'PICK' {filter} ORDER BY hit.host"
    ))?;
    let filed: FxHashSet<String> = if unfiled {
        ctx.store
            .all("SELECT DISTINCT host FROM issue WHERE kind = 'deny'")?
    } else {
        FxHashSet::default()
    };
    let gone: FxHashSet<String> = ctx
        .store
        .all("SELECT host FROM resolution WHERE rcode = 3")?;
    let hosts: Vec<&str> = rows
        .iter()
        .map(|r| r[0].as_str())
        .filter(|h| ctx.allowed(h).is_none() && !filed.contains(*h) && !gone.contains(*h))
        .collect();
    let product_rows = ctx
        .store
        .rows("SELECT host, product FROM hit WHERE verdict = 'PICK' ORDER BY host, product")?;
    let evidence_rows = ctx.store.rows(
        "SELECT host, product || ': ' || evidence FROM hit WHERE verdict = 'PICK' ORDER BY host, product",
    )?;
    let source_rows = ctx.store.rows(
        "SELECT DISTINCT origin.host, origin.source || CASE WHEN origin.detail = '' THEN '' ELSE ' ' || origin.detail END
         FROM origin JOIN hit ON hit.host = origin.host AND hit.verdict = 'PICK' ORDER BY 1, 2",
    )?;
    let resolution_rows = ctx.store.rows(
        "SELECT resolution.host, resolution.chain, resolution.addrs FROM resolution JOIN hit ON hit.host = resolution.host AND hit.verdict = 'PICK'",
    )?;
    let products = grouped(&product_rows);
    let evidence = grouped(&evidence_rows);
    let sources = grouped(&source_rows);
    let resolved: FxHashMap<&str, (&str, &str)> = resolution_rows
        .iter()
        .map(|r| (r[0].as_str(), (r[1].as_str(), r[2].as_str())))
        .collect();
    let list_of = |h: &str| -> Vec<String> {
        products
            .get(h)
            .into_iter()
            .flatten()
            .map(|p| (*p).to_string())
            .collect()
    };
    let titled: FxHashSet<String> = ctx.store.all(
        "SELECT DISTINCT host FROM probe WHERE path = '/' AND status = 200 AND lower(head) LIKE '%<title%'",
    )?;
    let probed_root: FxHashSet<String> = ctx
        .store
        .all("SELECT DISTINCT host FROM probe WHERE path = '/'")?;
    let keep_whole = |z: &str| {
        let www = format!("www.{z}");
        (probed_root.contains(z) || probed_root.contains(&www))
            && !titled.contains(z)
            && !titled.contains(&www)
    };
    let host_entry = |h: &str| -> Scored {
        let prods = list_of(h);
        let srcs: Vec<String> = sources
            .get(h)
            .into_iter()
            .flatten()
            .map(|s| (*s).to_string())
            .collect();
        let (chain, addrs) = resolved.get(h).copied().unwrap_or(("", ""));
        let own = ctx.regdom(h);
        let vendor = chain
            .rsplit('>')
            .next()
            .filter(|t| !t.is_empty())
            .map(|t| ctx.regdom(t))
            .filter(|v| *v != own);
        let class = Category::classify(
            prods.iter().map(String::as_str),
            srcs.iter().map(|s| s.split(' ').next().unwrap_or("")),
        );
        let own_products = prods
            .iter()
            .map(String::as_str)
            .filter(|p| Category::of_product(p) == Some(class));
        let candidate = match category::product_subcategory(own_products) {
            Some(p) => (p.to_string(), true),
            None => (category::company(vendor.as_deref().unwrap_or(&own)), false),
        };
        let mut entry = Entry {
            name: h.to_string(),
            category: Some(class),
            zone: false,
            members: Vec::new(),
            products: prods,
            evidence: evidence
                .get(h)
                .into_iter()
                .flatten()
                .map(|s| (*s).to_string())
                .collect(),
            sources: srcs,
            chain: chain.replace('>', " > "),
            addrs: addrs.to_string(),
            ..Entry::default()
        };
        entry.place(verified(&entry));
        (entry, candidate)
    };
    let all: Vec<Scored> = hosts.iter().map(|h| host_entry(h)).collect();
    let mut entries = Vec::new();
    let mut candidates = Vec::new();
    for c in Category::ALL {
        let mine: Vec<&Scored> = all.iter().filter(|(e, _)| e.category == Some(c)).collect();
        let names: Vec<&str> = mine
            .iter()
            .filter(|(_, (_, first_party))| !first_party)
            .map(|(e, _)| e.name.as_str())
            .collect();
        let zones = promoted(&names, |h| ctx.regdom(h), zones_min, |z| !keep_whole(z));
        let in_zone: FxHashMap<&str, &str> = zones
            .iter()
            .flat_map(|(z, hs)| hs.iter().map(move |h| (*h, z.as_str())))
            .collect();
        let mut zone_parts: FxHashMap<&str, Vec<&Scored>> = FxHashMap::default();
        for m in mine.iter().copied() {
            if let Some(z) = in_zone.get(m.0.name.as_str()) {
                zone_parts.entry(z).or_default().push(m);
            } else {
                entries.push(m.0.clone());
                candidates.push(m.1.clone());
            }
        }
        for (zone, parts) in zone_parts {
            let mut votes: FxHashMap<&Candidate, usize> = FxHashMap::default();
            for p in &parts {
                *votes.entry(&p.1).or_default() += 1;
            }
            let candidate = votes
                .into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
                .map(|(c, _)| c.clone())
                .unwrap_or_else(|| (category::OTHER.to_string(), false));
            let mut members: Vec<String> = parts.iter().map(|p| p.0.name.clone()).collect();
            members.sort_unstable();
            let mut products: Vec<String> =
                parts.iter().flat_map(|p| p.0.products.clone()).collect();
            products.sort_unstable();
            products.dedup();
            let mut srcs: Vec<String> = parts.iter().flat_map(|p| p.0.sources.clone()).collect();
            srcs.sort_unstable();
            srcs.dedup();
            let mut whole = Entry {
                name: zone.to_string(),
                category: Some(c),
                zone: true,
                members,
                products,
                evidence: parts
                    .iter()
                    .flat_map(|p| p.0.evidence.iter().map(|e| format!("{} {e}", p.0.name)))
                    .collect(),
                sources: srcs,
                ..Entry::default()
            };
            whole.place(parts.iter().all(|p| verified(&p.0)));
            entries.push(whole);
            candidates.push(candidate);
        }
    }
    settle_subcategories(&mut entries, &candidates);
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by(|a, b| entries[*a].name.cmp(&entries[*b].name));
    let entries = order.into_iter().map(|i| entries[i].clone()).collect();
    Ok(Picks {
        entries,
        skipped: rows.len() - hosts.len(),
    })
}

pub fn run(ctx: &Context, args: &ExportArgs) -> Result<()> {
    let picks = select(ctx, !args.unknown_only, args.unfiled, args.zones)?;
    let chosen = picks.chosen(args.tier, args.category, args.subcategory.as_deref());
    let mut out = Out::new();
    for e in &chosen {
        out.row(&[&e.name]);
    }
    drop(out);
    if let Some(path) = &args.metadata {
        let mut text = METADATA_HEADER.to_string();
        for e in &chosen {
            text.push_str(&e.metadata("-"));
        }
        std::fs::write(path, text)?;
    }
    eprintln!("entries={} skipped={}", chosen.len(), picks.skipped);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tiers_and_categories() {
        assert_eq!(parse_tier("aggressive"), Ok(Tier::Aggressive));
        assert_eq!(parse_tier("standard"), Ok(Tier::Standard));
        assert!(parse_tier("pro").is_err());
        assert_eq!(
            parse_category("self-hosted-telemetry"),
            Ok(Category::SelfHostedTelemetry)
        );
        assert!(parse_category("malware").is_err());
    }

    #[test]
    fn promotes_zones_with_many_picks_and_no_titled_apex() {
        let regdom = |h: &str| h.split_once('.').map_or(h, |(_, r)| r).to_string();
        let hosts = [
            "a.uno-dns.com",
            "b.uno-dns.com",
            "c.uno-dns.com",
            "sgtm.shop.com",
            "x.shop.com",
            "y.shop.com",
            "one.io.net",
        ];
        let got = promoted(&hosts, regdom, 3, |z| z == "shop.com");
        assert_eq!(got.keys().collect::<Vec<_>>(), ["uno-dns.com"]);
        assert!(promoted(&hosts, regdom, 0, |_| false).is_empty());
    }

    #[test]
    fn keeps_products_and_big_companies_as_subcategories_per_tier() {
        let entry = |name: &str, tier: Tier| Entry {
            name: name.into(),
            category: Some(Category::Tracker),
            tier,
            ..Entry::default()
        };
        let mut entries = vec![
            entry("a.io", Tier::Standard),
            entry("b.io", Tier::Standard),
            entry("c.io", Tier::Standard),
            entry("d.io", Tier::Standard),
            entry("e.io", Tier::Standard),
            entry("f.io", Tier::Aggressive),
        ];
        let candidates = [
            ("umami".to_string(), true),
            ("pubmatic".to_string(), false),
            ("pubmatic".to_string(), false),
            ("pubmatic".to_string(), false),
            ("tiny".to_string(), false),
            ("pubmatic".to_string(), false),
        ];
        settle_subcategories(&mut entries, &candidates);
        let subs: Vec<&str> = entries.iter().map(|e| e.subcategory.as_str()).collect();
        assert_eq!(
            subs,
            [
                "umami", "pubmatic", "pubmatic", "pubmatic", "other", "other"
            ]
        );
    }

    #[test]
    fn places_entries_by_breakage_and_category() {
        let mut e = Entry {
            name: "i.shop.com".into(),
            category: Some(Category::Tracker),
            evidence: vec![
                "sgtm: gtm.js; no visible change on https://shop.com/ when blocked".into(),
            ],
            ..Entry::default()
        };
        e.place(verified(&e));
        assert_eq!(
            (e.tier, e.list().as_str()),
            (Tier::Standard, "standard/tracker")
        );
        e.evidence.clear();
        e.place(verified(&e));
        assert_eq!(e.list(), "aggressive/tracker");
        let mut umami = Entry {
            category: Some(Category::SelfHostedTelemetry),
            evidence: vec!["umami: script; no visible change on https://a.io/ when blocked".into()],
            ..Entry::default()
        };
        umami.place(verified(&umami));
        assert_eq!(umami.tier, Tier::Aggressive);
        assert!(umami.tier_reason.contains("self-hosted"));
    }

    #[test]
    fn explains_why_an_entry_is_listed() {
        let mut e = Entry {
            name: "i.shop.com".into(),
            category: Some(Category::Tracker),
            subcategory: "snowplow".into(),
            products: vec!["snowplow".into()],
            evidence: vec!["snowplow: /i gif, cookie sp".into()],
            sources: vec!["hagezi-issue #12398 Snowplow collectors".into()],
            chain: "x.cdn.net".into(),
            addrs: "1.2.3.4".into(),
            ..Entry::default()
        };
        e.place(false);
        assert_eq!(
            e.reason(),
            "product snowplow | aggressive because the breakage test did not confirm that blocking it is safe | snowplow: /i gif, cookie sp | found by hagezi-issue #12398 Snowplow collectors | CNAME x.cdn.net | resolves to 1.2.3.4"
        );
        assert_eq!(
            e.metadata("2026-11-28T00:00:00Z"),
            "i.shop.com\tsnowplow\t2026-11-28T00:00:00Z\taggressive because the breakage test did not confirm that blocking it is safe\thost\tsnowplow\tsnowplow: /i gif, cookie sp\thagezi-issue #12398 Snowplow collectors\tx.cdn.net\t1.2.3.4\t\n"
        );
        let z = Entry {
            name: "uno-dns.com".into(),
            zone: true,
            members: vec!["a.uno-dns.com".into(), "b.uno-dns.com".into()],
            ..Entry::default()
        };
        assert!(
            z.reason()
                .starts_with("zone with 2 picks: a.uno-dns.com, b.uno-dns.com")
        );
        assert_eq!(z.list(), "-");
        let picks = Picks {
            entries: vec![e, z],
            skipped: 0,
        };
        assert_eq!(
            picks
                .chosen(Some(Tier::Aggressive), None, Some("snowplow"))
                .len(),
            1
        );
        assert!(picks.chosen(Some(Tier::Standard), None, None).is_empty());
    }
}
