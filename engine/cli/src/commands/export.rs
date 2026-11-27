use crate::context::{Context, Out};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use stella_core::category::Category;
use stella_core::list::{Entries, Format};

pub fn parse_format(s: &str) -> Result<Format, String> {
    Format::ALL
        .into_iter()
        .find(|f| f.file_name().strip_suffix(".txt") == Some(s))
        .ok_or_else(|| format!("{s} is not a format, use domains, hosts, adblock or rpz"))
}

pub fn parse_category(s: &str) -> Result<Category, String> {
    Category::from_slug(s).ok_or_else(|| {
        format!("{s} is not a category, use ads, tracker, telemetry or self-hosted-telemetry")
    })
}

#[derive(clap::Args)]
pub struct ExportArgs {
    #[arg(long, help = "Also export hosts that a reference list already covers")]
    with_known: bool,
    #[arg(long, help = "Skip hosts already named in a HaGeZi deny issue")]
    unfiled: bool,
    #[arg(long, default_value = "domains", value_parser = parse_format, help = "Output format: domains, hosts, adblock or rpz")]
    format: Format,
    #[arg(long, value_parser = parse_category, help = "Only this list: ads, tracker, telemetry or self-hosted-telemetry")]
    category: Option<Category>,
    #[arg(
        long,
        default_value_t = 0,
        help = "Export the whole zone instead of its hosts when it has this many picks and no titled site at its apex, 0 turns it off"
    )]
    zones: usize,
    #[arg(
        long,
        help = "Write host, category, product, verdict, evidence and sources as TSV to this file"
    )]
    metadata: Option<std::path::PathBuf>,
}

pub const METADATA_HEADER: &str = "host\tcategory\tproduct\tverdict\tevidence\tsources\n";

pub struct Selection {
    pub category: Category,
    pub zones: Vec<String>,
    pub hosts: Vec<String>,
    pub metadata: String,
}

impl Selection {
    pub fn entries(&self) -> Entries<'_> {
        Entries {
            zones: &self.zones,
            hosts: &self.hosts,
        }
    }
}

pub struct Picks {
    pub lists: Vec<Selection>,
    pub skipped: usize,
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

fn grouped(rows: &[Vec<String>]) -> FxHashMap<&str, Vec<&str>> {
    let mut by: FxHashMap<&str, Vec<&str>> = FxHashMap::default();
    for r in rows {
        by.entry(r[0].as_str()).or_default().push(r[1].as_str());
    }
    by
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
        .rows("SELECT host, product FROM hit WHERE verdict = 'PICK'")?;
    let source_rows = ctx.store.rows(
        "SELECT DISTINCT origin.host, origin.source FROM origin JOIN hit ON hit.host = origin.host AND hit.verdict = 'PICK'",
    )?;
    let products = grouped(&product_rows);
    let sources = grouped(&source_rows);
    let category_of = |h: &str| {
        Category::classify(
            products.get(h).into_iter().flatten().copied(),
            sources.get(h).into_iter().flatten().copied(),
        )
    };
    let titled: FxHashSet<String> = ctx.store.all(
        "SELECT DISTINCT host FROM probe WHERE path = '/' AND status = 200 AND lower(head) LIKE '%<title%'",
    )?;
    let meta = ctx.store.rows(
        "SELECT hit.host, hit.product, hit.verdict, hit.evidence,
                coalesce((SELECT group_concat(DISTINCT source) FROM origin WHERE origin.host = hit.host), '')
         FROM hit WHERE hit.verdict = 'PICK' ORDER BY hit.host, hit.product",
    )?;
    let mut lists = Vec::new();
    for category in Category::ALL {
        let mine: Vec<&str> = hosts
            .iter()
            .copied()
            .filter(|h| category_of(h) == category)
            .collect();
        let zones = promoted(
            &mine,
            |h| ctx.regdom(h),
            zones_min,
            |z| titled.contains(z) || titled.contains(&format!("www.{z}")),
        );
        let in_zone: FxHashSet<&str> = zones.values().flatten().copied().collect();
        let mut zone_names: Vec<String> = zones.keys().cloned().collect();
        zone_names.sort_unstable();
        let keep: FxHashSet<&str> = mine.iter().copied().collect();
        let mut metadata = String::new();
        for r in meta.iter().filter(|r| keep.contains(r[0].as_str())) {
            metadata.push_str(&format!(
                "{}\t{}\t{}\n",
                r[0],
                category.slug(),
                r[1..].join("\t")
            ));
        }
        lists.push(Selection {
            category,
            zones: zone_names,
            hosts: mine
                .iter()
                .filter(|h| !in_zone.contains(**h))
                .map(std::string::ToString::to_string)
                .collect(),
            metadata,
        });
    }
    Ok(Picks {
        lists,
        skipped: rows.len() - hosts.len(),
    })
}

pub fn run(ctx: &Context, args: &ExportArgs) -> Result<()> {
    let picks = select(ctx, args.with_known, args.unfiled, args.zones)?;
    let chosen: Vec<&Selection> = picks
        .lists
        .iter()
        .filter(|s| args.category.is_none_or(|c| c == s.category))
        .collect();
    let mut out = Out::new();
    for s in &chosen {
        for rule in s.entries().rules(args.format) {
            out.row(&[&rule]);
        }
    }
    drop(out);
    if let Some(path) = &args.metadata {
        let mut text = METADATA_HEADER.to_string();
        for s in &chosen {
            text.push_str(&s.metadata);
        }
        std::fs::write(path, text)?;
    }
    for s in &chosen {
        eprintln!(
            "category={} hosts={} zones={}",
            s.category.slug(),
            s.hosts.len(),
            s.zones.len()
        );
    }
    eprintln!("skipped={}", picks.skipped);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_formats_and_categories() {
        assert_eq!(parse_format("rpz"), Ok(Format::Rpz));
        assert!(parse_format("csv").is_err());
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
}
