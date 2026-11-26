use crate::ctx::{Ctx, Out};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};

#[derive(clap::Args)]
pub struct ReviewArgs {
    #[arg(
        long,
        default_value = "PICK,REVIEW",
        help = "Verdicts to list, comma separated"
    )]
    verdict: String,
}

#[derive(clap::Args)]
pub struct ExportArgs {
    #[arg(long, help = "Also export hosts that a reference list already covers")]
    with_known: bool,
    #[arg(long, help = "Skip hosts already named in a HaGeZi deny issue")]
    unfiled: bool,
    #[arg(long, value_enum, default_value_t = Format::Domains, help = "Output format")]
    format: Format,
    #[arg(
        long,
        default_value_t = 0,
        help = "Export the whole zone instead of its hosts when it has this many picks and no titled site at its apex, 0 turns it off"
    )]
    zones: usize,
    #[arg(
        long,
        help = "Write host, product, verdict, evidence and sources as TSV to this file"
    )]
    metadata: Option<std::path::PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Format {
    Domains,
    Hosts,
    Adblock,
    Rpz,
}

pub fn line(format: Format, name: &str, zone: bool) -> Vec<String> {
    match (format, zone) {
        (Format::Domains, false) => vec![name.to_string()],
        (Format::Domains, true) => vec![format!("*.{name}"), name.to_string()],
        (Format::Hosts, _) => vec![format!("0.0.0.0 {name}")],
        (Format::Adblock, _) => vec![format!("||{name}^")],
        (Format::Rpz, false) => vec![format!("{name} CNAME .")],
        (Format::Rpz, true) => vec![format!("{name} CNAME ."), format!("*.{name} CNAME .")],
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

fn verdicts(v: &str) -> String {
    v.split(',')
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| s.chars().all(|c| c.is_ascii_uppercase()))
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn review(ctx: &Ctx, args: ReviewArgs) -> Result<()> {
    let rows = ctx.store.rows(&format!(
        "SELECT hit.host, hit.product, hit.verdict, hit.evidence, coalesce(name.known, ''),
                coalesce((SELECT group_concat(source || ':' || detail, ' ') FROM (SELECT source, detail FROM origin WHERE origin.host = hit.host LIMIT 3)), '')
         FROM hit LEFT JOIN name USING(host) WHERE hit.verdict IN ({}) ORDER BY hit.verdict, hit.product, hit.host",
        verdicts(&args.verdict)
    ))?;
    let mut out = Out::new();
    for r in &rows {
        out.row(&r.iter().map(String::as_str).collect::<Vec<_>>());
    }
    eprintln!("rows={}", rows.len());
    Ok(())
}

pub fn export(ctx: &Ctx, args: ExportArgs) -> Result<()> {
    let filter = if args.with_known {
        ""
    } else {
        "AND coalesce(name.known, '') = ''"
    };
    let rows = ctx.store.rows(&format!(
        "SELECT DISTINCT hit.host FROM hit LEFT JOIN name USING(host) WHERE hit.verdict = 'PICK' {filter} ORDER BY hit.host"
    ))?;
    let filed: FxHashSet<String> = if args.unfiled {
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
    let titled: FxHashSet<String> = ctx.store.all(
        "SELECT DISTINCT host FROM probe WHERE path = '/' AND status = 200 AND lower(head) LIKE '%<title%'",
    )?;
    let zones = promoted(
        &hosts,
        |h| ctx.regdom(h),
        args.zones,
        |z| titled.contains(z) || titled.contains(&format!("www.{z}")),
    );
    let in_zone: FxHashSet<&str> = zones.values().flatten().copied().collect();
    let mut out = Out::new();
    let mut zone_names: Vec<&String> = zones.keys().collect();
    zone_names.sort_unstable();
    for z in &zone_names {
        for l in line(args.format, z, true) {
            out.row(&[&l]);
        }
    }
    for h in hosts.iter().filter(|h| !in_zone.contains(**h)) {
        for l in line(args.format, h, false) {
            out.row(&[&l]);
        }
    }
    drop(out);
    if let Some(path) = &args.metadata {
        let meta = ctx.store.rows(
            "SELECT hit.host, hit.product, hit.verdict, hit.evidence,
                    coalesce((SELECT group_concat(DISTINCT source) FROM origin WHERE origin.host = hit.host), '')
             FROM hit WHERE hit.verdict = 'PICK' ORDER BY hit.host, hit.product",
        )?;
        let keep: FxHashSet<&str> = hosts.iter().copied().collect();
        let mut text = String::from("host\tproduct\tverdict\tevidence\tsources\n");
        for r in meta.iter().filter(|r| keep.contains(r[0].as_str())) {
            text.push_str(&r.join("\t"));
            text.push('\n');
        }
        std::fs::write(path, text)?;
    }
    eprintln!(
        "hosts={} zones={} skipped={}",
        hosts.len() - in_zone.len(),
        zone_names.len(),
        rows.len() - hosts.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_each_format() {
        assert_eq!(line(Format::Domains, "a.io", false), ["a.io"]);
        assert_eq!(line(Format::Domains, "z.io", true), ["*.z.io", "z.io"]);
        assert_eq!(line(Format::Hosts, "a.io", false), ["0.0.0.0 a.io"]);
        assert_eq!(line(Format::Adblock, "z.io", true), ["||z.io^"]);
        assert_eq!(
            line(Format::Rpz, "z.io", true),
            ["z.io CNAME .", "*.z.io CNAME ."]
        );
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
