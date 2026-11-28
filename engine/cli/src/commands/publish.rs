use crate::commands::export::{Entry, METADATA_HEADER, select};
use crate::context::Context;
use anyhow::{Context as _, Result};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use stella_core::list::{
    self, CHANGELOG_FILE, COUNTS_FILE, DOMAINS_FILE, Header, LISTS_DIR, METADATA_FILE,
    SUBCATEGORIES_DIR, Tier, render,
};

pub const CHANGELOG_HEADER: &str = "time\taction\tentry\tlist\tsubcategory\treason\n";
pub const COUNTS_HEADER: &str = "list\tsubcategory\tentries\n";
pub const ADDED: &str = "added";
pub const REMOVED: &str = "removed";
pub const MOVED: &str = "moved";
const WHOLE_LIST: &str = "-";

#[derive(clap::Args)]
pub struct PublishArgs {
    #[arg(
        long,
        default_value = LISTS_DIR,
        help = "Directory that gets the standard and aggressive tiers, one folder per list with domains.txt, metadata.tsv and subcategories, and changelog.tsv"
    )]
    dir: PathBuf,
    #[arg(
        long,
        default_value_t = 3,
        help = "Picks a zone needs before the whole zone is listed, 0 turns it off"
    )]
    zones: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placed {
    pub list: String,
    pub subcategory: String,
    pub added: String,
}

pub fn history(changelog: &str) -> BTreeMap<String, Placed> {
    let mut now: BTreeMap<String, Placed> = BTreeMap::new();
    for line in changelog.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let [time, action, entry, list, subcategory, ..] = f[..] else {
            continue;
        };
        match action {
            ADDED => {
                now.insert(
                    entry.to_string(),
                    Placed {
                        list: list.to_string(),
                        subcategory: subcategory.to_string(),
                        added: time.to_string(),
                    },
                );
            }
            MOVED => {
                if let Some(p) = now.get_mut(entry) {
                    p.list = list.to_string();
                    p.subcategory = subcategory.to_string();
                }
            }
            REMOVED => {
                now.remove(entry);
            }
            _ => {}
        }
    }
    now
}

pub struct Why<'a> {
    pub gone: &'a FxHashMap<String, String>,
    pub allowed: &'a dyn Fn(&str) -> Option<String>,
    pub verdict: &'a FxHashMap<String, String>,
    pub zone_of: &'a FxHashMap<String, String>,
}

pub fn removal_reason(entry: &str, why: &Why) -> String {
    if let Some(at) = why.gone.get(entry) {
        return format!("NXDOMAIN from Stella's resolver at {at}, the name no longer exists");
    }
    if let Some(r) = (why.allowed)(entry) {
        return format!("allowlisted: {r}");
    }
    if let Some(z) = why.zone_of.get(entry) {
        return format!("now covered by the zone entry {z}");
    }
    match why.verdict.get(entry) {
        Some(v) => format!("no longer a pick, the battery now says {v}"),
        None => "no longer a pick, no current hit".to_string(),
    }
}

pub fn changes(
    before: &BTreeMap<String, Placed>,
    entries: &[Entry],
    time: &str,
    why: &Why,
) -> String {
    let mut out = String::new();
    let mut seen: FxHashSet<&str> = FxHashSet::default();
    for e in entries {
        seen.insert(&e.name);
        let list = e.list();
        let reason = e.reason().replace(['\t', '\n'], " ");
        match before.get(&e.name) {
            None => {
                let _ = writeln!(
                    out,
                    "{time}\t{ADDED}\t{}\t{list}\t{}\t{reason}",
                    e.name, e.subcategory
                );
            }
            Some(p) if p.list != list || p.subcategory != e.subcategory => {
                let _ = writeln!(
                    out,
                    "{time}\t{MOVED}\t{}\t{list}\t{}\tfrom {}/{} | {reason}",
                    e.name, e.subcategory, p.list, p.subcategory
                );
            }
            Some(_) => {}
        }
    }
    for (name, p) in before {
        if !seen.contains(name.as_str()) {
            let _ = writeln!(
                out,
                "{time}\t{REMOVED}\t{name}\t{}\t{}\t{}",
                p.list,
                p.subcategory,
                removal_reason(name, why)
            );
        }
    }
    out
}

pub fn existing_subcategories(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir.join(SUBCATEGORIES_DIR))
        .map(|d| {
            d.filter_map(std::result::Result::ok)
                .filter_map(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .strip_suffix(".txt")
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    v
}

fn write_domains(
    path: &Path,
    title: &str,
    description: &str,
    entries: &[&Entry],
    modified: i64,
) -> Result<()> {
    let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    let header = Header {
        title,
        description,
        modified,
    };
    std::fs::write(path, render(&header, &names))
        .with_context(|| format!("write {}", path.display()))
}

fn write_metadata(
    path: &Path,
    entries: &[&Entry],
    added: &FxHashMap<String, String>,
) -> Result<()> {
    let mut meta = METADATA_HEADER.to_string();
    for e in entries {
        meta.push_str(&e.metadata(added.get(&e.name).map_or("-", String::as_str)));
    }
    std::fs::write(path, meta).with_context(|| format!("write {}", path.display()))
}

pub fn run(ctx: &Context, args: &PublishArgs) -> Result<()> {
    let picks = select(ctx, true, false, args.zones)?;
    let modified = stella_core::now();
    let time = stella_core::time::utc(modified);
    std::fs::create_dir_all(&args.dir)?;
    let log_path = args.dir.join(CHANGELOG_FILE);
    let old_log = std::fs::read_to_string(&log_path).unwrap_or_default();
    let before = history(&old_log);
    let gone: FxHashMap<String, String> = ctx
        .store
        .rows("SELECT host, at FROM resolution WHERE rcode = 3")?
        .into_iter()
        .map(|r| {
            let at = r[1]
                .parse::<i64>()
                .map_or(r[1].clone(), stella_core::time::utc);
            (r[0].clone(), at)
        })
        .collect();
    let verdict: FxHashMap<String, String> = ctx
        .store
        .rows("SELECT host, group_concat(verdict || ' ' || product, ', ') FROM hit GROUP BY host")?
        .into_iter()
        .map(|r| (r[0].clone(), r[1].clone()))
        .collect();
    let zone_of: FxHashMap<String, String> = picks
        .entries
        .iter()
        .filter(|e| e.zone)
        .flat_map(|e| e.members.iter().map(|m| (m.clone(), e.name.clone())))
        .collect();
    let allowed = |h: &str| ctx.allowed(h).map(str::to_string);
    let why = Why {
        gone: &gone,
        allowed: &allowed,
        verdict: &verdict,
        zone_of: &zone_of,
    };
    let events = changes(&before, &picks.entries, &time, &why);
    let mut log = if old_log.is_empty() {
        CHANGELOG_HEADER.to_string()
    } else {
        old_log
    };
    log.push_str(&events);
    std::fs::write(&log_path, &log)?;
    let added: FxHashMap<String, String> = history(&log)
        .into_iter()
        .map(|(k, p)| (k, p.added))
        .collect();
    let mut counts = COUNTS_HEADER.to_string();
    for tier in Tier::ALL {
        for &c in tier.categories() {
            let mine = picks.chosen(Some(tier), Some(c), None);
            let dir = list::folder(&args.dir, tier, c);
            std::fs::create_dir_all(dir.join(SUBCATEGORIES_DIR))
                .with_context(|| format!("create {}", dir.display()))?;
            write_domains(
                &dir.join(DOMAINS_FILE),
                &list::title(tier, c, None),
                &list::description(tier, c, None),
                &mine,
                modified,
            )?;
            write_metadata(&dir.join(METADATA_FILE), &mine, &added)?;
            let id = list::list_id(tier, c);
            let _ = writeln!(counts, "{id}\t{WHOLE_LIST}\t{}", mine.len());
            let mut subs: Vec<String> = mine.iter().map(|e| e.subcategory.clone()).collect();
            subs.extend(existing_subcategories(&dir));
            subs.sort_unstable();
            subs.dedup();
            for s in &subs {
                let part = picks.chosen(Some(tier), Some(c), Some(s));
                write_domains(
                    &list::subcategory_file(&args.dir, tier, c, s),
                    &list::title(tier, c, Some(s)),
                    &list::description(tier, c, Some(s)),
                    &part,
                    modified,
                )?;
                let _ = writeln!(counts, "{id}\t{s}\t{}", part.len());
            }
            eprintln!(
                "published {}: entries={} subcategories={}",
                dir.display(),
                mine.len(),
                subs.len()
            );
        }
    }
    std::fs::write(args.dir.join(COUNTS_FILE), counts)?;
    eprintln!(
        "changelog: {} event(s), skipped={}",
        events.lines().count(),
        picks.skipped
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stella_core::category::Category;

    fn entry(name: &str, subcategory: &str) -> Entry {
        Entry {
            name: name.into(),
            category: Some(Category::SelfHostedTelemetry),
            tier: Tier::Aggressive,
            subcategory: subcategory.into(),
            products: vec!["umami".into()],
            ..Entry::default()
        }
    }

    #[test]
    fn logs_adds_moves_and_removals_with_reasons() {
        let log = format!(
            "{CHANGELOG_HEADER}t0\tadded\ta.io\tself-hosted-telemetry\tumami\tx\nt0\tadded\tb.io\ttracker\tother\tx\nt0\tadded\tc.io\ttracker\tother\tx\nt0\tadded\td.io\ttracker\tother\tx\nt1\tremoved\td.io\ttracker\tother\tgone\n"
        );
        let before = history(&log);
        assert_eq!(before.keys().collect::<Vec<_>>(), ["a.io", "b.io", "c.io"]);
        assert_eq!(before["a.io"].added, "t0");
        let gone: FxHashMap<String, String> = [("b.io".to_string(), "t2".to_string())]
            .into_iter()
            .collect();
        let verdict: FxHashMap<String, String> = [("c.io".to_string(), "REVIEW umami".to_string())]
            .into_iter()
            .collect();
        let zone_of = FxHashMap::default();
        let allowed = |_: &str| None;
        let why = Why {
            gone: &gone,
            allowed: &allowed,
            verdict: &verdict,
            zone_of: &zone_of,
        };
        let entries = vec![entry("a.io", "matomo"), entry("e.io", "umami")];
        let got = changes(&before, &entries, "t3", &why);
        let lines: Vec<&str> = got.lines().collect();
        assert_eq!(lines.len(), 4, "{got}");
        assert!(lines[0].starts_with("t3\tmoved\ta.io\taggressive/self-hosted-telemetry\tmatomo\tfrom self-hosted-telemetry/umami | product umami"), "{got}");
        assert!(lines[1].starts_with(
            "t3\tadded\te.io\taggressive/self-hosted-telemetry\tumami\tproduct umami"
        ));
        assert!(
            lines[2]
                .contains("removed\tb.io\ttracker\tother\tNXDOMAIN from Stella's resolver at t2")
        );
        assert!(lines[3].contains(
            "removed\tc.io\ttracker\tother\tno longer a pick, the battery now says REVIEW umami"
        ));
        let after = history(&format!("{log}{got}"));
        assert_eq!(after["a.io"].subcategory, "matomo");
        assert_eq!(after["a.io"].list, "aggressive/self-hosted-telemetry");
        assert_eq!(after["a.io"].added, "t0");
        assert!(!after.contains_key("b.io"));
        let blocked = |_: &str| Some("false positive".to_string());
        let zones: FxHashMap<String, String> = [("z.io".to_string(), "io".to_string())]
            .into_iter()
            .collect();
        let why = Why {
            gone: &FxHashMap::default(),
            allowed: &blocked,
            verdict: &verdict,
            zone_of: &zones,
        };
        assert_eq!(removal_reason("q.io", &why), "allowlisted: false positive");
        let why = Why {
            gone: &FxHashMap::default(),
            allowed: &allowed,
            verdict: &FxHashMap::default(),
            zone_of: &zones,
        };
        assert_eq!(
            removal_reason("z.io", &why),
            "now covered by the zone entry io"
        );
        assert_eq!(
            removal_reason("y.io", &why),
            "no longer a pick, no current hit"
        );
    }

    #[test]
    fn finds_existing_subcategory_files() {
        let dir = std::env::temp_dir().join(format!("stella-subs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(SUBCATEGORIES_DIR)).expect("dir");
        for f in ["umami.txt", "matomo.txt", "notes.tsv"] {
            std::fs::write(dir.join(SUBCATEGORIES_DIR).join(f), "").expect("write");
        }
        assert_eq!(existing_subcategories(&dir), ["matomo", "umami"]);
        assert!(existing_subcategories(&dir.join("absent")).is_empty());
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
