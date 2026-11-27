use crate::commands::export::{Entry, METADATA_HEADER, select};
use crate::context::Context;
use anyhow::{Context as _, Result};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use stella_core::category::Category;
use stella_core::list::{Format, Header, render};

pub const LISTS_DIR: &str = "lists";
pub const COUNTS_FILE: &str = "counts.tsv";
pub const METADATA_FILE: &str = "metadata.tsv";
pub const CHANGELOG_FILE: &str = "changelog.tsv";
pub const CHANGELOG_HEADER: &str = "time\taction\tentry\tlist\tsublist\treason\n";
pub const ADDED: &str = "added";
pub const REMOVED: &str = "removed";
pub const MOVED: &str = "moved";

#[derive(clap::Args)]
pub struct PublishArgs {
    #[arg(
        long,
        default_value = LISTS_DIR,
        help = "Directory that gets one folder per list and per sublist with every format, metadata.tsv and changelog.tsv"
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
    pub sublist: String,
    pub added: String,
}

pub fn history(changelog: &str) -> BTreeMap<String, Placed> {
    let mut now: BTreeMap<String, Placed> = BTreeMap::new();
    for line in changelog.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let [time, action, entry, list, sublist, ..] = f[..] else {
            continue;
        };
        match action {
            ADDED => {
                now.insert(
                    entry.to_string(),
                    Placed {
                        list: list.to_string(),
                        sublist: sublist.to_string(),
                        added: time.to_string(),
                    },
                );
            }
            MOVED => {
                if let Some(p) = now.get_mut(entry) {
                    p.list = list.to_string();
                    p.sublist = sublist.to_string();
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
        match before.get(&e.name) {
            None => {
                let _ = writeln!(
                    out,
                    "{time}\t{ADDED}\t{}\t{}\t{}\t{}",
                    e.name,
                    e.list(),
                    e.sublist,
                    e.reason().replace(['\t', '\n'], " ")
                );
            }
            Some(p) if p.list != e.list() || p.sublist != e.sublist => {
                let _ = writeln!(
                    out,
                    "{time}\t{MOVED}\t{}\t{}\t{}\tfrom {}/{} | {}",
                    e.name,
                    e.list(),
                    e.sublist,
                    p.list,
                    p.sublist,
                    e.reason().replace(['\t', '\n'], " ")
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
                p.sublist,
                removal_reason(name, why)
            );
        }
    }
    out
}

fn write_list(
    dir: &Path,
    title: &str,
    description: &str,
    entries: &[&Entry],
    added: &FxHashMap<String, String>,
    modified: i64,
) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    let header = Header {
        title,
        description,
        modified,
    };
    for format in Format::ALL {
        std::fs::write(
            dir.join(format.file_name()),
            render(format, &header, &names),
        )?;
    }
    let mut meta = METADATA_HEADER.to_string();
    for e in entries {
        meta.push_str(&e.metadata(added.get(&e.name).map_or("-", String::as_str)));
    }
    std::fs::write(dir.join(METADATA_FILE), meta)?;
    Ok(())
}

fn existing_sublists(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|d| {
            d.filter_map(std::result::Result::ok)
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    v
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
    let after = history(&log);
    let added: FxHashMap<String, String> = after.into_iter().map(|(k, p)| (k, p.added)).collect();
    let mut counts = String::from("list\tsublist\tentries\n");
    for c in Category::ALL {
        let mine = picks.chosen(Some(c), None);
        let dir = args.dir.join(c.slug());
        write_list(&dir, c.title(), c.description(), &mine, &added, modified)?;
        let _ = writeln!(counts, "{}\t-\t{}", c.slug(), mine.len());
        let mut subs: Vec<String> = mine.iter().map(|e| e.sublist.clone()).collect();
        subs.extend(existing_sublists(&dir));
        subs.sort_unstable();
        subs.dedup();
        for s in &subs {
            let part = picks.chosen(Some(c), Some(s));
            write_list(
                &dir.join(s),
                &c.sublist_title(s),
                &c.sublist_description(s),
                &part,
                &added,
                modified,
            )?;
            let _ = writeln!(counts, "{}\t{s}\t{}", c.slug(), part.len());
        }
        eprintln!(
            "published {}: entries={} sublists={}",
            dir.display(),
            mine.len(),
            subs.len()
        );
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

    fn entry(name: &str, sublist: &str) -> Entry {
        Entry {
            name: name.into(),
            category: Some(Category::SelfHostedTelemetry),
            sublist: sublist.into(),
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
        assert!(lines[0].starts_with("t3\tmoved\ta.io\tself-hosted-telemetry\tmatomo\tfrom self-hosted-telemetry/umami | product umami"));
        assert!(
            lines[1].starts_with("t3\tadded\te.io\tself-hosted-telemetry\tumami\tproduct umami")
        );
        assert!(
            lines[2]
                .contains("removed\tb.io\ttracker\tother\tNXDOMAIN from Stella's resolver at t2")
        );
        assert!(lines[3].contains(
            "removed\tc.io\ttracker\tother\tno longer a pick, the battery now says REVIEW umami"
        ));
        let after = history(&format!("{log}{got}"));
        assert_eq!(after["a.io"].sublist, "matomo");
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
}
