use crate::report::{Finding, Section, table};
use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const TIERS: [(&str, &[&str]); 2] = [
    ("standard", &["ads", "tracker", "telemetry"]),
    (
        "aggressive",
        &["ads", "tracker", "telemetry", "self-hosted-telemetry"],
    ),
];
pub const CATEGORIES: [&str; 4] = ["ads", "tracker", "telemetry", "self-hosted-telemetry"];
pub const HEADER: [&str; 10] = [
    "Title",
    "Description",
    "Homepage",
    "License",
    "Issues",
    "Expires",
    "Last modified",
    "Version",
    "Syntax",
    "Number of entries",
];
pub const DOMAINS: &str = "domains.txt";
pub const METADATA: &str = "metadata.tsv";
pub const SUBCATEGORIES: &str = "subcategories";
pub const CHANGELOG: &str = "changelog.tsv";
pub const COUNTS: &str = "counts.tsv";
pub const METADATA_HEADER: &str =
    "entry\tsubcategory\tadded\ttier\tkind\tproducts\tevidence\tsources\tchain\taddresses\tmembers";
pub const CHANGELOG_HEADER: &str = "time\taction\tentry\tlist\tsubcategory\treason";
const ACTIONS: [&str; 3] = ["added", "moved", "removed"];
const MAX_NAME: usize = 253;
const MAX_LABEL: usize = 63;

const WHY_LAYOUT: &str = "HaGeZi and other consumers fetch lists/<tier>/<list>/domains.txt and the files under subcategories directly. A missing file breaks their build, and a stray file is a list that nobody maintains.";
const WHY_HEADER: &str = "The header tells a consumer what the list is, where it comes from and how fresh it is. It follows the HaGeZi header, which blockers and list managers already read.";
const WHY_COUNT: &str = "The entry count in the header must match the names below it. A wrong count hides a truncated or broken file.";
const WHY_NAME: &str = "A blocker drops or misreads a line that is not a valid lowercase domain, and one bad line can disable a whole list in some tools.";
const WHY_DUPLICATE: &str = "A name appears once in a file. Duplicates waste memory in every blocker and hide mistakes in the generator.";
const WHY_SUBCATEGORY: &str = "Every entry of a list sits in exactly one subcategory file, and the subcategories together hold the whole list. Otherwise a user of a subcategory misses names or gets names of another product.";
const WHY_OVERLAP: &str = "Each name sits in one list of one tier. Standard feeds every HaGeZi list and aggressive only Pro++ and Ultimate, so a name in both tiers makes the tier meaningless.";
const WHY_METADATA: &str = "metadata.tsv explains every entry of its list: subcategory, date, tier reason, product, evidence, sources and DNS. An entry without a metadata row has no recorded reason.";
const WHY_LOG: &str = "lists/changelog.tsv records when and why every entry was added, moved or removed. An entry without a matching log line has no recorded reason.";
const FIX_PUBLISH: &str = "Run stella publish with the release build from nix run .#stella and commit the lists folder as it comes out. Never edit a list by hand.";

pub fn valid_name(name: &str) -> bool {
    name.len() <= MAX_NAME
        && name.contains('.')
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= MAX_LABEL
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

pub fn valid_subcategory(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn valid_list(id: &str) -> bool {
    TIERS.iter().any(|(tier, categories)| {
        id.split_once('/')
            .is_some_and(|(t, c)| t == *tier && categories.contains(&c))
    })
}

pub fn legacy_list(id: &str) -> bool {
    CATEGORIES.contains(&id)
}

pub struct Parsed {
    pub names: BTreeSet<String>,
    pub problems: usize,
}

pub fn check_file(place: &str, text: &str, out: &mut Vec<Finding>) -> Parsed {
    let before = out.len();
    let mut keys = Vec::new();
    let mut count = None;
    let mut lines = 0usize;
    let mut names = BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        if line == "#" {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            if let Some((k, v)) = rest.split_once(": ") {
                keys.push(k.to_string());
                if k == "Number of entries" {
                    count = v.parse::<usize>().ok();
                }
            }
            continue;
        }
        lines += 1;
        let at = format!("{place}:{}", n + 1);
        if !valid_name(line) {
            out.push(
                Finding::new("list-name", at.clone(), WHY_NAME)
                    .found(line.to_string())
                    .expected("a valid lowercase domain")
                    .fix(FIX_PUBLISH),
            );
        }
        if !names.insert(line.to_string()) {
            out.push(
                Finding::new("list-duplicate", at, WHY_DUPLICATE)
                    .found(line.to_string())
                    .expected("each name once")
                    .fix(FIX_PUBLISH),
            );
        }
    }
    if keys != HEADER {
        out.push(
            Finding::new("list-header", place.to_string(), WHY_HEADER)
                .found(keys.join(", "))
                .expected(format!("# Key: value lines for {}", HEADER.join(", ")))
                .fix(FIX_PUBLISH),
        );
    }
    if count.is_some_and(|c| c != lines) {
        out.push(
            Finding::new("list-count", place.to_string(), WHY_COUNT)
                .found(format!("Number of entries: {}", count.unwrap_or(0)))
                .expected(format!("{lines} name lines"))
                .fix(FIX_PUBLISH),
        );
    }
    Parsed {
        names,
        problems: out.len() - before,
    }
}

pub fn history(changelog: &str) -> BTreeMap<String, (String, String)> {
    let mut now = BTreeMap::new();
    for line in changelog.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let [_, action, entry, list, subcategory, ..] = f[..] else {
            continue;
        };
        match action {
            "added" | "moved" => {
                now.insert(
                    entry.to_string(),
                    (list.to_string(), subcategory.to_string()),
                );
            }
            "removed" => {
                now.remove(entry);
            }
            _ => {}
        }
    }
    now
}

pub fn check_changelog(text: &str, out: &mut Vec<Finding>) {
    let place = format!("lists/{CHANGELOG}");
    if text.lines().next() != Some(CHANGELOG_HEADER) {
        out.push(
            Finding::new("list-changelog", place.clone(), WHY_LOG)
                .found(text.lines().next().unwrap_or("no file").to_string())
                .expected(CHANGELOG_HEADER.replace('\t', " "))
                .fix(FIX_PUBLISH),
        );
    }
    for (n, line) in text.lines().enumerate().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let well_formed = f.len() == 6
            && ACTIONS.contains(&f[1])
            && (valid_list(f[3]) || legacy_list(f[3]))
            && !f[5].is_empty();
        if !well_formed {
            out.push(
                Finding::new("list-changelog", format!("{place}:{}", n + 1), WHY_LOG)
                    .found(line.to_string())
                    .expected("time, added, moved or removed, entry, tier/list, subcategory and a reason, tab separated")
                    .fix(FIX_PUBLISH),
            );
        }
    }
}

fn children(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .map(|d| {
            d.filter_map(std::result::Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn stray(place: String, expected: String, out: &mut Vec<Finding>) {
    out.push(
        Finding::new("list-stray", place, WHY_LAYOUT)
            .found("a file or folder that publish does not write")
            .expected(expected)
            .fix(FIX_PUBLISH),
    );
}

fn missing(place: String, out: &mut Vec<Finding>) {
    out.push(
        Finding::new("list-missing", place, WHY_LAYOUT)
            .found("no such file or folder")
            .expected("the file that publish writes")
            .fix(FIX_PUBLISH),
    );
}

fn result(problems: usize) -> String {
    if problems == 0 {
        "ok".to_string()
    } else {
        format!("{problems} problem(s)")
    }
}

pub struct Report {
    pub rows: Vec<[String; 3]>,
    pub lists: usize,
    pub subcategories: usize,
    pub entries: usize,
}

fn check_list(
    root: &Path,
    id: &str,
    placed: &BTreeMap<String, (String, String)>,
    seen: &mut BTreeMap<String, String>,
    report: &mut Report,
    out: &mut Vec<Finding>,
) {
    let dir = root.join(id);
    let rel = format!("lists/{id}");
    for name in children(&dir) {
        if ![DOMAINS, METADATA, SUBCATEGORIES].contains(&name.as_str()) {
            stray(
                format!("{rel}/{name}"),
                format!("only {DOMAINS}, {METADATA} and {SUBCATEGORIES}/"),
                out,
            );
        }
    }
    let Ok(text) = std::fs::read_to_string(dir.join(DOMAINS)) else {
        missing(format!("{rel}/{DOMAINS}"), out);
        return;
    };
    let parent = check_file(&format!("{rel}/{DOMAINS}"), &text, out);
    report.lists += 1;
    report.entries += parent.names.len();
    report.rows.push([
        id.to_string(),
        parent.names.len().to_string(),
        result(parent.problems),
    ]);
    for name in &parent.names {
        if let Some(other) = seen.insert(name.clone(), id.to_string()) {
            out.push(
                Finding::new("list-overlap", format!("{rel} {name}"), WHY_OVERLAP)
                    .found(format!("also in lists/{other}"))
                    .expected("each name in one list of one tier")
                    .fix(FIX_PUBLISH),
            );
        }
    }
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    let subs_dir = dir.join(SUBCATEGORIES);
    for file in children(&subs_dir) {
        let place = format!("{rel}/{SUBCATEGORIES}/{file}");
        let Some(sub) = file.strip_suffix(".txt").filter(|s| valid_subcategory(s)) else {
            stray(
                place,
                "a lowercase subcategory name of letters, digits and hyphens with .txt".into(),
                out,
            );
            continue;
        };
        let text = std::fs::read_to_string(subs_dir.join(&file)).unwrap_or_default();
        let part = check_file(&place, &text, out);
        report.subcategories += 1;
        report.rows.push([
            format!("  {sub}"),
            part.names.len().to_string(),
            result(part.problems),
        ]);
        for name in part.names {
            if !parent.names.contains(&name) {
                out.push(
                    Finding::new(
                        "list-subcategory",
                        format!("{place} {name}"),
                        WHY_SUBCATEGORY,
                    )
                    .found(format!("not in {rel}/{DOMAINS}"))
                    .expected("every subcategory entry also in its list")
                    .fix(FIX_PUBLISH),
                );
            }
            if let Some(other) = owner.insert(name.clone(), sub.to_string()) {
                out.push(
                    Finding::new(
                        "list-subcategory",
                        format!("{place} {name}"),
                        WHY_SUBCATEGORY,
                    )
                    .found(format!("also in {other}.txt"))
                    .expected("each entry in exactly one subcategory")
                    .fix(FIX_PUBLISH),
                );
            }
        }
    }
    for name in parent.names.iter().filter(|n| !owner.contains_key(*n)) {
        out.push(
            Finding::new("list-subcategory", format!("{rel} {name}"), WHY_SUBCATEGORY)
                .found("in the list but in no subcategory")
                .expected("each entry in exactly one subcategory")
                .fix(FIX_PUBLISH),
        );
    }
    for (name, sub) in &owner {
        let want = (id.to_string(), sub.clone());
        if parent.names.contains(name) && placed.get(name) != Some(&want) {
            out.push(
                Finding::new("list-log", format!("{rel} {name}"), WHY_LOG)
                    .found(
                        placed
                            .get(name)
                            .map_or("no log line".to_string(), |(l, s)| {
                                format!("logged in {l} {s}")
                            }),
                    )
                    .expected(format!("an added or moved line for {id} {sub}"))
                    .fix(FIX_PUBLISH),
            );
        }
    }
    let meta = std::fs::read_to_string(dir.join(METADATA)).unwrap_or_default();
    let place = format!("{rel}/{METADATA}");
    if meta.lines().next() != Some(METADATA_HEADER) {
        out.push(
            Finding::new("list-metadata", place.clone(), WHY_METADATA)
                .found(meta.lines().next().unwrap_or("no file").to_string())
                .expected(METADATA_HEADER.replace('\t', " "))
                .fix(FIX_PUBLISH),
        );
    }
    let rows: BTreeMap<&str, &str> = meta
        .lines()
        .skip(1)
        .filter_map(|l| {
            let mut f = l.split('\t');
            Some((f.next()?, f.next()?))
        })
        .collect();
    for name in &parent.names {
        let want = owner.get(name).map(String::as_str);
        if rows.get(name.as_str()).copied() != want {
            out.push(
                Finding::new("list-metadata", format!("{place} {name}"), WHY_METADATA)
                    .found(rows.get(name.as_str()).map_or("no row".to_string(), |s| {
                        format!("a row with subcategory {s}")
                    }))
                    .expected(format!("a row with subcategory {}", want.unwrap_or("-")))
                    .fix(FIX_PUBLISH),
            );
        }
    }
    if rows.len() != parent.names.len() {
        out.push(
            Finding::new("list-metadata", place, WHY_METADATA)
                .found(format!("{} rows", rows.len()))
                .expected(format!("{} rows, one per entry", parent.names.len()))
                .fix(FIX_PUBLISH),
        );
    }
}

pub fn check_dir(root: &Path) -> Result<(Vec<Section>, Vec<Finding>)> {
    if !root.is_dir() {
        bail!(
            "{} is not a directory, run stella publish first",
            root.display()
        );
    }
    let mut findings = Vec::new();
    let log = std::fs::read_to_string(root.join(CHANGELOG)).unwrap_or_default();
    check_changelog(&log, &mut findings);
    let placed = history(&log);
    let tiers: Vec<&str> = TIERS.iter().map(|(t, _)| *t).collect();
    for name in children(root) {
        if !tiers.contains(&name.as_str()) && name != CHANGELOG && name != COUNTS {
            stray(
                format!("lists/{name}"),
                format!("only {}, {CHANGELOG} and {COUNTS}", tiers.join(", ")),
                &mut findings,
            );
        }
    }
    let mut report = Report {
        rows: Vec::new(),
        lists: 0,
        subcategories: 0,
        entries: 0,
    };
    let mut seen = BTreeMap::new();
    for (tier, categories) in TIERS {
        for name in children(&root.join(tier)) {
            if !categories.contains(&name.as_str()) {
                stray(
                    format!("lists/{tier}/{name}"),
                    format!("only {}", categories.join(", ")),
                    &mut findings,
                );
            }
        }
        for category in categories {
            let id = format!("{tier}/{category}");
            check_list(root, &id, &placed, &mut seen, &mut report, &mut findings);
        }
    }
    let mut lines = vec![
        format!(
            "{} tiers, {} lists, {} subcategories",
            TIERS.len(),
            report.lists,
            report.subcategories
        ),
        format!(
            "{} entries, {} live in the changelog history",
            report.entries,
            placed.len()
        ),
        String::new(),
    ];
    lines.extend(table(["list", "entries", "result"], &report.rows));
    Ok((vec![Section::new("files", lines)], findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains(names: &[&str]) -> String {
        let mut s: String = HEADER
            .iter()
            .map(|k| {
                let v = if *k == "Number of entries" {
                    names.len().to_string()
                } else {
                    "x".to_string()
                };
                format!("# {k}: {v}\n")
            })
            .collect();
        s.push_str("#\n");
        for n in names {
            s.push_str(n);
            s.push('\n');
        }
        s
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("dir");
        std::fs::write(p, text).expect("write");
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("stella-lint-{name}-{}", std::process::id()))
    }

    fn tree(name: &str) -> std::path::PathBuf {
        let root = scratch(name);
        let _ = std::fs::remove_dir_all(&root);
        let mut log = format!("{CHANGELOG_HEADER}\n");
        for (tier, categories) in TIERS {
            for c in categories {
                let id = format!("{tier}/{c}");
                let (names, sub): (Vec<&str>, &str) = match id.as_str() {
                    "standard/tracker" => (vec!["a.io", "b.io"], "segment"),
                    "aggressive/self-hosted-telemetry" => (vec!["u.io"], "umami"),
                    _ => (Vec::new(), "other"),
                };
                write(&root, &format!("{id}/{DOMAINS}"), &domains(&names));
                write(
                    &root,
                    &format!("{id}/{SUBCATEGORIES}/{sub}.txt"),
                    &domains(&names),
                );
                let mut meta = format!("{METADATA_HEADER}\n");
                for n in &names {
                    meta.push_str(&format!("{n}\t{sub}\tt\twhy\thost\tp\te\ts\t\t\t\n"));
                    log.push_str(&format!("t\tadded\t{n}\t{id}\t{sub}\twhy\n"));
                }
                write(&root, &format!("{id}/{METADATA}"), &meta);
            }
        }
        write(&root, CHANGELOG, &log);
        write(&root, COUNTS, "list\tsubcategory\tentries\n");
        root
    }

    fn rules(root: &Path) -> Vec<&'static str> {
        let (_, findings) = check_dir(root).expect("check");
        findings.iter().map(|f| f.rule).collect()
    }

    #[test]
    fn accepts_valid_names_and_ids() {
        assert!(valid_name("a-b.example.co"));
        assert!(valid_name("_dmarc.x.io"));
        assert!(!valid_name("localhost"));
        assert!(!valid_name("A.io"));
        assert!(!valid_name("-a.io"));
        assert!(!valid_name("a..io"));
        assert!(valid_subcategory("server-side-gtm") && !valid_subcategory("Umami"));
        assert!(valid_list("aggressive/self-hosted-telemetry"));
        assert!(!valid_list("standard/self-hosted-telemetry"));
        assert!(!valid_list("tracker") && legacy_list("tracker"));
    }

    #[test]
    fn checks_one_file() {
        let mut out = Vec::new();
        let p = check_file("d", &domains(&["a.io", "z.io"]), &mut out);
        assert!(out.is_empty(), "{}", out.len());
        assert_eq!((p.names.len(), p.problems), (2, 0));
        let broken = domains(&["a.io", "z.io"]).replace("z.io\n", "z.io\nz.io\nBAD\n");
        check_file("d", &broken, &mut out);
        let rules: Vec<&str> = out.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["list-duplicate", "list-name", "list-count"]);
        out.clear();
        check_file("d", "a.io\n", &mut out);
        assert_eq!(out[0].rule, "list-header");
    }

    #[test]
    fn accepts_a_published_tree() {
        let root = tree("ok");
        assert!(rules(&root).is_empty(), "{:?}", rules(&root));
        let (sections, _) = check_dir(&root).expect("check");
        assert_eq!(sections[0].lines[0], "2 tiers, 7 lists, 7 subcategories");
        assert_eq!(
            sections[0].lines[1],
            "3 entries, 3 live in the changelog history"
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rejects_stray_overlapping_and_unlogged_entries() {
        let root = tree("bad");
        write(&root, "tracker/adblock.txt", "");
        write(&root, "standard/self-hosted-telemetry/domains.txt", "");
        write(&root, "standard/tracker/wildcard.txt", "");
        write(&root, "standard/tracker/subcategories/Bad.txt", "");
        assert_eq!(
            rules(&root),
            ["list-stray", "list-stray", "list-stray", "list-stray"]
        );
        let root = tree("overlap");
        write(&root, "aggressive/tracker/domains.txt", &domains(&["a.io"]));
        let got = rules(&root);
        assert!(got.contains(&"list-overlap"), "{got:?}");
        assert!(got.contains(&"list-subcategory"), "{got:?}");
        assert!(got.contains(&"list-metadata"), "{got:?}");
        let root = tree("log");
        let log = std::fs::read_to_string(root.join(CHANGELOG)).expect("log");
        write(
            &root,
            CHANGELOG,
            &log.replace("\tsegment\twhy", "\tother\twhy"),
        );
        assert_eq!(rules(&root), ["list-log", "list-log"]);
        for name in ["bad", "overlap", "log"] {
            std::fs::remove_dir_all(scratch(name)).expect("cleanup");
        }
    }

    #[test]
    fn checks_the_changelog() {
        let mut out = Vec::new();
        let log = format!(
            "{CHANGELOG_HEADER}\nt\tadded\ta.io\ttracker\tother\twhy\nt\tmoved\ta.io\tstandard/tracker\tother\twhy\nt\tremoved\tb.io\ttracker\tother\tgone\n"
        );
        check_changelog(&log, &mut out);
        assert!(out.is_empty(), "{}", out.len());
        check_changelog("bad\nt\tdeleted\ta.io\n", &mut out);
        assert_eq!(out.len(), 2);
        out.clear();
        check_changelog(
            &format!(
                "{CHANGELOG_HEADER}\nt\tadded\ta.io\tstandard/self-hosted-telemetry\tumami\twhy\n"
            ),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(
            history(&log).get("a.io"),
            Some(&("standard/tracker".to_string(), "other".to_string()))
        );
        assert!(!history(&log).contains_key("b.io"));
    }
}
