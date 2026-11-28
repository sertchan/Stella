use crate::report::{Finding, Section, table};
use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const LISTS: [&str; 4] = ["ads", "tracker", "telemetry", "self-hosted-telemetry"];
pub const FORMATS: [&str; 6] = [
    "domains.txt",
    "wildcard.txt",
    "hosts.txt",
    "adblock.txt",
    "rpz.txt",
    "dnsmasq.txt",
];
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
pub const METADATA: &str = "metadata.tsv";
pub const METADATA_HEADER: &str =
    "entry\tlist\tsublist\tadded\tkind\tproducts\tevidence\tsources\tchain\taddresses\tmembers";
pub const CHANGELOG: &str = "changelog.tsv";
pub const CHANGELOG_HEADER: &str = "time\taction\tentry\tlist\tsublist\treason";
const ACTIONS: [&str; 3] = ["added", "moved", "removed"];
const MAX_NAME: usize = 253;
const MAX_LABEL: usize = 63;

const WHY_MISSING: &str = "Every list and sublist ships in every format, so that each blocker can use the same list. HaGeZi and other consumers fetch these paths directly.";
const WHY_HEADER: &str = "The header tells a consumer what the list is, where it comes from and how fresh it is. It follows the HaGeZi header, which blockers and list managers already read.";
const WHY_COUNT: &str = "The entry count in the header must match the rules below it. A wrong count hides a truncated or broken file.";
const WHY_RULE: &str = "A blocker drops or misreads a rule that breaks the syntax of its format, and one bad line can disable a whole list in some tools.";
const WHY_DUPLICATE: &str = "A rule appears once. Duplicates waste memory in every blocker and hide mistakes in the generator.";
const WHY_SAME: &str = "Every format of one list must block the same names. A format that differs gives users of one blocker other results than users of another.";
const WHY_SUBLIST: &str = "Every entry of a list sits in exactly one sublist, and the sublists together hold the whole list. Otherwise a user of a sublist misses names or gets names from another product.";
const WHY_LOG: &str = "lists/changelog.tsv records when and why every entry was added, moved or removed. An entry without a matching log line has no recorded reason.";
const FIX_PUBLISH: &str = "Run stella publish with the release build from nix run .#stella and commit the lists folder as it comes out. Never edit a list by hand.";

pub fn comment(format: &str) -> &'static str {
    match format {
        "adblock.txt" => "!",
        "rpz.txt" => ";",
        _ => "#",
    }
}

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

pub fn valid_sublist(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn rule_name(format: &str, rule: &str) -> Option<String> {
    let name = match format {
        "domains.txt" => rule,
        "wildcard.txt" => rule.strip_prefix("*.")?,
        "hosts.txt" => rule.strip_prefix("0.0.0.0 ")?,
        "adblock.txt" => rule.strip_prefix("||")?.strip_suffix('^')?,
        "rpz.txt" => {
            let n = rule.strip_suffix(" CNAME .")?;
            n.strip_prefix("*.").unwrap_or(n)
        }
        "dnsmasq.txt" => rule.strip_prefix("local=/")?.strip_suffix('/')?,
        _ => return None,
    };
    valid_name(name).then(|| name.to_string())
}

fn preamble(format: &str, n: usize, line: &str) -> bool {
    match format {
        "adblock.txt" => n == 0 && line == "[Adblock Plus]",
        "rpz.txt" => {
            line.starts_with("$TTL ") || line.starts_with("@ SOA ") || line == "  NS  localhost."
        }
        _ => false,
    }
}

pub struct Parsed {
    pub entries: Option<usize>,
    pub names: BTreeSet<String>,
    pub rules: usize,
}

pub fn check_file(place: &str, format: &str, text: &str, out: &mut Vec<Finding>) -> Parsed {
    let c = comment(format);
    let mut keys = Vec::new();
    let mut entries = None;
    let mut parsed = Parsed {
        entries: None,
        names: BTreeSet::new(),
        rules: 0,
    };
    let mut seen = BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        if preamble(format, n, line) || line == c {
            continue;
        }
        let at = format!("{place}:{}", n + 1);
        if let Some(rest) = line.strip_prefix(c).and_then(|r| r.strip_prefix(' ')) {
            if let Some((k, v)) = rest.split_once(": ") {
                keys.push(k.to_string());
                if k == "Number of entries" {
                    entries = v.parse::<usize>().ok();
                }
            }
            continue;
        }
        parsed.rules += 1;
        match rule_name(format, line) {
            Some(name) => {
                parsed.names.insert(name);
            }
            None => out.push(
                Finding::new("list-rule", at.clone(), WHY_RULE)
                    .found(line.to_string())
                    .expected(format!(
                        "a rule in {format} syntax with a valid lowercase domain"
                    ))
                    .fix(FIX_PUBLISH),
            ),
        }
        if !seen.insert(line.to_string()) {
            out.push(
                Finding::new("list-duplicate", at, WHY_DUPLICATE)
                    .found(line.to_string())
                    .expected("each rule once")
                    .fix(FIX_PUBLISH),
            );
        }
    }
    if keys != HEADER {
        out.push(
            Finding::new("list-header", place.to_string(), WHY_HEADER)
                .found(keys.join(", "))
                .expected(format!("{c} Key: value lines for {}", HEADER.join(", ")))
                .fix(FIX_PUBLISH),
        );
    }
    if entries.is_some_and(|e| e != parsed.rules) {
        out.push(
            Finding::new("list-count", place.to_string(), WHY_COUNT)
                .found(format!("Number of entries: {}", entries.unwrap_or(0)))
                .expected(format!("{} rule lines", parsed.rules))
                .fix(FIX_PUBLISH),
        );
    }
    parsed.entries = entries;
    parsed
}

pub struct Folder {
    pub names: BTreeSet<String>,
    pub rows: Vec<[String; 4]>,
}

pub fn check_folder(root: &Path, rel: &str, out: &mut Vec<Finding>) -> Folder {
    let mut folder = Folder {
        names: BTreeSet::new(),
        rows: Vec::new(),
    };
    let mut first: Option<String> = None;
    for format in FORMATS {
        let file = format!("{rel}/{format}");
        let Ok(text) = std::fs::read_to_string(root.join(rel).join(format)) else {
            out.push(
                Finding::new("list-missing", format!("lists/{file}"), WHY_MISSING)
                    .found("no file")
                    .expected(format!("{format} in lists/{rel}"))
                    .fix(FIX_PUBLISH),
            );
            folder.rows.push([
                rel.to_string(),
                format.to_string(),
                "-".into(),
                "missing".into(),
            ]);
            continue;
        };
        let before = out.len();
        let parsed = check_file(&format!("lists/{file}"), format, &text, out);
        match &first {
            None => {
                first = Some(file.clone());
                folder.names.clone_from(&parsed.names);
            }
            Some(f) if folder.names != parsed.names => out.push(
                Finding::new("list-mismatch", format!("lists/{file}"), WHY_SAME)
                    .found(format!("{} names", parsed.names.len()))
                    .expected(format!("the {} names of lists/{f}", folder.names.len()))
                    .fix(FIX_PUBLISH),
            ),
            Some(_) => {}
        }
        let result = if out.len() == before {
            "ok".to_string()
        } else {
            format!("{} problem(s)", out.len() - before)
        };
        folder.rows.push([
            rel.to_string(),
            format.to_string(),
            parsed.rules.to_string(),
            result,
        ]);
    }
    let meta = std::fs::read_to_string(root.join(rel).join(METADATA)).unwrap_or_default();
    if meta.lines().next() != Some(METADATA_HEADER) {
        out.push(
            Finding::new("list-metadata", format!("lists/{rel}/{METADATA}"), WHY_LOG)
                .found(meta.lines().next().unwrap_or("no file").to_string())
                .expected(METADATA_HEADER.replace('\t', " "))
                .fix(FIX_PUBLISH),
        );
    }
    folder
}

pub fn history(changelog: &str) -> BTreeMap<String, (String, String)> {
    let mut now = BTreeMap::new();
    for line in changelog.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let [_, action, entry, list, sublist, ..] = f[..] else {
            continue;
        };
        match action {
            "added" | "moved" => {
                now.insert(entry.to_string(), (list.to_string(), sublist.to_string()));
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
        if f.len() != 6 || !ACTIONS.contains(&f[1]) || f[5].is_empty() {
            out.push(
                Finding::new("list-changelog", format!("{place}:{}", n + 1), WHY_LOG)
                    .found(line.to_string())
                    .expected("time, added, moved or removed, entry, list, sublist and a reason, tab separated")
                    .fix(FIX_PUBLISH),
            );
        }
    }
}

fn sublists(dir: &Path) -> Vec<String> {
    let mut subs: Vec<String> = std::fs::read_dir(dir)
        .map(|d| {
            d.filter_map(std::result::Result::ok)
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    subs.sort_unstable();
    subs
}

pub fn check_dir(root: &Path) -> Result<(Vec<Section>, Vec<Finding>)> {
    if !root.is_dir() {
        bail!(
            "{} is not a directory, run stella publish first",
            root.display()
        );
    }
    let mut findings = Vec::new();
    let mut rows = Vec::new();
    let log = std::fs::read_to_string(root.join(CHANGELOG)).unwrap_or_default();
    check_changelog(&log, &mut findings);
    let placed = history(&log);
    let mut subs_total = 0usize;
    for list in LISTS {
        let parent = check_folder(root, list, &mut findings);
        rows.extend(parent.rows);
        let subs = sublists(&root.join(list));
        subs_total += subs.len();
        let mut owner: BTreeMap<String, String> = BTreeMap::new();
        for sub in &subs {
            let rel = format!("{list}/{sub}");
            if !valid_sublist(sub) {
                findings.push(
                    Finding::new("list-sublist", format!("lists/{rel}"), WHY_SUBLIST)
                        .found(sub.clone())
                        .expected("a lowercase name of letters, digits and hyphens")
                        .fix(FIX_PUBLISH),
                );
            }
            let folder = check_folder(root, &rel, &mut findings);
            rows.extend(folder.rows);
            for name in folder.names {
                if let Some(other) = owner.insert(name.clone(), sub.clone()) {
                    findings.push(
                        Finding::new("list-sublist", format!("lists/{rel} {name}"), WHY_SUBLIST)
                            .found(format!("also in lists/{list}/{other}"))
                            .expected("each entry in exactly one sublist")
                            .fix(FIX_PUBLISH),
                    );
                }
            }
        }
        for name in parent.names.iter().filter(|n| !owner.contains_key(*n)) {
            findings.push(
                Finding::new("list-sublist", format!("lists/{list} {name}"), WHY_SUBLIST)
                    .found("in the list but in no sublist")
                    .expected("each entry in exactly one sublist")
                    .fix(FIX_PUBLISH),
            );
        }
        for (name, sub) in &owner {
            if !parent.names.contains(name) {
                findings.push(
                    Finding::new(
                        "list-sublist",
                        format!("lists/{list}/{sub} {name}"),
                        WHY_SUBLIST,
                    )
                    .found(format!("in the sublist but not in lists/{list}"))
                    .expected("every sublist entry also in its list")
                    .fix(FIX_PUBLISH),
                );
            }
            if placed.get(name) != Some(&(list.to_string(), sub.clone())) {
                findings.push(
                    Finding::new("list-log", format!("lists/{list}/{sub} {name}"), WHY_LOG)
                        .found(
                            placed
                                .get(name)
                                .map_or("no log line".to_string(), |(l, s)| {
                                    format!("logged in {l}/{s}")
                                }),
                        )
                        .expected(format!("an added or moved line for {list}/{sub}"))
                        .fix(FIX_PUBLISH),
                );
            }
        }
    }
    let mut lines = vec![format!(
        "{} lists and {subs_total} sublists in {} formats, {} live entries in the changelog history",
        LISTS.len(),
        FORMATS.len(),
        placed.len()
    )];
    lines.extend(table(["folder", "format", "rules", "result"], &rows));
    Ok((vec![Section::new("files", lines)], findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(c: &str, count: usize) -> String {
        let mut s: String = HEADER
            .iter()
            .map(|k| {
                let v = if *k == "Number of entries" {
                    count.to_string()
                } else {
                    "x".to_string()
                };
                format!("{c} {k}: {v}\n")
            })
            .collect();
        s.push_str(c);
        s.push('\n');
        s
    }

    #[test]
    fn accepts_valid_names_and_rules() {
        assert!(valid_name("a-b.example.co"));
        assert!(valid_name("_dmarc.x.io"));
        assert!(!valid_name("localhost"));
        assert!(!valid_name("A.io"));
        assert!(!valid_name("-a.io"));
        assert!(!valid_name("a..io"));
        assert!(valid_sublist("server-side-gtm") && !valid_sublist("Umami"));
        for (format, rule) in [
            ("domains.txt", "a.io"),
            ("wildcard.txt", "*.a.io"),
            ("hosts.txt", "0.0.0.0 a.io"),
            ("adblock.txt", "||a.io^"),
            ("rpz.txt", "*.a.io CNAME ."),
            ("dnsmasq.txt", "local=/a.io/"),
        ] {
            assert_eq!(rule_name(format, rule), Some("a.io".into()), "{format}");
        }
        assert_eq!(rule_name("hosts.txt", "127.0.0.1 a.io"), None);
        assert_eq!(rule_name("csv", "a.io"), None);
    }

    #[test]
    fn checks_one_file() {
        let mut out = Vec::new();
        let text = format!("{}a.io\nz.io\n", header("#", 2));
        let p = check_file("d", "domains.txt", &text, &mut out);
        assert!(out.is_empty(), "{}", out.len());
        assert_eq!((p.rules, p.entries, p.names.len()), (2, Some(2), 2));
        let broken = text.replace("z.io\n", "z.io\nz.io\nBAD\n");
        check_file("d", "domains.txt", &broken, &mut out);
        let rules: Vec<&str> = out.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["list-duplicate", "list-rule", "list-count"]);
        out.clear();
        check_file("d", "domains.txt", "a.io\n", &mut out);
        assert_eq!(out[0].rule, "list-header");
        out.clear();
        let rpz = format!(
            "$TTL 3600\n@ SOA localhost. root.localhost. 1 28800 3600 259200 3600\n  NS  localhost.\n;\n{}a.io CNAME .\n*.a.io CNAME .\n",
            header(";", 2)
        );
        assert_eq!(check_file("r", "rpz.txt", &rpz, &mut out).names.len(), 1);
        let adblock = format!("[Adblock Plus]\n{}||a.io^\n", header("!", 1));
        assert_eq!(check_file("a", "adblock.txt", &adblock, &mut out).rules, 1);
        assert!(out.is_empty(), "{}", out.len());
    }

    #[test]
    fn checks_the_changelog() {
        let mut out = Vec::new();
        let log = format!(
            "{CHANGELOG_HEADER}\nt\tadded\ta.io\ttracker\tother\twhy\nt\tremoved\tb.io\ttracker\tother\tgone\n"
        );
        check_changelog(&log, &mut out);
        assert!(out.is_empty(), "{}", out.len());
        check_changelog("bad\nt\tdeleted\ta.io\n", &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(
            history(&log).get("a.io"),
            Some(&("tracker".to_string(), "other".to_string()))
        );
        assert!(!history(&log).contains_key("b.io"));
    }
}
