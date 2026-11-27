use crate::report::{Finding, Section, table};
use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

pub const LISTS: [&str; 4] = ["ads", "tracker", "telemetry", "self-hosted-telemetry"];
pub const FORMATS: [&str; 4] = ["domains.txt", "hosts.txt", "adblock.txt", "rpz.txt"];
pub const HEADER: [&str; 8] = [
    "Title",
    "Description",
    "Homepage",
    "License",
    "Last modified",
    "Expires",
    "Number of entries",
    "Syntax",
];
const MAX_NAME: usize = 253;
const MAX_LABEL: usize = 63;

const WHY_MISSING: &str = "Every list ships in every format, so that each blocker can use the same list. HaGeZi and other consumers fetch these paths directly.";
const WHY_HEADER: &str = "The header tells a consumer what the list is, where it comes from and how fresh it is. Blockers and list managers read these fields.";
const WHY_COUNT: &str = "The entry count in the header must match the rules below it. A wrong count hides a truncated or broken file.";
const WHY_RULE: &str = "A blocker drops or misreads a rule that breaks the syntax of its format, and one bad line can disable a whole list in some tools.";
const WHY_DUPLICATE: &str = "A rule appears once. Duplicates waste memory in every blocker and hide mistakes in the generator.";
const WHY_SAME: &str = "Every format of one list must block the same names. A format that differs gives users of one blocker other results than users of another.";
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

pub fn rule_name(format: &str, rule: &str) -> Option<(String, bool)> {
    let (name, zone) = match format {
        "domains.txt" => match rule.strip_prefix("*.") {
            Some(n) => (n, true),
            None => (rule, false),
        },
        "hosts.txt" => (rule.strip_prefix("0.0.0.0 ")?, false),
        "adblock.txt" => (rule.strip_prefix("||")?.strip_suffix('^')?, false),
        "rpz.txt" => {
            let n = rule.strip_suffix(" CNAME .")?;
            match n.strip_prefix("*.") {
                Some(n) => (n, true),
                None => (n, false),
            }
        }
        _ => return None,
    };
    valid_name(name).then(|| (name.to_string(), zone))
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
        let at = format!("{place}:{}", n + 1);
        if n == 0 && line == "[Adblock Plus]" && format == "adblock.txt" {
            continue;
        }
        if let Some(rest) = line.strip_prefix(c).and_then(|r| r.strip_prefix(' ')) {
            if let Some((k, v)) = rest.split_once(": ") {
                keys.push(k.to_string());
                if k == "Number of entries" {
                    entries = v.parse::<usize>().ok();
                }
            }
            continue;
        }
        if format == "rpz.txt"
            && (line.starts_with("$TTL ")
                || line.starts_with("@ SOA ")
                || line == "  NS localhost.")
        {
            continue;
        }
        parsed.rules += 1;
        match rule_name(format, line) {
            Some((name, _)) => {
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

pub fn check_dir(root: &Path) -> Result<(Vec<Section>, Vec<Finding>)> {
    if !root.is_dir() {
        bail!(
            "{} is not a directory, run stella publish first",
            root.display()
        );
    }
    let mut findings = Vec::new();
    let mut rows = Vec::new();
    for list in LISTS {
        let mut names: Option<(String, BTreeSet<String>)> = None;
        for format in FORMATS {
            let rel = format!("lists/{list}/{format}");
            let path = root.join(list).join(format);
            let Ok(text) = std::fs::read_to_string(&path) else {
                findings.push(
                    Finding::new("list-missing", rel, WHY_MISSING)
                        .found("no file")
                        .expected(format!("{format} for the {list} list"))
                        .fix(FIX_PUBLISH),
                );
                rows.push([
                    list.to_string(),
                    format.to_string(),
                    "-".into(),
                    "missing".into(),
                ]);
                continue;
            };
            let before = findings.len();
            let parsed = check_file(&rel, format, &text, &mut findings);
            match &names {
                None => names = Some((rel.clone(), parsed.names.clone())),
                Some((first, set)) if *set != parsed.names => findings.push(
                    Finding::new("list-mismatch", rel.clone(), WHY_SAME)
                        .found(format!("{} names", parsed.names.len()))
                        .expected(format!("the {} names of {first}", set.len()))
                        .fix(FIX_PUBLISH),
                ),
                Some(_) => {}
            }
            let result = if findings.len() == before {
                "ok".to_string()
            } else {
                format!("{} problem(s)", findings.len() - before)
            };
            rows.push([
                list.to_string(),
                format.to_string(),
                parsed.rules.to_string(),
                result,
            ]);
        }
    }
    let mut lines = vec![format!(
        "{} lists in {} formats, header, entry count, rule syntax, duplicates and the same names in every format",
        LISTS.len(),
        FORMATS.len()
    )];
    lines.extend(table(["list", "format", "rules", "result"], &rows));
    Ok((vec![Section::new("files", lines)], findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAINS: &str = "# Title: Stella Ads\n# Description: x\n# Homepage: h\n# License: l\n# Last modified: t\n# Expires: 1 day\n# Number of entries: 3\n# Syntax: s\n*.z.io\nz.io\na.io\n";

    #[test]
    fn accepts_valid_names_and_rules() {
        assert!(valid_name("a-b.example.co"));
        assert!(valid_name("_dmarc.x.io"));
        assert!(!valid_name("localhost"));
        assert!(!valid_name("A.io"));
        assert!(!valid_name("-a.io"));
        assert!(!valid_name("a..io"));
        assert_eq!(
            rule_name("domains.txt", "*.z.io"),
            Some(("z.io".into(), true))
        );
        assert_eq!(
            rule_name("hosts.txt", "0.0.0.0 a.io"),
            Some(("a.io".into(), false))
        );
        assert_eq!(
            rule_name("adblock.txt", "||a.io^"),
            Some(("a.io".into(), false))
        );
        assert_eq!(
            rule_name("rpz.txt", "*.a.io CNAME ."),
            Some(("a.io".into(), true))
        );
        assert_eq!(rule_name("hosts.txt", "127.0.0.1 a.io"), None);
        assert_eq!(rule_name("csv", "a.io"), None);
    }

    #[test]
    fn checks_one_file() {
        let mut out = Vec::new();
        let p = check_file("d", "domains.txt", DOMAINS, &mut out);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!((p.rules, p.entries), (3, Some(3)));
        assert_eq!(p.names.len(), 2);
        let broken = DOMAINS.replace("a.io\n", "a.io\na.io\nBAD\n");
        check_file("d", "domains.txt", &broken, &mut out);
        let rules: Vec<&str> = out.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["list-duplicate", "list-rule", "list-count"]);
        out.clear();
        check_file("d", "domains.txt", "a.io\n", &mut out);
        assert_eq!(out[0].rule, "list-header");
        out.clear();
        let rpz = "; Title: t\n; Description: x\n; Homepage: h\n; License: l\n; Last modified: t\n; Expires: e\n; Number of entries: 1\n; Syntax: s\n$TTL 300\n@ SOA localhost. root.localhost. 1 43200 3600 86400 300\n  NS localhost.\na.io CNAME .\n";
        assert_eq!(check_file("r", "rpz.txt", rpz, &mut out).rules, 1);
        let adblock = format!(
            "[Adblock Plus]\n{}",
            DOMAINS
                .replace('#', "!")
                .replace("*.z.io\nz.io\na.io\n", "||z.io^\n||a.io^\n")
                .replace("entries: 3", "entries: 2")
        );
        assert_eq!(check_file("a", "adblock.txt", &adblock, &mut out).rules, 2);
        assert!(out.is_empty(), "{out:?}");
    }
}
