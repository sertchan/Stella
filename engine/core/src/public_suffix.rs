use anyhow::{Context, Result};
use rustc_hash::FxHashMap;
use std::path::Path;

const PRIVATE_MARK: &str = "===BEGIN PRIVATE DOMAINS===";

#[derive(Default)]
pub struct Psl {
    rules: FxHashMap<Box<str>, bool>,
    wild: FxHashMap<Box<str>, bool>,
    exceptions: FxHashMap<Box<str>, bool>,
}

fn has(map: &FxHashMap<Box<str>, bool>, key: &str, icann_only: bool) -> bool {
    map.get(key)
        .is_some_and(|private| !(icann_only && *private))
}

impl Psl {
    pub fn parse(text: &str) -> Self {
        let mut psl = Self::default();
        let mut private = false;
        for line in text.lines() {
            if line.contains(PRIVATE_MARK) {
                private = true;
                continue;
            }
            let rule = line.split_whitespace().next().unwrap_or("");
            if rule.is_empty() || rule.starts_with("//") {
                continue;
            }
            let rule = rule.to_ascii_lowercase();
            if let Some(r) = rule.strip_prefix('!') {
                psl.exceptions.insert(r.into(), private);
            } else if let Some(r) = rule.strip_prefix("*.") {
                psl.wild.insert(r.into(), private);
            } else {
                psl.rules.insert(rule.into(), private);
            }
        }
        psl
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("{} is missing, run stella known sync", path.display()))?;
        Ok(Self::parse(&text))
    }

    fn suffix_of<'a>(&self, name: &'a str, icann_only: bool) -> &'a str {
        for s in crate::name::suffixes(name) {
            if has(&self.exceptions, s, icann_only) {
                return s.split_once('.').map_or(s, |(_, rest)| rest);
            }
            if has(&self.rules, s, icann_only) {
                return s;
            }
            if let Some((_, rest)) = s.split_once('.')
                && has(&self.wild, rest, icann_only)
            {
                return s;
            }
        }
        name.rsplit('.').next().unwrap_or(name)
    }

    pub fn public_suffix<'a>(&self, name: &'a str) -> &'a str {
        self.suffix_of(name, false)
    }

    fn registrable<'a>(&self, name: &'a str, icann_only: bool) -> Option<&'a str> {
        let ps = self.suffix_of(name, icann_only);
        if ps.len() >= name.len() {
            return None;
        }
        let head = &name[..name.len() - ps.len() - 1];
        let start = head.rfind('.').map_or(0, |i| i + 1);
        Some(&name[start..])
    }

    pub fn regdom<'a>(&self, name: &'a str) -> Option<&'a str> {
        self.registrable(name, false)
    }

    pub fn regdom_or_self<'a>(&self, name: &'a str) -> &'a str {
        self.regdom(name).unwrap_or(name)
    }

    pub fn listed_tld(&self, name: &str) -> bool {
        has(&self.rules, name.rsplit('.').next().unwrap_or(name), false)
    }

    pub fn icann_regdom_or_self<'a>(&self, name: &'a str) -> &'a str {
        self.registrable(name, true).unwrap_or(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "com\nuk\nco.uk\n*.ck\n!www.ck\n===BEGIN PRIVATE DOMAINS===\n*.compute.amazonaws.com\nappspot.com\n";

    #[test]
    fn finds_registrable_domain() {
        let psl = Psl::parse(LIST);
        assert_eq!(psl.regdom("a.b.example.co.uk"), Some("example.co.uk"));
        assert_eq!(psl.regdom("www.ck"), Some("www.ck"));
        assert_eq!(psl.regdom("a.b.ck"), Some("a.b.ck"));
        assert_eq!(psl.regdom("x.app.appspot.com"), Some("app.appspot.com"));
        assert_eq!(
            psl.regdom("a.b.eu-west-1.compute.amazonaws.com"),
            Some("b.eu-west-1.compute.amazonaws.com")
        );
        assert_eq!(psl.regdom("x.example.zz"), Some("example.zz"));
        assert_eq!(psl.regdom("co.uk"), None);
        assert_eq!(psl.icann_regdom_or_self("x.app.appspot.com"), "appspot.com");
        assert_eq!(
            psl.icann_regdom_or_self("a.b.example.co.uk"),
            "example.co.uk"
        );
    }
}
