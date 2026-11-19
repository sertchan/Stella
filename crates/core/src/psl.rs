use anyhow::{Context, Result};
use rustc_hash::FxHashSet;
use std::path::Path;

#[derive(Default)]
pub struct Psl {
    rules: FxHashSet<Box<str>>,
    wild: FxHashSet<Box<str>>,
    exceptions: FxHashSet<Box<str>>,
}

impl Psl {
    pub fn parse(text: &str) -> Self {
        let mut psl = Self::default();
        for line in text.lines() {
            let rule = line.split_whitespace().next().unwrap_or("");
            if rule.is_empty() || rule.starts_with("//") {
                continue;
            }
            let rule = rule.to_ascii_lowercase();
            if let Some(r) = rule.strip_prefix('!') {
                psl.exceptions.insert(r.into());
            } else if let Some(r) = rule.strip_prefix("*.") {
                psl.wild.insert(r.into());
            } else {
                psl.rules.insert(rule.into());
            }
        }
        psl
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("{} is missing, run stella known sync", path.display()))?;
        Ok(Self::parse(&text))
    }

    pub fn public_suffix<'a>(&self, name: &'a str) -> &'a str {
        for s in crate::name::suffixes(name) {
            if self.exceptions.contains(s) {
                return s.split_once('.').map_or(s, |(_, rest)| rest);
            }
            if self.rules.contains(s) {
                return s;
            }
            if let Some((_, rest)) = s.split_once('.')
                && self.wild.contains(rest)
            {
                return s;
            }
        }
        name.rsplit('.').next().unwrap_or(name)
    }

    pub fn regdom<'a>(&self, name: &'a str) -> Option<&'a str> {
        let ps = self.public_suffix(name);
        if ps.len() >= name.len() {
            return None;
        }
        let head = &name[..name.len() - ps.len() - 1];
        let start = head.rfind('.').map_or(0, |i| i + 1);
        Some(&name[start..])
    }

    pub fn regdom_or_self<'a>(&self, name: &'a str) -> &'a str {
        self.regdom(name).unwrap_or(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "com\nuk\nco.uk\n*.ck\n!www.ck\n*.compute.amazonaws.com\nappspot.com\n";

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
    }
}
