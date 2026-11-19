use anyhow::Result;
use rustc_hash::FxHashMap;
use std::path::Path;

#[derive(Default)]
pub struct Known {
    lists: Vec<String>,
    map: FxHashMap<Box<str>, u64>,
}

impl Known {
    pub fn load(dir: &Path, names: &[&str]) -> Result<Self> {
        let mut known = Self::default();
        for name in names.iter().take(64) {
            let path = dir.join(format!("{name}-onlydomains.txt"));
            let Ok(text) = std::fs::read_to_string(&path) else {
                eprintln!("known: {} missing", path.display());
                continue;
            };
            known.add(name, &text);
        }
        Ok(known)
    }

    pub fn add(&mut self, name: &str, text: &str) {
        let bit = 1u64 << self.lists.len().min(63);
        self.lists.push(name.to_string());
        for line in text.lines() {
            let d = line.trim();
            if d.is_empty() || d.starts_with('#') {
                continue;
            }
            let d = d.strip_prefix("*.").unwrap_or(d).to_ascii_lowercase();
            *self.map.entry(d.into_boxed_str()).or_default() |= bit;
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn mask(&self, host: &str) -> u64 {
        crate::name::suffixes(host)
            .filter_map(|s| self.map.get(s))
            .fold(0, |a, b| a | b)
    }

    pub fn contains(&self, host: &str) -> bool {
        crate::name::suffixes(host).any(|s| self.map.contains_key(s))
    }

    pub fn chain_mask<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> u64 {
        names.into_iter().fold(0, |a, n| a | self.mask(n))
    }

    pub fn labels(&self, mask: u64) -> String {
        self.lists
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, n)| n.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_parents_and_chains() {
        let mut k = Known::default();
        k.add("pro", "# head\nexample.com\n*.tracker.net\n");
        k.add("ultimate", "example.com\nads.other.org\n");
        assert_eq!(k.labels(k.mask("a.b.example.com")), "pro,ultimate");
        assert!(k.contains("x.tracker.net"));
        assert!(!k.contains("other.org"));
        assert_eq!(
            k.labels(k.chain_mask(["cdn.site.io", "ads.other.org"])),
            "ultimate"
        );
    }
}
