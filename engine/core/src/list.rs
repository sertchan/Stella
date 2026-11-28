use crate::category::Category;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub const HOMEPAGE: &str = "https://github.com/sertchan/Stella";
pub const LICENSE: &str = "https://github.com/sertchan/Stella/blob/main/LICENSE";
pub const ISSUES: &str = "https://github.com/sertchan/Stella/issues";
pub const EXPIRES: &str = "1 day";
pub const SYNTAX: &str = "Domains (without subdomains)";
pub const LISTS_DIR: &str = "lists";
pub const DOMAINS_FILE: &str = "domains.txt";
pub const METADATA_FILE: &str = "metadata.tsv";
pub const SUBCATEGORIES_DIR: &str = "subcategories";
pub const CHANGELOG_FILE: &str = "changelog.tsv";
pub const COUNTS_FILE: &str = "counts.tsv";
pub const BREAKAGE_OK: &str = "no visible change on";

const SELF_HOSTED_ONLY_AGGRESSIVE: &str =
    "aggressive because self-hosted telemetry is blocked only in aggressive lists";
const BREAKAGE_VERIFIED: &str =
    "standard because blocking it showed no visible change in the breakage test";
const BREAKAGE_UNVERIFIED: &str =
    "aggressive because the breakage test did not confirm that blocking it is safe";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    Standard,
    #[default]
    Aggressive,
}

impl Tier {
    pub const ALL: [Self; 2] = [Self::Standard, Self::Aggressive];

    pub fn slug(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Aggressive => "aggressive",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.slug() == slug)
    }

    pub fn audience(self) -> &'static str {
        match self {
            Self::Standard => "For every HaGeZi list from Light to Ultimate",
            Self::Aggressive => "For HaGeZi Pro++ and Ultimate only",
        }
    }

    pub fn categories(self) -> &'static [Category] {
        match self {
            Self::Standard => &[Category::Ads, Category::Tracker, Category::Telemetry],
            Self::Aggressive => &Category::ALL,
        }
    }

    pub fn holds(self, category: Category) -> bool {
        self.categories().contains(&category)
    }

    pub fn place(category: Category, verified: bool) -> (Self, &'static str) {
        if category == Category::SelfHostedTelemetry {
            (Self::Aggressive, SELF_HOSTED_ONLY_AGGRESSIVE)
        } else if verified {
            (Self::Standard, BREAKAGE_VERIFIED)
        } else {
            (Self::Aggressive, BREAKAGE_UNVERIFIED)
        }
    }
}

pub fn list_id(tier: Tier, category: Category) -> String {
    format!("{}/{}", tier.slug(), category.slug())
}

pub fn parse_list_id(id: &str) -> Option<(Tier, Category)> {
    let (t, c) = id.split_once('/')?;
    let tier = Tier::from_slug(t)?;
    let category = Category::from_slug(c)?;
    tier.holds(category).then_some((tier, category))
}

pub fn folder(root: &Path, tier: Tier, category: Category) -> PathBuf {
    root.join(tier.slug()).join(category.slug())
}

pub fn subcategory_file(root: &Path, tier: Tier, category: Category, sub: &str) -> PathBuf {
    folder(root, tier, category)
        .join(SUBCATEGORIES_DIR)
        .join(format!("{sub}.txt"))
}

pub fn title(tier: Tier, category: Category, sub: Option<&str>) -> String {
    let base = match tier {
        Tier::Standard => category.title().to_string(),
        Tier::Aggressive => format!("{} Aggressive", category.title()),
    };
    match sub {
        Some(s) => format!("{base}: {s}"),
        None => base,
    }
}

pub fn description(tier: Tier, category: Category, sub: Option<&str>) -> String {
    let part = sub.map_or(String::new(), |s| {
        format!("The {s} part of {}. ", title(tier, category, None))
    });
    format!("{part}{}. {}", category.description(), tier.audience())
}

pub struct Header<'a> {
    pub title: &'a str,
    pub description: &'a str,
    pub modified: i64,
}

pub const HEADER_KEYS: [&str; 10] = [
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

pub fn render(header: &Header, entries: &[String]) -> String {
    let values = [
        header.title.to_string(),
        header.description.to_string(),
        HOMEPAGE.to_string(),
        LICENSE.to_string(),
        ISSUES.to_string(),
        EXPIRES.to_string(),
        crate::time::list_modified(header.modified),
        crate::time::list_version(header.modified),
        SYNTAX.to_string(),
        entries.len().to_string(),
    ];
    let mut text = String::new();
    for (key, value) in HEADER_KEYS.iter().zip(values) {
        let _ = writeln!(text, "# {key}: {value}");
    }
    text.push_str("#\n");
    for e in entries {
        text.push_str(e);
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_hagezi_style_domains() {
        let header = Header {
            title: "Stella Tracker",
            description: "Tracking hosts",
            modified: 1_795_234_589,
        };
        let text = render(&header, &["a.io".to_string(), "z.io".to_string()]);
        assert!(text.starts_with("# Title: Stella Tracker\n# Description: Tracking hosts\n# Homepage: https://github.com/sertchan/Stella\n"));
        assert!(text.ends_with("# Issues: https://github.com/sertchan/Stella/issues\n# Expires: 1 day\n# Last modified: 21 Nov 2026 04:16 UTC\n# Version: 2026.1121.0416.29\n# Syntax: Domains (without subdomains)\n# Number of entries: 2\n#\na.io\nz.io\n"));
        assert!(render(&header, &[]).ends_with("# Number of entries: 0\n#\n"));
    }

    #[test]
    fn places_entries_in_tiers() {
        assert_eq!(
            Tier::place(Category::SelfHostedTelemetry, true).0,
            Tier::Aggressive
        );
        assert_eq!(Tier::place(Category::Tracker, true).0, Tier::Standard);
        assert_eq!(Tier::place(Category::Ads, false).0, Tier::Aggressive);
        assert!(
            Tier::place(Category::Ads, false)
                .1
                .contains("did not confirm")
        );
        assert!(!Tier::Standard.holds(Category::SelfHostedTelemetry));
        for t in Tier::ALL {
            assert_eq!(Tier::from_slug(t.slug()), Some(t));
            for c in t.categories() {
                assert_eq!(parse_list_id(&list_id(t, *c)), Some((t, *c)));
            }
        }
        assert_eq!(parse_list_id("standard/self-hosted-telemetry"), None);
        assert_eq!(parse_list_id("tracker"), None);
        assert_eq!(
            subcategory_file(
                Path::new("lists"),
                Tier::Aggressive,
                Category::SelfHostedTelemetry,
                "umami"
            ),
            Path::new("lists/aggressive/self-hosted-telemetry/subcategories/umami.txt")
        );
    }

    #[test]
    fn names_lists_and_subcategories() {
        assert_eq!(
            title(
                Tier::Aggressive,
                Category::SelfHostedTelemetry,
                Some("umami")
            ),
            "Stella Self-Hosted Telemetry Aggressive: umami"
        );
        assert_eq!(
            title(Tier::Standard, Category::Tracker, None),
            "Stella Tracker"
        );
        let d = description(Tier::Standard, Category::Ads, Some("pubmatic"));
        assert!(
            d.starts_with("The pubmatic part of Stella Ads. Ad serving"),
            "{d}"
        );
        assert!(
            d.ends_with(". For every HaGeZi list from Light to Ultimate"),
            "{d}"
        );
        assert!(
            description(Tier::Aggressive, Category::Tracker, None)
                .ends_with("For HaGeZi Pro++ and Ultimate only")
        );
    }
}
