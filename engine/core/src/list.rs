use crate::category::Category;
use std::fmt::Write as _;

pub const HOMEPAGE: &str = "https://github.com/sertchan/Stella";
pub const LICENSE: &str = "https://github.com/sertchan/Stella/blob/main/LICENSE";
pub const EXPIRES: &str = "1 day";
const RPZ_TTL: u32 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Domains,
    Hosts,
    Adblock,
    Rpz,
}

impl Format {
    pub const ALL: [Self; 4] = [Self::Domains, Self::Hosts, Self::Adblock, Self::Rpz];

    pub fn file_name(self) -> &'static str {
        match self {
            Self::Domains => "domains.txt",
            Self::Hosts => "hosts.txt",
            Self::Adblock => "adblock.txt",
            Self::Rpz => "rpz.txt",
        }
    }

    pub fn syntax(self) -> &'static str {
        match self {
            Self::Domains => "Domains, one per line, *. covers every subdomain",
            Self::Hosts => "Hosts file, 0.0.0.0 then the domain",
            Self::Adblock => "Adblock Plus, ||domain^ covers every subdomain",
            Self::Rpz => "Response Policy Zone, CNAME . answers NXDOMAIN",
        }
    }

    pub fn comment(self) -> &'static str {
        match self {
            Self::Domains | Self::Hosts => "#",
            Self::Adblock => "!",
            Self::Rpz => ";",
        }
    }

    pub fn rules(self, name: &str, zone: bool) -> Vec<String> {
        match (self, zone) {
            (Self::Domains, false) => vec![name.to_string()],
            (Self::Domains, true) => vec![format!("*.{name}"), name.to_string()],
            (Self::Hosts, _) => vec![format!("0.0.0.0 {name}")],
            (Self::Adblock, _) => vec![format!("||{name}^")],
            (Self::Rpz, false) => vec![format!("{name} CNAME .")],
            (Self::Rpz, true) => vec![format!("{name} CNAME ."), format!("*.{name} CNAME .")],
        }
    }
}

pub struct Entries<'a> {
    pub zones: &'a [String],
    pub hosts: &'a [String],
}

impl Entries<'_> {
    pub fn rules(&self, format: Format) -> Vec<String> {
        let zones = self.zones.iter().flat_map(|z| format.rules(z, true));
        let hosts = self.hosts.iter().flat_map(|h| format.rules(h, false));
        zones.chain(hosts).collect()
    }
}

pub fn render(format: Format, category: Category, entries: &Entries, modified: i64) -> String {
    let rules = entries.rules(format);
    let c = format.comment();
    let mut text = String::new();
    if format == Format::Adblock {
        text.push_str("[Adblock Plus]\n");
    }
    for (key, value) in [
        ("Title", category.title().to_string()),
        ("Description", category.description().to_string()),
        ("Homepage", HOMEPAGE.to_string()),
        ("License", LICENSE.to_string()),
        ("Last modified", crate::time::utc(modified)),
        ("Expires", EXPIRES.to_string()),
        ("Number of entries", rules.len().to_string()),
        ("Syntax", format.syntax().to_string()),
    ] {
        let _ = writeln!(text, "{c} {key}: {value}");
    }
    if format == Format::Rpz {
        let serial = u32::try_from(modified).unwrap_or(u32::MAX);
        let _ = writeln!(text, "$TTL {RPZ_TTL}");
        let _ = writeln!(
            text,
            "@ SOA localhost. root.localhost. {serial} 43200 3600 86400 {RPZ_TTL}"
        );
        text.push_str("  NS localhost.\n");
    }
    for r in rules {
        text.push_str(&r);
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_each_rule_format() {
        assert_eq!(Format::Domains.rules("a.io", false), ["a.io"]);
        assert_eq!(Format::Domains.rules("z.io", true), ["*.z.io", "z.io"]);
        assert_eq!(Format::Hosts.rules("a.io", false), ["0.0.0.0 a.io"]);
        assert_eq!(Format::Adblock.rules("z.io", true), ["||z.io^"]);
        assert_eq!(
            Format::Rpz.rules("z.io", true),
            ["z.io CNAME .", "*.z.io CNAME ."]
        );
    }

    #[test]
    fn renders_a_header_and_every_rule() {
        let zones = vec!["z.io".to_string()];
        let hosts = vec!["a.io".to_string()];
        let entries = Entries {
            zones: &zones,
            hosts: &hosts,
        };
        let domains = render(Format::Domains, Category::Tracker, &entries, 0);
        assert!(domains.starts_with("# Title: Stella Tracker\n# Description: Tracking"));
        assert!(domains.contains("# Last modified: 1970-01-01T00:00:00Z\n"));
        assert!(domains.contains("# Number of entries: 3\n"));
        assert!(domains.ends_with(
            "# Syntax: Domains, one per line, *. covers every subdomain\n*.z.io\nz.io\na.io\n"
        ));
        let adblock = render(Format::Adblock, Category::Ads, &entries, 0);
        assert!(adblock.starts_with("[Adblock Plus]\n! Title: Stella Ads\n"));
        assert!(adblock.ends_with("||z.io^\n||a.io^\n"));
        let rpz = render(Format::Rpz, Category::Telemetry, &entries, 1_795_234_589);
        assert!(rpz.contains("$TTL 300\n@ SOA localhost. root.localhost. 1795234589 43200 3600 86400 300\n  NS localhost.\nz.io CNAME .\n"));
        let empty = Entries {
            zones: &[],
            hosts: &[],
        };
        let hosts = render(Format::Hosts, Category::SelfHostedTelemetry, &empty, 0);
        assert!(hosts.contains("# Number of entries: 0\n"));
        assert!(hosts.ends_with("# Syntax: Hosts file, 0.0.0.0 then the domain\n"));
        for f in Format::ALL {
            assert!(f.file_name().ends_with(".txt"));
        }
    }
}
