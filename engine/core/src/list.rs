use std::fmt::Write as _;

pub const HOMEPAGE: &str = "https://github.com/sertchan/Stella";
pub const LICENSE: &str = "https://github.com/sertchan/Stella/blob/main/LICENSE";
pub const ISSUES: &str = "https://github.com/sertchan/Stella/issues";
pub const EXPIRES: &str = "1 day";
pub const NULL_ADDRESS: &str = "0.0.0.0";
const RPZ_TTL: u32 = 3600;
const RPZ_TIMERS: &str = "28800 3600 259200 3600";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Domains,
    Wildcard,
    Hosts,
    Adblock,
    Rpz,
    Dnsmasq,
}

impl Format {
    pub const ALL: [Self; 6] = [
        Self::Domains,
        Self::Wildcard,
        Self::Hosts,
        Self::Adblock,
        Self::Rpz,
        Self::Dnsmasq,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Domains => "domains",
            Self::Wildcard => "wildcard",
            Self::Hosts => "hosts",
            Self::Adblock => "adblock",
            Self::Rpz => "rpz",
            Self::Dnsmasq => "dnsmasq",
        }
    }

    pub fn file_name(self) -> &'static str {
        match self {
            Self::Domains => "domains.txt",
            Self::Wildcard => "wildcard.txt",
            Self::Hosts => "hosts.txt",
            Self::Adblock => "adblock.txt",
            Self::Rpz => "rpz.txt",
            Self::Dnsmasq => "dnsmasq.txt",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.name() == name)
    }

    pub fn syntax(self) -> &'static str {
        match self {
            Self::Domains => "Domains (without subdomains)",
            Self::Wildcard => "Domains Wildcard (without subdomains)",
            Self::Hosts => "Hosts (without subdomains)",
            Self::Adblock => "AdBlock",
            Self::Rpz => "RPZ",
            Self::Dnsmasq => "DNSMasq v2.86 or newer",
        }
    }

    pub fn comment(self) -> &'static str {
        match self {
            Self::Adblock => "!",
            Self::Rpz => ";",
            _ => "#",
        }
    }

    pub fn rules(self, name: &str) -> Vec<String> {
        match self {
            Self::Domains => vec![name.to_string()],
            Self::Wildcard => vec![format!("*.{name}")],
            Self::Hosts => vec![format!("{NULL_ADDRESS} {name}")],
            Self::Adblock => vec![format!("||{name}^")],
            Self::Rpz => vec![format!("{name} CNAME ."), format!("*.{name} CNAME .")],
            Self::Dnsmasq => vec![format!("local=/{name}/")],
        }
    }
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

pub fn render(format: Format, header: &Header, entries: &[String]) -> String {
    let rules: Vec<String> = entries.iter().flat_map(|e| format.rules(e)).collect();
    let c = format.comment();
    let mut text = String::new();
    match format {
        Format::Adblock => text.push_str("[Adblock Plus]\n"),
        Format::Rpz => {
            let serial = u32::try_from(header.modified).unwrap_or(u32::MAX);
            let _ = writeln!(text, "$TTL {RPZ_TTL}");
            let _ = writeln!(
                text,
                "@ SOA localhost. root.localhost. {serial} {RPZ_TIMERS}"
            );
            text.push_str("  NS  localhost.\n;\n");
        }
        _ => {}
    }
    let values = [
        header.title.to_string(),
        header.description.to_string(),
        HOMEPAGE.to_string(),
        LICENSE.to_string(),
        ISSUES.to_string(),
        EXPIRES.to_string(),
        crate::time::list_modified(header.modified),
        crate::time::list_version(header.modified),
        format.syntax().to_string(),
        rules.len().to_string(),
    ];
    for (key, value) in HEADER_KEYS.iter().zip(values) {
        let _ = writeln!(text, "{c} {key}: {value}");
    }
    let _ = writeln!(text, "{c}");
    for r in rules {
        text.push_str(&r);
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header<'static> {
        Header {
            title: "Stella Tracker",
            description: "Tracking hosts",
            modified: 1_795_234_589,
        }
    }

    #[test]
    fn writes_each_rule_format() {
        let expected = [
            (Format::Domains, vec!["a.io"]),
            (Format::Wildcard, vec!["*.a.io"]),
            (Format::Hosts, vec!["0.0.0.0 a.io"]),
            (Format::Adblock, vec!["||a.io^"]),
            (Format::Rpz, vec!["a.io CNAME .", "*.a.io CNAME ."]),
            (Format::Dnsmasq, vec!["local=/a.io/"]),
        ];
        for (f, rules) in expected {
            assert_eq!(f.rules("a.io"), rules);
            assert_eq!(Format::from_name(f.name()), Some(f));
            assert_eq!(f.file_name(), format!("{}.txt", f.name()));
        }
        assert_eq!(Format::from_name("csv"), None);
    }

    #[test]
    fn renders_hagezi_style_headers() {
        let entries = vec!["a.io".to_string(), "z.io".to_string()];
        let domains = render(Format::Domains, &header(), &entries);
        assert!(domains.starts_with("# Title: Stella Tracker\n# Description: Tracking hosts\n# Homepage: https://github.com/sertchan/Stella\n"));
        assert!(domains.contains("# Issues: https://github.com/sertchan/Stella/issues\n# Expires: 1 day\n# Last modified: 21 Nov 2026 04:16 UTC\n# Version: 2026.1121.0416.29\n# Syntax: Domains (without subdomains)\n# Number of entries: 2\n#\na.io\nz.io\n"));
        let adblock = render(Format::Adblock, &header(), &entries);
        assert!(adblock.starts_with("[Adblock Plus]\n! Title: Stella Tracker\n"));
        assert!(adblock.ends_with("!\n||a.io^\n||z.io^\n"));
        let rpz = render(Format::Rpz, &header(), &entries);
        assert!(rpz.starts_with("$TTL 3600\n@ SOA localhost. root.localhost. 1795234589 28800 3600 259200 3600\n  NS  localhost.\n;\n; Title: Stella Tracker\n"));
        assert!(rpz.contains("; Number of entries: 4\n;\na.io CNAME .\n*.a.io CNAME .\n"));
        let empty = render(Format::Dnsmasq, &header(), &[]);
        assert!(empty.ends_with("# Syntax: DNSMasq v2.86 or newer\n# Number of entries: 0\n#\n"));
    }
}
