use regex::bytes::Regex;
use rustc_hash::FxHashSet;
use std::sync::LazyLock;

static SCRIPT_URL: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)(\.m?js$|/gtm\.js\?|/gtag/js\?|/signals/config/|/fbevents\.js|/(js|sdk|tag|tags|loader|script)(/|\?|$)|cookielaw\.org/|osano\.com/|transcend-cdn\.com/|consensu\.org/|\.json$)")
        .expect("SCRIPT_URL regex")
});

static URL_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:https?:)?\\?/\\?/([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,24})")
        .expect("URL_HOST regex")
});

static QUOTED_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)["'`]([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|ai|app|dev|tech|cloud|me|tv|tr|com\.tr|net\.tr|ru|de|eu|uk|co\.uk|fr|nl|pl|cn|jp|kr|in|br|us|info|biz|xyz|site|online|digital|media|ads|link|click|pro|global))["'`]"#)
        .expect("QUOTED_HOST regex")
});

static BARE_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,24})\b")
        .expect("BARE_HOST regex")
});

pub fn script_url(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    url.starts_with("https://") && (SCRIPT_URL.is_match(path) || SCRIPT_URL.is_match(url))
}

pub fn hosts_in_script(body: &[u8]) -> Vec<String> {
    let mut set: FxHashSet<String> = FxHashSet::default();
    set.extend(crate::hosts_in(body, &URL_HOST, 1));
    set.extend(crate::hosts_in(body, &QUOTED_HOST, 1));
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort_unstable();
    v
}

pub fn refang(text: &str) -> String {
    let mut s = text.to_string();
    for (from, to) in [
        ("[.]", "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[dot]", "."),
        ("(dot)", "."),
        ("[:]", ":"),
        ("hxxps", "https"),
        ("hxxp", "http"),
        ("fxp", "ftp"),
    ] {
        s = s.replace(from, to);
    }
    s
}

pub fn hosts_in_report(text: &str, listed_tld: impl Fn(&str) -> bool) -> Vec<(String, bool)> {
    let plain: FxHashSet<String> = crate::hosts_in(text.as_bytes(), &BARE_HOST, 1)
        .into_iter()
        .collect();
    let clean = refang(text);
    let mut v: Vec<(String, bool)> = crate::hosts_in(clean.as_bytes(), &BARE_HOST, 1)
        .into_iter()
        .filter(|h| listed_tld(h))
        .map(|h| {
            let defanged = !plain.contains(&h);
            (h, defanged)
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_hosts_in_scripts_and_reports() {
        assert!(script_url("https://cdn.x.com/a/b.js?v=1"));
        assert!(script_url("https://cdn.cookielaw.org/consent/abc/abc.json"));
        assert!(!script_url("https://x.com/img.png"));
        let js = br#"var a="https:\/\/t.vendor.io\/c";var b='api.vendor.com';var c="v1.2.3";"#;
        assert_eq!(hosts_in_script(js), ["api.vendor.com", "t.vendor.io"]);
        let report = "C2: bad-domain[.]com and hxxps://evil(.)example[.]net/x, also config.json";
        let got = hosts_in_report(report, |h| h.ends_with(".com") || h.ends_with(".net"));
        assert_eq!(
            got,
            [
                ("bad-domain.com".to_string(), true),
                ("evil.example.net".to_string(), true)
            ]
        );
    }
}
