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

static SOURCE_MAP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[/][/][#@]\s*sourceMappingURL=([^\s'"]+)"#).expect("SOURCE_MAP regex")
});

static SERVICE_WORKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"serviceWorker\s*\.\s*register\(\s*['"`]([^'"`]+)['"`]"#)
        .expect("SERVICE_WORKER regex")
});

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Linked {
    SourceMap,
    ServiceWorker,
}

impl Linked {
    pub fn source(self) -> &'static str {
        match self {
            Linked::SourceMap => "sourcemap",
            Linked::ServiceWorker => "serviceworker",
        }
    }
}

pub fn resolve(base: &str, rel: &str) -> Option<String> {
    let base = base.split(['?', '#']).next()?;
    let (scheme, rest) = base.split_once("://")?;
    let host_end = rest.find('/').unwrap_or(rest.len());
    let origin = format!("{scheme}://{}", &rest[..host_end]);
    if rel.starts_with("https://") || rel.starts_with("http://") {
        return Some(rel.to_string());
    }
    if let Some(r) = rel.strip_prefix("//") {
        return Some(format!("{scheme}://{r}"));
    }
    if rel.starts_with('/') {
        return Some(format!("{origin}{rel}"));
    }
    let dir = &base[..base.rfind('/')? + 1];
    (dir.len() > origin.len()).then(|| format!("{dir}{rel}"))
}

pub fn linked(body: &[u8], base: &str) -> Vec<(Linked, String)> {
    let mut out = Vec::new();
    for (kind, re) in [
        (Linked::SourceMap, &SOURCE_MAP),
        (Linked::ServiceWorker, &SERVICE_WORKER),
    ] {
        for c in re.captures_iter(body) {
            let Some(m) = c.get(1) else { continue };
            let rel = String::from_utf8_lossy(m.as_bytes());
            if rel.starts_with("data:") {
                out.push((kind, rel.into_owned()));
            } else if let Some(u) = resolve(base, &rel) {
                out.push((kind, u));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub fn inline_map(url: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let (_, data) = url.strip_prefix("data:")?.split_once(";base64,")?;
    base64::engine::general_purpose::STANDARD.decode(data).ok()
}

pub fn hosts_in_map(body: &[u8]) -> Vec<String> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let mut set: FxHashSet<String> = FxHashSet::default();
    for s in v["sourcesContent"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str())
    {
        set.extend(hosts_in_script(s.as_bytes()));
    }
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort_unstable();
    out
}

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
    fn follows_source_maps_and_service_workers() {
        use base64::Engine;
        let map = br#"{"version":3,"sources":["a.ts"],"sourcesContent":["fetch('https://ev.vendor.io/v1/e')","const h = \"cdn.vendor.io\";"]}"#;
        let inline = format!(
            "data:application/json;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(map)
        );
        let body = format!(
            "var a=1;navigator.serviceWorker.register('sw.js',{{scope:'/'}});\n{}{} sourceMappingURL=app.js.map\n{}{} sourceMappingURL={inline}",
            '/', "/#", '/', "/#"
        );
        let got = linked(body.as_bytes(), "https://www.shop.com/static/js/app.js?v=3");
        assert_eq!(
            got,
            [
                (Linked::SourceMap, inline.clone()),
                (
                    Linked::SourceMap,
                    "https://www.shop.com/static/js/app.js.map".to_string()
                ),
                (
                    Linked::ServiceWorker,
                    "https://www.shop.com/static/js/sw.js".to_string()
                ),
            ]
        );
        assert_eq!(
            hosts_in_map(&inline_map(&inline).expect("inline")),
            ["cdn.vendor.io", "ev.vendor.io"]
        );
        assert_eq!(
            resolve("https://a.io/x/y.js", "/sw.js").as_deref(),
            Some("https://a.io/sw.js")
        );
        assert_eq!(
            resolve("https://a.io/y.js", "//cdn.b.io/m.map").as_deref(),
            Some("https://cdn.b.io/m.map")
        );
        assert!(hosts_in_map(b"not json").is_empty());
    }

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
