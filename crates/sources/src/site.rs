use crate::hosts_in;
use regex::bytes::Regex;
use std::sync::LazyLock;

const PAGE_CAP: usize = 1_500_000;
const GTM_HOST: &str = "www.googletagmanager.com";

static IDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(GTM-[A-Z0-9]{4,10}|G-[A-Z0-9]{6,12}|AW-[0-9]{6,12}|DC-[0-9]{6,10})\b")
        .expect("IDS regex")
});
static INLINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:(?:server_container_url|transport_url)["' :=]+https?:\\?/\\?/([a-z0-9.-]+))|(?:https?:\\?/\\?/([a-z0-9.-]+)/(?:gtm\.js|gtag/js)\?id=)"#,
    )
    .expect("INLINE regex")
});
static HEADER_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:https?://|wss?://|[ "',])\*?\.?([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)"#)
        .expect("HEADER_HOST regex")
});

pub const HEADERS: &[&str] = &[
    "content-security-policy",
    "content-security-policy-report-only",
    "access-control-allow-origin",
    "report-to",
    "nel",
    "reporting-endpoints",
    "link",
    "timing-allow-origin",
];

static LINK_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)<link\b[^>]*>"#).expect("LINK_TAG regex"));
static LINK_REL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\brel\s*=\s*["']?\s*(preconnect|dns-prefetch)\b"#).expect("LINK_REL regex")
});
static LINK_HREF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bhref\s*=\s*["']?(?:https?:)?//([a-z0-9.-]+)"#).expect("LINK_HREF regex")
});

pub fn resource_hints(body: &[u8]) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for tag in LINK_TAG.find_iter(body) {
        let tag = tag.as_bytes();
        let Some(rel) = LINK_REL.captures(tag).and_then(|c| c.get(1)) else {
            continue;
        };
        let kind = if rel.as_bytes().eq_ignore_ascii_case(b"preconnect") {
            "preconnect"
        } else {
            "dns-prefetch"
        };
        for h in hosts_in(tag, &LINK_HREF, 1) {
            out.push((kind, h));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[derive(Default, Debug)]
pub struct Finds {
    pub ids: Vec<String>,
    pub inline: Vec<String>,
    pub headers: Vec<(&'static str, String)>,
}

pub fn ids(body: &[u8]) -> Vec<String> {
    let mut v: Vec<String> = IDS
        .find_iter(body)
        .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

pub fn inline(body: &[u8]) -> Vec<String> {
    let mut v: Vec<String> = hosts_in(body, &INLINE, 1)
        .into_iter()
        .chain(hosts_in(body, &INLINE, 2))
        .filter(|h| h != GTM_HOST)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

pub fn header_hosts(name: &'static str, value: &[u8]) -> Vec<(&'static str, String)> {
    let mut padded = Vec::with_capacity(value.len() + 1);
    padded.push(b' ');
    padded.extend_from_slice(value);
    hosts_in(&padded, &HEADER_HOST, 1)
        .into_iter()
        .map(|h| (name, h))
        .collect()
}

pub async fn mine(client: &reqwest::Client, domain: &str) -> Option<Finds> {
    let mut page = None;
    for url in [
        format!("https://www.{domain}/"),
        format!("https://{domain}/"),
    ] {
        if let Ok(p) = stella_net::client::fetch(client, &url, PAGE_CAP).await
            && !p.body.is_empty()
        {
            page = Some(p);
            break;
        }
    }
    let page = page?;
    let mut f = Finds {
        ids: ids(&page.body)
            .into_iter()
            .chain(crate::vendors::pixel_ids(&page.body))
            .collect(),
        inline: inline(&page.body),
        headers: resource_hints(&page.body),
    };
    for name in HEADERS {
        for v in page.headers.get_all(*name) {
            f.headers.extend(header_hosts(name, v.as_bytes()));
        }
    }
    f.headers.sort_unstable();
    f.headers.dedup();
    Some(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_preconnect_and_dns_prefetch_hints() {
        let page = br#"<head><link rel="preconnect" href="https://sst.shop.com" crossorigin>
            <link href='//cdn.vendor.io' rel='dns-prefetch'>
            <LINK REL=preconnect HREF=https://Fonts.Gstatic.com>
            <link rel="stylesheet" href="https://css.shop.com/a.css">
            <link rel="preload" href="https://img.shop.com/a.png"></head>"#;
        assert_eq!(
            resource_hints(page),
            [
                ("dns-prefetch", "cdn.vendor.io".to_string()),
                ("preconnect", "fonts.gstatic.com".to_string()),
                ("preconnect", "sst.shop.com".to_string()),
            ]
        );
        let tao: Vec<String> = header_hosts(
            "timing-allow-origin",
            b"https://www.shop.com, https://m.shop.com",
        )
        .into_iter()
        .map(|(_, h)| h)
        .collect();
        assert_eq!(tao, ["m.shop.com", "www.shop.com"]);
    }

    #[test]
    fn mines_report_and_link_headers_and_escaped_urls() {
        let hosts = |name: &'static str, v: &[u8]| -> Vec<String> {
            header_hosts(name, v).into_iter().map(|(_, h)| h).collect()
        };
        assert_eq!(
            hosts(
                "report-to",
                br#"{"group":"default","max_age":31536000,"endpoints":[{"url":"https://r.vendor.io/report"}]}"#
            ),
            ["r.vendor.io"]
        );
        assert!(hosts("nel", br#"{"report_to":"default","max_age":31536000}"#).is_empty());
        assert_eq!(
            hosts(
                "link",
                b"<https://cdn.vendor.io>; rel=preconnect, <https://fonts.gstatic.com>; rel=dns-prefetch"
            ),
            ["cdn.vendor.io", "fonts.gstatic.com"]
        );
        let json = br#"{"vtp_transport_url":"https:\/\/sst.shop.com","x":1}"#;
        assert_eq!(inline(json), ["sst.shop.com"]);
        let escaped = br#"{"transport_url":"https:\/\/sst.shop.com"}"#;
        assert_eq!(inline(escaped), ["sst.shop.com"]);
        assert!(ids(b"GTM-1 G-ABC AW-12").is_empty());
    }

    #[test]
    fn mines_tags_and_headers() {
        let page = br#"<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123XY"></script>
            gtag('config','GTM-W8KJ2Q',{server_container_url:'https://sgtm.shop.com'});
            <script src="https://load.data.shop.com/gtm.js?id=GTM-W8KJ2Q"></script>"#;
        assert_eq!(ids(page), ["G-ABC123XY", "GTM-W8KJ2Q"]);
        assert_eq!(inline(page), ["load.data.shop.com", "sgtm.shop.com"]);
        let csp = b"default-src 'self'; connect-src https://*.collect.shop.com wss://rt.shop.com https://www.google-analytics.com";
        let got: Vec<String> = header_hosts("content-security-policy", csp)
            .into_iter()
            .map(|(_, h)| h)
            .collect();
        assert_eq!(
            got,
            [
                "collect.shop.com",
                "rt.shop.com",
                "www.google-analytics.com"
            ]
        );
    }
}
