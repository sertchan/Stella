use crate::battery::{HostProbe, RANDOM};
use stella_net::http::Resp;

#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub product: &'static str,
    pub evidence: String,
    pub verdict: &'static str,
}

pub const PICK: &str = "PICK";
pub const REVIEW: &str = "REVIEW";
pub const DROP: &str = "DROP";

fn lower(r: &Resp) -> Vec<u8> {
    r.body.to_ascii_lowercase()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    memchr::memmem::find(hay, needle.as_bytes()).is_some()
}

fn has(r: Option<&Resp>, needle: &str) -> bool {
    r.is_some_and(|r| contains(&lower(r), &needle.to_ascii_lowercase()))
}

fn html(r: Option<&Resp>) -> bool {
    r.is_some_and(|r| {
        let b = lower(r);
        contains(&b, "<html") || contains(&b, "<!doctype")
    })
}

fn mirrors(r: &Resp, rand: Option<&Resp>) -> bool {
    let Some(x) = rand else {
        return false;
    };
    if x.status != r.status || x.ctype != r.ctype {
        return false;
    }
    if x.body == r.body {
        return true;
    }
    let (a, b) = (r.body.len(), x.body.len());
    let near = a.abs_diff(b) * 100 <= a.max(b);
    let head = MIRROR_HEAD.min(a).min(b);
    near && head > 0 && r.body[..head] == x.body[..head]
}

fn fixed<'a>(p: &'a HostProbe, path: &str) -> Option<&'a Resp> {
    let r = p.get(path)?;
    (r.status == 200 && !mirrors(r, p.get(RANDOM))).then_some(r)
}

fn script(r: Option<&Resp>, needle: &str) -> bool {
    !html(r) && has(r, needle)
}

fn script_with(r: Option<&Resp>, needle: &str, second: &[&str]) -> bool {
    script(r, needle) && second.iter().any(|m| has(r, m))
}

pub fn title(r: Option<&Resp>) -> Option<String> {
    let r = r?;
    let b = lower(r);
    let start = memchr::memmem::find(&b, b"<title")?;
    let open = start + memchr::memchr(b'>', &b[start..])? + 1;
    let close = open + memchr::memmem::find(&b[open..], b"</title")?;
    let t = String::from_utf8_lossy(&r.body[open..close])
        .trim()
        .to_string();
    (!t.is_empty()).then_some(t)
}

const OWN_UI: &[(&str, &[&str])] = &[
    ("sgtm", &["stape server container", "taggrs", "heytag"]),
    ("matomo", &["matomo", "piwik"]),
    ("umami", &["umami"]),
    ("plausible", &["plausible"]),
    ("posthog", &["posthog"]),
    ("fathom", &["fathom"]),
    ("jitsu", &["jitsu"]),
    ("rudderstack", &["rudder"]),
];
const UMAMI_SECOND: &[&str] = &["website-id"];
const PLAUSIBLE_SECOND: &[&str] = &["data-domain", "/api/event"];
const FATHOM_SECOND: &[&str] = &["data-site", "trackpageview"];
const POSTHOG_SECOND: &[&str] = &["$pageview"];
const JITSU_SECOND: &[&str] = &["writekey", "/api/s/"];
const MIXPANEL_SECOND: &[&str] = &["api-js.mixpanel.com", "track_pageview"];
const MIRROR_HEAD: usize = 256;
const POSTHOG_MIN_BYTES: usize = 20_000;
const COLLECTOR_MAX_BYTES: usize = 512;
const PIXEL_MAX_BYTES: usize = 100;
const COLLECTOR_STRONG: &[&str] = &[
    "missing payload",
    "missing event",
    "no events",
    "invalid write key",
    "invalid writekey",
    "please post",
    "only post",
    "no data received",
    "event received",
    "events received",
    "unexpected end of json",
    "missing body",
    "empty body",
    "request body is empty",
];
const COLLECTOR_WEAK: &[&str] = &[
    "\"status\":\"ok\"",
    "\"status\": \"ok\"",
    "{\"success\":true}",
    "{\"ok\":true}",
];
pub const COLLECTOR: &str = "collector";

pub fn html_app(p: &HostProbe) -> Option<String> {
    let root = page(p.get("/"), p.get(crate::battery::FOLLOWED))?;
    if !html(Some(root)) {
        return None;
    }
    title(Some(root))
}

const HINTS: &[(&str, &str)] = &[
    ("matomo", "/matomo.js"),
    ("piwik", "/matomo.js"),
    ("umami", "/script.js"),
    ("plausible", "/js/script.js"),
    ("posthog", "/static/array.js"),
    ("fathom", "/script.js"),
    ("jitsu", "/p.js"),
    ("mixpanel", "/lib.min.js"),
    ("rudder", "/health"),
];

const BODY_HINTS: &[(&str, &str)] = &[("acceptingevents", "/health")];

fn page<'a>(root: Option<&'a Resp>, followed: Option<&'a Resp>) -> Option<&'a Resp> {
    root.filter(|r| r.status == 200)
        .or(followed.filter(|r| r.status == 200))
}

pub fn stage_two(
    root: Option<&Resp>,
    followed: Option<&Resp>,
    tracking_name: bool,
) -> Vec<&'static str> {
    let landing = page(root, followed);
    let mut v: Vec<&'static str> = Vec::new();
    if let Some(r) = landing {
        let body = lower(r);
        for (mark, path) in BODY_HINTS {
            if contains(&body, mark) {
                v.push(path);
            }
        }
    }
    for r in [root, followed].into_iter().flatten() {
        if let Some(t) = title(Some(r)).filter(|_| html(Some(r))) {
            let t = t.to_ascii_lowercase();
            v.extend(
                HINTS
                    .iter()
                    .filter(|(mark, _)| t.contains(mark))
                    .map(|(_, path)| *path),
            );
        }
    }
    let site = landing
        .filter(|r| html(Some(r)))
        .and_then(|r| title(Some(r)))
        .is_some();
    if v.is_empty() && (!site || tracking_name) {
        v.extend_from_slice(crate::battery::FULL_EXTRA);
    }
    let mut seen: Vec<&'static str> = Vec::new();
    v.retain(|p| {
        let fresh = !seen.contains(p);
        if fresh {
            seen.push(p);
        }
        fresh
    });
    v
}

pub fn same_host_target(location: &str, host: &str) -> Option<String> {
    let path = if location.starts_with('/') && !location.starts_with("//") {
        location.to_string()
    } else {
        let rest = location
            .strip_prefix("https://")
            .or_else(|| location.strip_prefix("http://"))?;
        let (h, p) = rest.split_once('/').unwrap_or((rest, ""));
        if !h.eq_ignore_ascii_case(host) {
            return None;
        }
        format!("/{p}")
    };
    (path.len() <= 512 && path != "/").then_some(path)
}

fn status(r: Option<&Resp>) -> u16 {
    r.map_or(0, |r| r.status)
}

fn products(p: &HostProbe) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let rand = p.get(RANDOM);
    let healthy = p.get("/healthy");
    let rs = status(rand);
    let healthy_ok =
        healthy.is_some_and(|h| h.status == 200 && h.body.len() <= 3 && h.body.starts_with(b"ok"));
    let empty_400 = rand.is_some_and(|r| r.status == 400 && r.length == 0);
    if healthy_ok && (empty_400 || has(rand, "Stape server container")) {
        out.push(("sgtm", format!("healthy ok, random {rs}")));
    }
    if let Some(i) = p.get("/i")
        && i.ctype.to_ascii_lowercase().starts_with("image/gif")
        && has(rand, "404 not found")
    {
        let cookie = i.cookies.first().map_or("-", String::as_str);
        out.push(("snowplow", format!("/i gif, cookie {cookie}")));
    }
    if has(rand, "Invalid path or write key") {
        out.push((
            "segment-proxy",
            "random path: Cannot GET - Invalid path or write key".into(),
        ));
    }
    if let Some(r) = rand
        && r.server.to_ascii_lowercase().starts_with("jag")
        && r.status == 404
        && r.length < 5
    {
        out.push(("adobe-fp", "Server: jag, empty 404".into()));
    }
    if let Some(r) = rand
        && r.status == 200
        && r.ctype.to_ascii_lowercase().starts_with("image/")
    {
        out.push(("pixel", format!("random path 200 {}", r.ctype)));
    }
    if has(
        fixed(p, "/matomo.js"),
        "Matomo - free/libre analytics platform",
    ) || has(
        fixed(p, "/matomo.js"),
        "Piwik - free/libre analytics platform",
    ) {
        out.push(("matomo", "/matomo.js".into()));
    }
    if script_with(fixed(p, "/js/script.js"), "plausible", PLAUSIBLE_SECOND) {
        out.push(("plausible", "/js/script.js".into()));
    }
    if script_with(fixed(p, "/script.js"), "umami", UMAMI_SECOND) {
        out.push(("umami", "/script.js".into()));
    }
    if script_with(fixed(p, "/script.js"), "fathom", FATHOM_SECOND) {
        out.push(("fathom", "/script.js".into()));
    }
    let array = fixed(p, "/static/array.js");
    if array.is_some_and(|a| a.body.len() > POSTHOG_MIN_BYTES)
        && script_with(array, "posthog", POSTHOG_SECOND)
    {
        out.push(("posthog", "/static/array.js".into()));
    }
    if script_with(fixed(p, "/p.js"), "jitsu", JITSU_SECOND) {
        out.push(("jitsu", "/p.js".into()));
    }
    if script_with(fixed(p, "/lib.min.js"), "mixpanel", MIXPANEL_SECOND) {
        out.push(("mixpanel-proxy", "/lib.min.js".into()));
    }
    if has(fixed(p, "/health"), "\"acceptingEvents\"") {
        out.push(("rudderstack", "/health".into()));
    }
    let first = p.host.split('.').next().unwrap_or("");
    if first.starts_with("mpc")
        && p.get("/").is_some_and(|r| {
            String::from_utf8_lossy(&r.body).trim() == "<h1>Resource not found</h1>"
        })
    {
        out.push(("mpc-gateway", "GET / Resource not found".into()));
    }
    out
}

fn collector(p: &HostProbe) -> Option<(bool, String)> {
    let rand_image = p
        .get(RANDOM)
        .is_some_and(|r| r.status == 200 && r.ctype.to_ascii_lowercase().starts_with("image/"));
    for (path, at) in [("/", "/"), (RANDOM, "random path")] {
        let Some(r) = p.get(path) else {
            continue;
        };
        if r.body.len() > COLLECTOR_MAX_BYTES || html(Some(r)) {
            continue;
        }
        let body = lower(r);
        let text = String::from_utf8_lossy(&body);
        let text = text.trim();
        let shown = crate::battery::head(text.as_bytes(), 60);
        if let Some(m) = COLLECTOR_STRONG.iter().find(|m| text.contains(*m)) {
            return Some((true, format!("{at} {} says {m}: {shown}", r.status)));
        }
        if r.status == 204 && r.body.is_empty() {
            return Some((false, format!("{at} empty 204")));
        }
        if text == "ok" || COLLECTOR_WEAK.iter().any(|m| text.contains(m)) {
            return Some((false, format!("{at} {} {shown}", r.status)));
        }
        if r.status == 405 {
            return Some((false, format!("{at} 405, GET not allowed")));
        }
        if path == "/" && !rand_image && tiny_gif(r) {
            return Some((false, format!("/ answers a {} byte gif", r.body.len())));
        }
    }
    let empty = |path: &str| {
        p.get(path)
            .filter(|r| r.body.is_empty() && matches!(r.status, 200 | 404))
            .map(|r| r.status)
    };
    if let (Some(a), Some(b)) = (empty("/"), empty(RANDOM)) {
        return Some((
            false,
            format!("/ answers an empty {a} and the random path an empty {b}"),
        ));
    }
    None
}

fn tiny_gif(r: &Resp) -> bool {
    r.status == 200
        && r.body.len() <= PIXEL_MAX_BYTES
        && r.ctype.to_ascii_lowercase().starts_with("image/gif")
}

fn own_ui(product: &str, title: &str) -> bool {
    let t = title.to_ascii_lowercase();
    OWN_UI
        .iter()
        .filter(|(p, _)| *p == product)
        .any(|(_, marks)| marks.iter().any(|m| t.contains(m)))
}

fn main_site(p: &HostProbe, regdom: &str) -> bool {
    p.host == regdom || p.host.strip_prefix("www.") == Some(regdom)
}

fn landing_title(p: &HostProbe) -> Option<String> {
    [p.get("/"), p.get(crate::battery::FOLLOWED)]
        .into_iter()
        .flatten()
        .filter(|r| html(Some(r)))
        .find_map(|r| title(Some(r)))
}

pub fn classify(p: &HostProbe, regdom: &str) -> Vec<Hit> {
    let sub = stella_core::name::subdomain(&p.host, regdom);
    let app = html_app(p);
    let main = main_site(p, regdom);
    let landing = landing_title(p);
    let skipped = stella_core::token::skipped(sub);
    let found = products(p);
    if found.is_empty() {
        return collector(p)
            .filter(|(strong, _)| !skipped && (*strong || stella_core::token::tracking(sub)))
            .map(|(_, evidence)| Hit {
                product: COLLECTOR,
                evidence: format!("{evidence}; collector-like reply, no known product"),
                verdict: REVIEW,
            })
            .into_iter()
            .collect();
    }
    found
        .into_iter()
        .map(|(product, evidence)| {
            let (verdict, evidence) = if product == "pixel" {
                let beacon = !skipped
                    && !main
                    && app.is_none()
                    && p.get(RANDOM).is_some_and(tiny_gif)
                    && stella_core::token::tracking(sub);
                if beacon {
                    (
                        REVIEW,
                        format!("{evidence}; tiny gif on every path under a tracking name"),
                    )
                } else {
                    (DROP, evidence)
                }
            } else if skipped {
                (DROP, format!("{evidence}; staging or dev name"))
            } else if main && !landing.as_deref().is_some_and(|t| own_ui(product, t)) {
                (REVIEW, format!("{evidence}; main site of its zone"))
            } else if let Some(t) = app.as_ref().filter(|t| !own_ui(product, t)) {
                (
                    REVIEW,
                    format!(
                        "{evidence}; html app at /: {}",
                        crate::battery::head(t.as_bytes(), 60)
                    ),
                )
            } else {
                (PICK, evidence)
            };
            Hit {
                product,
                evidence,
                verdict,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::battery::{FULL_EXTRA, LITE};
    use std::net::{IpAddr, Ipv4Addr};

    #[expect(
        clippy::unnecessary_wraps,
        reason = "fixtures fill the optional reply slots of a probe"
    )]
    fn resp(status: u16, ctype: &str, server: &str, body: &str) -> Option<Resp> {
        Some(Resp {
            status,
            ctype: ctype.into(),
            server: server.into(),
            length: body.len() as i64,
            body: body.as_bytes().to_vec(),
            ..Resp::default()
        })
    }

    fn probe(host: &str, set: &[(&str, Option<Resp>)]) -> HostProbe {
        let results = LITE
            .iter()
            .chain(FULL_EXTRA)
            .copied()
            .map(|p| {
                (
                    p,
                    set.iter()
                        .find(|(q, _)| *q == p)
                        .and_then(|(_, r)| r.clone()),
                )
            })
            .collect();
        HostProbe {
            host: host.into(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            results,
            sans: Vec::new(),
            tls: String::new(),
            fails: Vec::new(),
            requests: 0,
            elapsed: std::time::Duration::ZERO,
            sequential: false,
            connects: 0,
            plain_http: false,
        }
    }

    fn products_of(p: &HostProbe, sub: &str) -> Vec<(&'static str, &'static str)> {
        let regdom = p.host.strip_prefix(&format!("{sub}.")).unwrap_or(&p.host);
        classify(p, regdom)
            .into_iter()
            .map(|h| (h.product, h.verdict))
            .collect()
    }

    #[test]
    fn collector_replies_only_reach_review() {
        let strong = probe(
            "edge.shop.com",
            &[
                (
                    "/",
                    resp(
                        400,
                        "application/json",
                        "",
                        "{\"error\":\"missing payload\"}",
                    ),
                ),
                (RANDOM, resp(404, "text/plain", "", "")),
            ],
        );
        assert_eq!(products_of(&strong, "edge"), [(COLLECTOR, REVIEW)]);
        let weak = |sub: &str| {
            probe(
                &format!("{sub}.shop.com"),
                &[
                    ("/", resp(204, "", "", "")),
                    (RANDOM, resp(204, "", "", "")),
                ],
            )
        };
        assert_eq!(
            products_of(&weak("events"), "events"),
            [(COLLECTOR, REVIEW)]
        );
        assert!(products_of(&weak("api"), "api").is_empty());
        assert!(products_of(&weak("events-staging"), "events-staging").is_empty());
        let page = probe(
            "events.shop.com",
            &[(
                "/",
                resp(200, "text/html", "", "<html><title>ok</title></html>"),
            )],
        );
        assert!(products_of(&page, "events").is_empty());
    }

    #[test]
    fn detects_sgtm() {
        let p = probe(
            "sgtm.shop.com",
            &[
                ("/healthy", resp(200, "text/plain", "", "ok")),
                (RANDOM, resp(400, "", "", "")),
                ("/", resp(400, "", "", "")),
            ],
        );
        assert_eq!(products_of(&p, "sgtm"), [("sgtm", PICK)]);
        let stape = probe(
            "sst.shop.com",
            &[
                ("/healthy", resp(200, "text/plain", "", "ok")),
                (
                    "/",
                    resp(
                        200,
                        "text/html",
                        "",
                        "<html><title>Invalid request - Stape server container</title></html>",
                    ),
                ),
                (
                    RANDOM,
                    resp(
                        400,
                        "text/html",
                        "",
                        "<title>Invalid request - Stape server container</title>",
                    ),
                ),
            ],
        );
        assert_eq!(products_of(&stape, "sst"), [("sgtm", PICK)]);
        let plain = probe(
            "api.shop.com",
            &[
                ("/healthy", resp(200, "text/plain", "", "ok")),
                (RANDOM, resp(404, "", "", "nope")),
            ],
        );
        assert!(products_of(&plain, "api").is_empty());
    }

    #[test]
    fn detects_collectors() {
        let snow = probe(
            "sp.shop.com",
            &[
                ("/i", {
                    let mut r = resp(200, "image/gif", "", "GIF89a");
                    if let Some(r) = r.as_mut() {
                        r.cookies = vec!["sp".into()];
                    }
                    r
                }),
                (
                    RANDOM,
                    resp(
                        404,
                        "text/plain",
                        "akka-http",
                        "The requested resource could not be found. 404 Not Found",
                    ),
                ),
            ],
        );
        assert_eq!(products_of(&snow, "sp"), [("snowplow", PICK)]);
        let seg = probe(
            "cdp.shop.com",
            &[(
                RANDOM,
                resp(
                    404,
                    "text/html",
                    "",
                    "Cannot GET - Invalid path or write key",
                ),
            )],
        );
        assert_eq!(products_of(&seg, "cdp"), [("segment-proxy", PICK)]);
        let adobe = probe("smetrics.shop.com", &[(RANDOM, resp(404, "", "jag", ""))]);
        assert_eq!(products_of(&adobe, "smetrics"), [("adobe-fp", PICK)]);
        let rudder = probe(
            "rs.shop.com",
            &[(
                "/health",
                resp(
                    200,
                    "application/json",
                    "",
                    "{\"server\":\"UP\",\"db\":\"UP\",\"acceptingEvents\":\"TRUE\"}",
                ),
            )],
        );
        assert_eq!(products_of(&rudder, "rs"), [("rudderstack", PICK)]);
    }

    #[test]
    fn guards_false_positives() {
        let cdn = probe(
            "img.shop.com",
            &[(RANDOM, resp(200, "image/png", "", "\u{89}PNG"))],
        );
        assert_eq!(products_of(&cdn, "img"), [("pixel", DROP)]);
        let staging = probe(
            "sgtm.staging.shop.com",
            &[
                ("/healthy", resp(200, "", "", "ok")),
                (RANDOM, resp(400, "", "", "")),
            ],
        );
        assert_eq!(products_of(&staging, "sgtm.staging"), [("sgtm", DROP)]);
        let app = probe(
            "px.vendor.com",
            &[
                (
                    "/",
                    resp(
                        200,
                        "text/html",
                        "",
                        "<!doctype html><html><head><title>Vendor Console</title></head><body><div id=app></div></body></html>",
                    ),
                ),
                ("/healthy", resp(200, "", "", "ok")),
                (RANDOM, resp(400, "", "", "")),
            ],
        );
        assert_eq!(products_of(&app, "px"), [("sgtm", REVIEW)]);
        let shell = probe(
            "px.vendor.com",
            &[(
                "/",
                resp(
                    200,
                    "text/html",
                    "",
                    "<!doctype html><title>Vendor</title><div id=root></div>",
                ),
            )],
        );
        assert!(products_of(&shell, "px").is_empty());
        let mention = probe(
            "stats.example.org",
            &[(
                "/static/array.js",
                resp(
                    200,
                    "application/javascript",
                    "",
                    &format!("{}posthog grafana", "x".repeat(30_000)),
                ),
            )],
        );
        assert!(products_of(&mention, "stats").is_empty());
    }

    #[test]
    fn ignores_single_page_apps_that_answer_every_path() {
        let shell = format!(
            "<!doctype html><html lang=\"en\"><head><title>Plaud Web</title><script>posthog.init('phc_x')</script></head>{}</html>",
            " ".repeat(26_000)
        );
        let spa: Vec<(&str, Option<Resp>)> = [
            "/",
            "/static/array.js",
            "/health",
            "/script.js",
            "/matomo.js",
            RANDOM,
        ]
        .into_iter()
        .map(|p| (p, resp(200, "text/html; charset=utf-8", "", &shell)))
        .collect();
        assert!(products_of(&probe("web.plaud.ai", &spa), "web").is_empty());
        let bundle = format!("{}posthog umami", "x".repeat(30_000));
        let js_spa: Vec<(&str, Option<Resp>)> = ["/static/array.js", "/script.js", RANDOM]
            .into_iter()
            .map(|p| (p, resp(200, "application/javascript", "", &bundle)))
            .collect();
        assert!(products_of(&probe("cdn.shop.com", &js_spa), "cdn").is_empty());
        let real = probe(
            "ph.shop.com",
            &[
                (
                    "/static/array.js",
                    resp(
                        200,
                        "application/javascript",
                        "",
                        &format!(
                            "!function(t,e){{posthog.capture(\"$pageview\")}}{}",
                            "x".repeat(30_000)
                        ),
                    ),
                ),
                (RANDOM, resp(404, "text/plain", "", "Not Found")),
            ],
        );
        assert_eq!(products_of(&real, "ph"), [("posthog", PICK)]);
        let redirect = probe(
            "a.shop.com",
            &[(
                "/matomo.js",
                resp(
                    302,
                    "text/html",
                    "",
                    "Matomo - free/libre analytics platform",
                ),
            )],
        );
        assert!(products_of(&redirect, "a").is_empty());
        let matomo = probe(
            "stats.uni.edu",
            &[
                (
                    "/",
                    resp(
                        200,
                        "text/html",
                        "",
                        "<!DOCTYPE html><html><title>Sign in - Matomo</title></html>",
                    ),
                ),
                (
                    "/matomo.js",
                    resp(
                        200,
                        "application/javascript",
                        "",
                        "var Matomo; Matomo - free/libre analytics platform",
                    ),
                ),
                (RANDOM, resp(404, "text/html", "", "<html>missing</html>")),
            ],
        );
        assert_eq!(products_of(&matomo, "stats"), [("matomo", PICK)]);
    }

    #[test]
    fn guards_main_sites_but_not_analytics_dashboards() {
        let matomo_js = resp(
            200,
            "application/javascript",
            "",
            "Matomo - free/libre analytics platform",
        );
        let mut moved = resp(301, "", "", "");
        if let Some(r) = moved.as_mut() {
            r.location = "https://brave.com/".into();
        }
        let www = probe(
            "www.brave.com",
            &[("/", moved.clone()), ("/matomo.js", matomo_js.clone())],
        );
        assert_eq!(products_of(&www, "www"), [("matomo", REVIEW)]);
        let apex = probe("brave.com", &[("/matomo.js", matomo_js.clone())]);
        assert_eq!(classify(&apex, "brave.com")[0].verdict, REVIEW);
        let ui = resp(
            200,
            "text/html",
            "",
            "<html><title>Sign in - Matomo</title></html>",
        );
        let platform = probe(
            "stats.example.app",
            &[("/", ui), ("/matomo.js", matomo_js.clone())],
        );
        assert_eq!(classify(&platform, "stats.example.app")[0].verdict, PICK);
        let proxy = probe(
            "stats.shop.com",
            &[("/", moved), ("/matomo.js", matomo_js.clone())],
        );
        assert_eq!(products_of(&proxy, "stats"), [("matomo", PICK)]);
        let mut sso = resp(302, "", "", "");
        if let Some(r) = sso.as_mut() {
            r.location = "/index.php?module=Login".into();
        }
        let dashboard = probe(
            "analytics.uni.edu",
            &[("/", sso), ("/matomo.js", matomo_js)],
        );
        assert_eq!(products_of(&dashboard, "analytics"), [("matomo", PICK)]);
    }

    #[test]
    fn script_rules_need_a_second_product_marker() {
        let js = |path: &'static str, body: &str| {
            probe(
                "t.shop.com",
                &[
                    (path, resp(200, "application/javascript", "", body)),
                    (RANDOM, resp(404, "text/plain", "", "Not Found")),
                ],
            )
        };
        let umami = "const{currentScript:u,referrer:m}=c,p=e.umamiConfig||{};$=k(\"website-id\"),x=k(\"host-url\")";
        let plausible = "a.domain=o.getAttribute(\"data-domain\");window.plausible=g";
        let fathom = "window.fathom=(()=>{var s=document.querySelector(\"script[data-site]\")";
        let jitsu = "const jitsu=e=>{let t=e.writeKey;fetch(`${e.host}/api/s/${n}`)}";
        let mixpanel = "var MIXPANEL_LIB=\"mixpanel\";k={api_host:\"https://api-js.mixpanel.com\",track_pageview:!1}";
        assert_eq!(
            products_of(&js("/script.js", umami), "t"),
            [("umami", PICK)]
        );
        assert_eq!(
            products_of(&js("/js/script.js", plausible), "t"),
            [("plausible", PICK)]
        );
        assert_eq!(
            products_of(&js("/script.js", fathom), "t"),
            [("fathom", PICK)]
        );
        assert_eq!(products_of(&js("/p.js", jitsu), "t"), [("jitsu", PICK)]);
        assert_eq!(
            products_of(&js("/lib.min.js", mixpanel), "t"),
            [("mixpanel-proxy", PICK)]
        );
        for (path, bundle) in [
            ("/script.js", "import umami from \"./stats\";render()"),
            (
                "/js/script.js",
                "var label = \"plausible analytics setup\";",
            ),
            ("/script.js", "const fathom = depth * 6;"),
            ("/p.js", "var jitsu = 1;"),
            ("/lib.min.js", "export const mixpanel = null;"),
        ] {
            assert!(products_of(&js(path, bundle), "t").is_empty(), "{bundle}");
        }
    }

    #[test]
    fn picks_second_stage_paths_from_the_root_reply() {
        let site = resp(200, "text/html", "", "<html><title>Shop</title></html>");
        assert!(stage_two(site.as_ref(), None, false).is_empty());
        assert_eq!(stage_two(site.as_ref(), None, true), FULL_EXTRA);
        let matomo = resp(
            200,
            "text/html",
            "",
            "<html><title>Sign in - Matomo</title></html>",
        );
        assert_eq!(stage_two(matomo.as_ref(), None, false), ["/matomo.js"]);
        let api = resp(400, "", "", "");
        assert_eq!(stage_two(api.as_ref(), None, false), FULL_EXTRA);
        let redirect = resp(307, "", "", "");
        let login = resp(200, "text/html", "", "<html><title>Umami</title></html>");
        assert_eq!(
            stage_two(redirect.as_ref(), login.as_ref(), false),
            ["/script.js"]
        );
        let rudder = resp(
            200,
            "application/json",
            "",
            "{\"acceptingEvents\":\"TRUE\"}",
        );
        assert_eq!(stage_two(rudder.as_ref(), None, false)[0], "/health");
        assert_eq!(
            same_host_target("/login", "a.io").as_deref(),
            Some("/login")
        );
        assert_eq!(
            same_host_target("https://a.io/x?y=1", "a.io").as_deref(),
            Some("/x?y=1")
        );
        assert!(same_host_target("https://www.b.io/", "a.io").is_none());
        assert!(same_host_target("//evil.io/x", "a.io").is_none());
    }
}
