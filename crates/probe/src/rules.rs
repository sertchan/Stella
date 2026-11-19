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
    ("sgtm", &["stape server container"]),
    ("matomo", &["matomo", "piwik"]),
    ("umami", &["umami"]),
    ("plausible", &["plausible"]),
    ("posthog", &["posthog"]),
    ("fathom", &["fathom"]),
    ("jitsu", &["jitsu"]),
    ("rudderstack", &["rudder"]),
];
const MIRROR_HEAD: usize = 256;
const POSTHOG_MIN_BYTES: usize = 20_000;

pub fn html_app(p: &HostProbe) -> Option<String> {
    let root = p.get("/")?;
    if root.status != 200 || !html(Some(root)) {
        return None;
    }
    title(Some(root))
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
    if script(fixed(p, "/js/script.js"), "plausible") {
        out.push(("plausible", "/js/script.js".into()));
    }
    if script(fixed(p, "/script.js"), "umami") {
        out.push(("umami", "/script.js".into()));
    }
    if script(fixed(p, "/script.js"), "fathom") {
        out.push(("fathom", "/script.js".into()));
    }
    let array = fixed(p, "/static/array.js");
    if array.is_some_and(|a| a.body.len() > POSTHOG_MIN_BYTES)
        && script(array, "posthog")
        && !has(array, "grafana")
    {
        out.push(("posthog", "/static/array.js".into()));
    }
    if script(fixed(p, "/p.js"), "jitsu") {
        out.push(("jitsu", "/p.js".into()));
    }
    if script(fixed(p, "/lib.min.js"), "mixpanel") {
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

fn own_ui(product: &str, title: &str) -> bool {
    let t = title.to_ascii_lowercase();
    OWN_UI
        .iter()
        .filter(|(p, _)| *p == product)
        .any(|(_, marks)| marks.iter().any(|m| t.contains(m)))
}

pub fn classify(p: &HostProbe, sub: &str) -> Vec<Hit> {
    let app = html_app(p);
    let skipped = stella_core::token::skipped(sub);
    products(p)
        .into_iter()
        .map(|(product, evidence)| {
            let (verdict, evidence) = if product == "pixel" {
                (DROP, evidence)
            } else if skipped {
                (DROP, format!("{evidence}; staging or dev name"))
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
    use crate::battery::Battery;
    use std::net::{IpAddr, Ipv4Addr};

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
        let results = Battery::Full
            .paths()
            .into_iter()
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
        }
    }

    fn products_of(p: &HostProbe, sub: &str) -> Vec<(&'static str, &'static str)> {
        classify(p, sub)
            .into_iter()
            .map(|h| (h.product, h.verdict))
            .collect()
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
        let grafana = probe(
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
        assert!(products_of(&grafana, "stats").is_empty());
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
                        &format!("!function(t,e){{posthog}}{}", "x".repeat(30_000)),
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
}
