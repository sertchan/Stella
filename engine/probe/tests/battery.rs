use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use stella_net::limit::Limiter;
use stella_net::tls::Fail;
use stella_probe::battery::{self, Battery, FOLLOWED, FULL_EXTRA, LITE, Prober, RANDOM};
use stella_probe::rules::{self, PICK};
use stella_testkit::http::{Http, Reply, Site};
use tokio::net::TcpListener;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn prober(tls_port: u16, plain_port: u16) -> Prober {
    let mut p = Prober::new(Limiter::new(32, 2000));
    p.tls_port = tls_port;
    p.plain_port = plain_port;
    p.timeout = Duration::from_secs(2);
    p.tcp_timeout = Duration::from_secs(1);
    p.tls_timeout = Duration::from_secs(1);
    p.budget = Duration::from_secs(8);
    p
}

async fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    drop(l);
    port
}

fn sgtm() -> Site {
    Site::new()
        .route(
            "/healthy",
            Reply::ok("ok").header("Content-Type", "text/plain"),
        )
        .fallback(Reply::new(400))
}

fn paths(srv: &Http) -> Vec<String> {
    srv.seen().into_iter().map(|s| s.path).collect()
}

#[tokio::test]
async fn sgtm_server_is_picked_end_to_end() {
    let srv = Http::tls(sgtm(), &["sgtm.shop.test"])
        .await
        .expect("server");
    let p = prober(srv.addr.port(), closed_port().await)
        .probe("sgtm.shop.test", LOCAL, Battery::Lite)
        .await;
    assert!(p.answered());
    assert!(!p.plain_http);
    assert_eq!(p.results.len(), LITE.len());
    assert_eq!(p.get("/healthy").map(|r| r.status), Some(200));
    assert_eq!(p.get(RANDOM).map(|r| (r.status, r.length)), Some((400, 0)));
    assert_eq!(p.sans, ["sgtm.shop.test"]);
    assert!(p.tls.ends_with("|http/1.1|1"), "{}", p.tls);
    assert_eq!(p.requests, LITE.len());
    assert!(p.fails.is_empty());
    let hits = rules::classify(&p, "shop.test");
    assert!(
        hits.iter()
            .any(|h| h.product == "sgtm" && h.verdict == PICK),
        "{:?}",
        hits.iter()
            .map(|h| (h.product, h.verdict))
            .collect::<Vec<_>>()
    );
    let seen = srv.seen();
    assert!(
        seen.iter()
            .all(|s| s.method == "GET" && s.host == "sgtm.shop.test")
    );
    assert!(
        seen.iter()
            .any(|s| s.path.len() > 2 && !LITE.contains(&s.path.as_str()))
    );
}

#[tokio::test]
async fn staged_battery_follows_redirect_and_asks_scripts() {
    let site = Site::new()
        .route(
            "/",
            Reply::new(302).header("Location", "https://t.shop.test/landing"),
        )
        .route("/landing", Reply::ok("plain landing"))
        .route(
            "/matomo.js",
            Reply::ok("/*! Matomo - free/libre analytics platform */ var Matomo={};")
                .header("Content-Type", "application/javascript"),
        );
    let srv = Http::tls(site, &["t.shop.test"]).await.expect("server");
    let p = prober(srv.addr.port(), closed_port().await)
        .probe("t.shop.test", LOCAL, Battery::Staged { tracking: true })
        .await;
    assert_eq!(p.get(FOLLOWED).map(|r| r.status), Some(200));
    let asked = paths(&srv);
    assert!(asked.contains(&"/landing".to_string()));
    for extra in FULL_EXTRA {
        assert!(
            asked.contains(&(*extra).to_string()),
            "{extra} in {asked:?}"
        );
    }
    let hits = rules::classify(&p, "shop.test");
    assert!(
        hits.iter().any(|h| h.product == "matomo"),
        "{:?}",
        hits.len()
    );
}

#[tokio::test]
async fn full_battery_asks_every_fixed_path() {
    let srv = Http::tls(Site::new(), &["f.shop.test"])
        .await
        .expect("server");
    let p = prober(srv.addr.port(), closed_port().await)
        .probe("f.shop.test", LOCAL, Battery::Full)
        .await;
    assert_eq!(p.results.len(), LITE.len() + FULL_EXTRA.len());
    assert!(
        p.results
            .iter()
            .all(|(_, r)| r.as_ref().is_some_and(|r| r.status == 404))
    );
}

#[tokio::test]
async fn closed_connections_spread_the_rest_over_new_ones() {
    let site = Site::new()
        .route("/", Reply::ok("bye").close())
        .route("/healthy", Reply::ok("ok").close());
    let srv = Http::tls(site, &["c.shop.test"]).await.expect("server");
    let p = prober(srv.addr.port(), closed_port().await)
        .probe("c.shop.test", LOCAL, Battery::Lite)
        .await;
    assert!(p.results.iter().all(|(_, r)| r.is_some()));
    assert!(p.connects >= 2, "connects {}", p.connects);
}

#[tokio::test]
async fn plain_http_answers_when_tls_fails() {
    let plain = Http::plain(sgtm()).await.expect("plain");
    let p = prober(plain.addr.port(), plain.addr.port())
        .probe("p.shop.test", LOCAL, Battery::Lite)
        .await;
    assert!(p.plain_http);
    assert!(p.answered());
    assert_eq!(
        p.get("/healthy").map(|r| r.body.clone()),
        Some(b"ok".to_vec())
    );
    assert!(
        p.fails
            .iter()
            .any(|f| matches!(f, Fail::TlsOther | Fail::TlsReset))
    );
}

#[tokio::test]
async fn refused_host_gives_up_at_once() {
    let port = closed_port().await;
    let p = prober(port, port)
        .probe("gone.shop.test", LOCAL, Battery::Lite)
        .await;
    assert!(!p.answered());
    assert_eq!(p.fails, [Fail::Refused]);
    assert_eq!(p.requests, 0);
}

#[tokio::test]
async fn silent_server_times_out_inside_budget() {
    let site = Site::new().fallback(Reply::ok("late").delay(Duration::from_secs(30)));
    let srv = Http::tls(site, &["s.shop.test"]).await.expect("server");
    let mut pr = prober(srv.addr.port(), closed_port().await);
    pr.timeout = Duration::from_millis(300);
    let p = pr.probe("s.shop.test", LOCAL, Battery::Lite).await;
    assert!(!p.answered());
    assert!(p.elapsed < Duration::from_secs(8));
}

#[tokio::test]
async fn probe_all_reports_every_host() {
    let srv = Http::tls(sgtm(), &["a.shop.test"]).await.expect("server");
    let pr = prober(srv.addr.port(), closed_port().await);
    let items: Vec<(String, IpAddr, Battery)> = ["a.shop.test", "b.shop.test", "c.shop.test"]
        .iter()
        .map(|h| ((*h).to_string(), LOCAL, Battery::Lite))
        .collect();
    let mut got = Vec::new();
    battery::probe_all(&pr, items, 2, |p| {
        got.push(p.host.clone());
        p.answered()
    })
    .await;
    got.sort();
    assert_eq!(got, ["a.shop.test", "b.shop.test", "c.shop.test"]);
    assert_eq!(battery::head(b"  a\n\n b\tc \x01d", 5), " a b ");
    assert_eq!(battery::head("çok uzun".as_bytes(), 3), "ço");
}
