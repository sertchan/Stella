use std::net::SocketAddr;
use std::time::Duration;
use stella_net::client::{self, Options};
use stella_net::http::Conn;
use stella_net::limiter::Limiter;
use stella_net::tls::{self, Fail};
use stella_testkit::http::{Http, Reply, Site};
use tokio::net::TcpListener;

const WAIT: Duration = Duration::from_secs(2);

async fn closed_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l);
    a
}

#[tokio::test]
async fn tls_reads_print_sans_and_serves_get() {
    stella_net::install_crypto();
    let site = Site::new().route("/x", Reply::ok("hello").header("X-Kind", "probe"));
    let srv = Http::tls(site, &["api.vendor.test", "*.cdn.vendor.test"])
        .await
        .expect("server");
    let c = tls::insecure_connector();
    let s = tls::connect(&c, "api.vendor.test", srv.addr, WAIT, WAIT)
        .await
        .expect("connect");
    let print = tls::print(&s);
    assert!(print.starts_with("TLSv1_3|TLS13_"), "{print}");
    assert!(print.ends_with("|http/1.1|1"), "{print}");
    assert_eq!(tls::sans(&s), ["api.vendor.test", "cdn.vendor.test"]);
    let mut conn = Conn::new(s);
    let r = conn
        .get("api.vendor.test", "/x", "ua", 1024)
        .await
        .expect("get");
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
    let r = conn
        .get("api.vendor.test", "/none", "ua", 1024)
        .await
        .expect("get");
    assert_eq!(r.status, 404);
    let seen = srv.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].host, "api.vendor.test");
    let ip_only = tls::connect(&c, "127.0.0.1", srv.addr, WAIT, WAIT)
        .await
        .expect("ip name");
    assert_eq!(tls::sans(&ip_only).len(), 2);
}

#[tokio::test]
async fn tls_failures_are_named() {
    stella_net::install_crypto();
    let c = tls::insecure_connector();
    let refused = tls::connect(&c, "h.test", closed_port().await, WAIT, WAIT).await;
    assert_eq!(refused.err(), Some(Fail::Refused));
    let quiet = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let quiet_addr = quiet.local_addr().expect("addr");
    let hold = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = quiet.accept().await {
            held.push(s);
        }
    });
    let slow = tls::connect(&c, "h.test", quiet_addr, WAIT, Duration::from_millis(200)).await;
    assert_eq!(slow.err(), Some(Fail::TlsTimeout));
    hold.abort();
    let plain = Http::plain(Site::new()).await.expect("plain");
    let wrong = tls::connect(&c, "h.test", plain.addr, WAIT, WAIT).await;
    assert!(matches!(wrong.err(), Some(Fail::TlsReset | Fail::TlsOther)));
    assert_eq!(Fail::TlsReset.retries(), 4);
    assert_eq!(Fail::Refused.retries(), 0);
    assert_eq!(Fail::TcpTimeout.retries(), 1);
    let names: Vec<&str> = [
        Fail::Refused,
        Fail::Unreachable,
        Fail::TcpTimeout,
        Fail::TlsReset,
        Fail::TlsTimeout,
        Fail::TlsOther,
    ]
    .iter()
    .map(|f| f.as_str())
    .collect();
    assert_eq!(
        names,
        [
            "refused",
            "unreachable",
            "tcp-timeout",
            "tls-reset",
            "tls-timeout",
            "tls-error"
        ]
    );
}

#[tokio::test]
async fn client_fetches_follows_redirects_and_caps_bodies() {
    let site = Site::new()
        .route("/old", Reply::new(301).header("Location", "/new"))
        .route("/new", Reply::ok("0123456789").header("X-Seen", "yes"))
        .route("/file", Reply::ok(&"z".repeat(1000)))
        .route("/missing", Reply::new(404));
    let srv = Http::plain(site).await.expect("server");
    let http = client::build(&Options {
        timeout: WAIT,
        http1_only: true,
        insecure: true,
        ..Options::default()
    })
    .expect("client");
    let page = client::fetch(&http, &srv.url("/old"), 4)
        .await
        .expect("page");
    assert_eq!(page.status, 200);
    assert!(page.url.ends_with("/new"));
    assert_eq!(page.body, b"0123");
    assert_eq!(page.headers["x-seen"], "yes");
    let dir = std::env::temp_dir().join(format!("stella-net-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let target = dir.join("file.bin");
    let n = client::download(&http, &srv.url("/file"), &target, 4096)
        .await
        .expect("download");
    assert_eq!(n, 1000);
    assert_eq!(std::fs::read(&target).expect("read").len(), 1000);
    let big = client::download(&http, &srv.url("/file"), &dir.join("big.bin"), 10).await;
    assert!(big.expect_err("cap").to_string().contains("larger than 10"));
    let missing = client::download(&http, &srv.url("/missing"), &dir.join("m.bin"), 10).await;
    assert!(missing.expect_err("404").to_string().contains("404"));
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[tokio::test]
async fn limiter_caps_slots_handshakes_and_paces() {
    let l = Limiter::with_handshakes(2, 1000, 1);
    let a = l.slot().await.expect("a");
    let _b = l.slot().await.expect("b");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), l.slot())
            .await
            .is_err()
    );
    drop(a);
    assert!(l.slot().await.is_some());
    let h = l.handshake().await.expect("hs");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), l.handshake())
            .await
            .is_err()
    );
    drop(h);
    let paced = Limiter::new(8, 20);
    let started = tokio::time::Instant::now();
    for _ in 0..3 {
        paced.pace().await;
    }
    assert!(started.elapsed() >= Duration::from_millis(90));
}

#[tokio::test]
async fn redirected_hosts_reach_the_mirror() {
    let srv = Http::plain(Site::new().route("/v1/list", Reply::ok("mirrored")))
        .await
        .expect("server");
    client::redirect("Mirror.Example.Test", &format!("http://{}/", srv.addr));
    assert_eq!(
        client::target("https://mirror.example.test/v1/list?x=1#top"),
        format!("http://{}/v1/list?x=1#top", srv.addr)
    );
    assert_eq!(
        client::target("https://user@mirror.example.test:8443"),
        format!("http://{}", srv.addr)
    );
    assert_eq!(
        client::target("https://other.example.test/a"),
        "https://other.example.test/a"
    );
    assert_eq!(client::target("not a url"), "not a url");
    let http = client::build(&Options {
        insecure: true,
        ..Options::default()
    })
    .expect("client");
    let page = client::fetch(&http, "https://mirror.example.test/v1/list", 64)
        .await
        .expect("mirrored page");
    assert_eq!(page.body, b"mirrored");
}
