use std::time::Duration;
use stella_crawl::breakage::{self, Case};
use stella_crawl::cdp::{ANDROID_UA, Browser, Compositor, Launch, Profile};
use stella_crawl::crawler::{self, Options};
use stella_testkit::http::{Http, Reply, Site};
use tokio::sync::mpsc;

const PAGE: &str = r#"<html><head><title>Shop</title>
<script>document.write('<script src="http://assets.localhost:' + location.port + '/app.js"><\/script>');</script>
</head><body><h1>Shop</h1><button>Buy</button>
<script>
fetch("/collect?uid=1234567890abcdef", { method: "POST", body: "x" });
navigator.sendBeacon("/beacon", "y");
const c = document.createElement("canvas");
c.getContext("2d").fillText("x", 1, 1);
c.toDataURL();
</script></body></html>"#;

const APP: &str = r#"document.addEventListener("DOMContentLoaded", () => {
  const p = document.createElement("p");
  p.textContent = "loaded ".repeat(400);
  document.body.appendChild(p);
  for (let i = 0; i < 12; i++) {
    const b = document.createElement("button");
    b.textContent = "item " + i;
    document.body.appendChild(b);
  }
});"#;

async fn shop() -> Http {
    let site = Site::new()
        .route("/", Reply::ok(PAGE).header("Content-Type", "text/html"))
        .route(
            "/app.js",
            Reply::ok(APP).header("Content-Type", "application/javascript"),
        )
        .fallback(Reply::new(204));
    Http::plain(site).await.expect("shop server")
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("stella-crawl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn options() -> Options {
    Options {
        par: 2,
        dwell: Duration::from_secs(2),
        consent: true,
        after: Duration::from_millis(500),
        headful: false,
        restart_every: 4,
        width: 412,
        height: 915,
        profile: Profile::Android,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn crawl_records_requests_hooks_and_renders() {
    let srv = shop().await;
    let url = format!("http://127.0.0.1:{}/", srv.addr.port());
    let work = scratch("visit");
    let launch = Launch {
        headful: false,
        user_agent: ANDROID_UA,
        wayland: None,
        width: 412,
        height: 915,
        extra: Vec::new(),
    };
    let b = Browser::launch(&launch, &work.join("profile"))
        .await
        .expect("chromium");
    let page = crawler::visit(&b, &url, &options()).await;
    assert!(page.error.is_none(), "{:?}", page.error);
    assert!(
        page.requests
            .iter()
            .any(|(m, u)| m == "POST" && u.contains("/collect?uid=")),
        "{:?}",
        page.requests
    );
    assert!(page.requests.iter().any(|(_, u)| u.contains("/beacon")));
    assert!(
        page.hooks.keys().any(|(api, _, _)| api == "canvas"),
        "{:?}",
        page.hooks
    );
    let title = crawler::render(&b, &url, Duration::from_secs(1), "document.title")
        .await
        .expect("render");
    assert_eq!(title, "Shop");
    b.close().await;
    let (tx, mut rx) = mpsc::channel(8);
    crawler::run(vec![url.clone(), url.clone()], options(), &work, tx)
        .await
        .expect("crawl run");
    let mut pages = 0;
    while let Some(p) = rx.recv().await {
        assert!(p.error.is_none(), "{:?}", p.error);
        pages += 1;
    }
    assert_eq!(pages, 2);
    std::fs::remove_dir_all(work).expect("cleanup");
}

#[tokio::test(flavor = "multi_thread")]
async fn breakage_sees_a_page_lose_its_script() {
    let srv = shop().await;
    let url = format!("http://127.0.0.1:{}/", srv.addr.port());
    let work = scratch("breakage");
    let opts = breakage::Options {
        dwell: Duration::from_secs(2),
        consent: false,
        headful: false,
        par: 2,
        width: 412,
        height: 915,
    };
    let (tx, mut rx) = mpsc::channel(8);
    let cases = vec![
        Case {
            host: "assets.localhost".into(),
            pages: vec![url.clone()],
        },
        Case {
            host: "unused.localhost".into(),
            pages: vec![url.clone()],
        },
    ];
    breakage::run(cases, opts, &work, tx)
        .await
        .expect("breakage run");
    let mut seen = Vec::new();
    while let Some(o) = rx.recv().await {
        assert_eq!(o.base.len(), 2);
        assert!(o.base.iter().all(|s| s.title == "Shop"), "{:?}", o.base);
        seen.push((o.host, o.judgement.breaks, o.blocked.controls));
    }
    seen.sort();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(
        seen[0].1,
        "blocking the script host must break the page: {seen:?}"
    );
    assert!(
        !seen[1].1,
        "blocking an unused host must not break the page: {seen:?}"
    );
    assert_eq!(
        breakage::block_rule("x.test"),
        "--host-resolver-rules=MAP x.test ~NOTFOUND, MAP *.x.test ~NOTFOUND"
    );
    std::fs::remove_dir_all(work).expect("cleanup");
}

#[tokio::test(flavor = "multi_thread")]
async fn headful_crawl_runs_on_a_headless_wayland_compositor() {
    let srv = shop().await;
    let url = format!("http://127.0.0.1:{}/", srv.addr.port());
    let work = scratch("wayland");
    let compositor = Compositor::start(std::process::id() % 400, 412, 915)
        .await
        .expect("weston");
    assert!(
        compositor
            .wayland
            .runtime_dir
            .join(&compositor.wayland.socket)
            .exists()
    );
    let launch = Launch {
        headful: true,
        user_agent: ANDROID_UA,
        wayland: Some(compositor.wayland.clone()),
        width: 412,
        height: 915,
        extra: Vec::new(),
    };
    let b = Browser::launch(&launch, &work.join("profile"))
        .await
        .expect("chromium on wayland");
    let title = crawler::render(&b, &url, Duration::from_secs(1), "document.title")
        .await
        .expect("render");
    assert_eq!(title, "Shop");
    b.close().await;
    compositor.stop().await;
    let (tx, mut rx) = mpsc::channel(8);
    let opts = Options {
        headful: true,
        ..options()
    };
    crawler::run(vec![url], opts, &work, tx)
        .await
        .expect("headful crawl run");
    let page = rx.recv().await.expect("one page");
    assert!(page.error.is_none(), "{:?}", page.error);
    std::fs::remove_dir_all(work).expect("cleanup");
}
