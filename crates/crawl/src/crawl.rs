use crate::cdp::{Browser, Display, Launch};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::Instant;

const CONSENT_JS: &str = include_str!("consent.js");
const NOISE: &[&str] = &[
    "accounts.google.com",
    "update.googleapis.com",
    "redirector.gvt1.com",
    "cloudflare-dns.com",
    "content-autofill.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "safebrowsing.googleapis.com",
    "edgedl.me.gvt1.com",
    "android.clients.google.com",
];
const MIN_FREE_BYTES: u64 = 1536 * 1024 * 1024;
const FIRST_CONSENT: Duration = Duration::from_secs(8);
const CONSENT_GAP: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct Options {
    pub par: usize,
    pub dwell: Duration,
    pub consent: bool,
    pub after: Duration,
    pub headful: bool,
    pub restart_every: usize,
    pub width: u32,
    pub height: u32,
}

pub struct Page {
    pub url: String,
    pub requests: Vec<(String, String)>,
    pub consent: String,
    pub error: Option<String>,
}

fn noise(url: &str) -> bool {
    stella_core::name::host_of_url(url)
        .is_none_or(|h| NOISE.contains(&h) || h.starts_with("clients"))
}

fn mem_available() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("MemAvailable:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map_or(u64::MAX, |kb| kb * 1024)
}

async fn wait_for_memory() {
    while mem_available() < MIN_FREE_BYTES {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn record(v: &Value, out: &mut Vec<(String, String)>) {
    if v.get("method").and_then(Value::as_str) != Some("Network.requestWillBeSent") {
        return;
    }
    let method = v
        .pointer("/params/request/method")
        .and_then(Value::as_str)
        .unwrap_or("GET");
    let Some(url) = v.pointer("/params/request/url").and_then(Value::as_str) else {
        return;
    };
    if url.starts_with("http") && !noise(url) {
        out.push((method.to_string(), url.to_string()));
    }
}

fn wake_child(b: &Browser, v: &Value) {
    if v.get("method").and_then(Value::as_str) != Some("Target.attachedToTarget") {
        return;
    }
    let Some(child) = v.pointer("/params/sessionId").and_then(Value::as_str) else {
        return;
    };
    b.notify(child, "Network.enable", json!({}));
    b.notify(
        child,
        "Target.setAutoAttach",
        json!({ "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true }),
    );
    b.notify(child, "Runtime.runIfWaitingForDebugger", json!({}));
}

async fn drain(
    b: &Browser,
    rx: &mut mpsc::UnboundedReceiver<Value>,
    until: Instant,
    out: &mut Vec<(String, String)>,
) {
    while let Ok(Some(v)) = tokio::time::timeout_at(until, rx.recv()).await {
        wake_child(b, &v);
        record(&v, out);
    }
}

pub async fn visit(b: &Browser, url: &str, opts: &Options) -> Page {
    let mut page = Page {
        url: url.to_string(),
        requests: Vec::new(),
        consent: String::new(),
        error: None,
    };
    let ctx = match b
        .call(
            None,
            "Target.createBrowserContext",
            json!({ "disposeOnDetach": true }),
        )
        .await
    {
        Ok(v) => v["browserContextId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        Err(e) => {
            page.error = Some(e.to_string());
            return page;
        }
    };
    let run = async {
        let target = b
            .call(
                None,
                "Target.createTarget",
                json!({ "url": "about:blank", "browserContextId": ctx }),
            )
            .await?;
        let target = target["targetId"]
            .as_str()
            .ok_or_else(|| anyhow!("no target"))?
            .to_string();
        let attached = b
            .call(
                None,
                "Target.attachToTarget",
                json!({ "targetId": target, "flatten": true }),
            )
            .await?;
        let session = attached["sessionId"]
            .as_str()
            .ok_or_else(|| anyhow!("no session"))?
            .to_string();
        let mut rx = b.subscribe(&session);
        b.call(Some(&session), "Network.enable", json!({})).await?;
        b.call(Some(&session), "Page.enable", json!({})).await?;
        b.call(
            Some(&session),
            "Target.setAutoAttach",
            json!({ "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true }),
        )
        .await?;
        let started = Instant::now();
        b.notify(&session, "Page.navigate", json!({ "url": url }));
        let mut clicked = Vec::new();
        if opts.consent {
            drain(b, &mut rx, started + FIRST_CONSENT, &mut page.requests).await;
            for _ in 0..2 {
                let r = b
                    .call(
                        Some(&session),
                        "Runtime.evaluate",
                        json!({ "expression": CONSENT_JS, "returnByValue": true }),
                    )
                    .await;
                if let Some(s) = r.ok().and_then(|v| {
                    v.pointer("/result/value")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                }) && !s.is_empty()
                {
                    clicked.push(s);
                }
                drain(b, &mut rx, Instant::now() + CONSENT_GAP, &mut page.requests).await;
            }
            drain(b, &mut rx, Instant::now() + opts.after, &mut page.requests).await;
        }
        let end = started + opts.dwell;
        if end > Instant::now() {
            drain(b, &mut rx, end, &mut page.requests).await;
        }
        drop(rx);
        b.forget(&session);
        Ok::<String, anyhow::Error>(clicked.join(","))
    };
    match run.await {
        Ok(c) => page.consent = c,
        Err(e) => page.error = Some(e.to_string()),
    }
    let _ = b
        .call(
            None,
            "Target.disposeBrowserContext",
            json!({ "browserContextId": ctx }),
        )
        .await;
    page
}

pub async fn run(
    urls: Vec<String>,
    opts: Options,
    work: &Path,
    tx: mpsc::Sender<Page>,
) -> Result<()> {
    let display = if opts.headful {
        Some(Display::start(90 + std::process::id() % 400, opts.width, opts.height).await?)
    } else {
        None
    };
    let launch = Launch {
        headful: opts.headful,
        display: display.as_ref().map(|d| d.name.clone()),
        width: opts.width,
        height: opts.height,
        extra: Vec::new(),
    };
    let per_browser = opts.restart_every.max(opts.par).max(1);
    for (n, chunk) in urls.chunks(per_browser).enumerate() {
        let profile: PathBuf = work.join(format!("profile-{n}"));
        let browser = Arc::new(Browser::launch(&launch, &profile).await?);
        let sem = Arc::new(Semaphore::new(opts.par.max(1)));
        let mut set = tokio::task::JoinSet::new();
        for url in chunk {
            let permit = sem.clone().acquire_owned().await?;
            wait_for_memory().await;
            let (b, o, tx, url) = (browser.clone(), opts.clone(), tx.clone(), url.clone());
            set.spawn(async move {
                let page = visit(&b, &url, &o).await;
                let _ = tx.send(page).await;
                drop(permit);
            });
        }
        while set.join_next().await.is_some() {}
        if let Ok(b) = Arc::try_unwrap(browser) {
            b.close().await;
        }
    }
    if let Some(d) = display {
        d.stop().await;
    }
    Ok(())
}
