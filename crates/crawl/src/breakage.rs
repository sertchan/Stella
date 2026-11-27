use crate::cdp::{Browser, Display, Launch};
use crate::crawl::{CONSENT_JS, FIRST_CONSENT, wait_for_memory};
use anyhow::{Result, anyhow};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::Instant;

const MEASURE_JS: &str = r#"JSON.stringify({t: document.title || "", x: ((document.body && document.body.innerText) || "").length, c: document.querySelectorAll("a[href],button,input,select,textarea").length, f: Array.from(document.querySelectorAll("iframe")).filter(e => e.offsetWidth * e.offsetHeight > 0).length})"#;
const BASE_RUNS: usize = 2;
const MIN_TEXT: usize = 200;
const MIN_CONTROLS: usize = 10;
const MIN_FRAMES: usize = 1;
const EXTRA_ERRORS: usize = 2;
const EXTRA_FAILED: usize = 2;

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub title: String,
    pub text: usize,
    pub controls: usize,
    pub frames: usize,
    pub errors: usize,
    pub failed: usize,
    pub requests: usize,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct Judgement {
    pub known: bool,
    pub breaks: bool,
    pub reasons: Vec<String>,
    pub notes: Vec<String>,
}

pub struct Case {
    pub host: String,
    pub pages: Vec<String>,
}

pub struct Outcome {
    pub host: String,
    pub page: String,
    pub base: Vec<Snapshot>,
    pub blocked: Snapshot,
    pub judgement: Judgement,
}

pub struct Options {
    pub dwell: Duration,
    pub consent: bool,
    pub headful: bool,
    pub par: usize,
    pub width: u32,
    pub height: u32,
}

fn under(host: &str, blocked: &str) -> bool {
    host == blocked || host.ends_with(&format!(".{blocked}"))
}

fn count(v: &Value, blocked: Option<&str>, ids: &mut FxHashMap<String, String>, s: &mut Snapshot) {
    match v.get("method").and_then(Value::as_str) {
        Some("Network.requestWillBeSent") => {
            s.requests += 1;
            let id = v.pointer("/params/requestId").and_then(Value::as_str);
            let url = v.pointer("/params/request/url").and_then(Value::as_str);
            if let (Some(id), Some(h)) = (id, url.and_then(stella_core::name::host_of_url)) {
                ids.insert(id.to_string(), h.to_string());
            }
        }
        Some("Network.loadingFailed") => {
            if v.pointer("/params/canceled").and_then(Value::as_bool) == Some(true) {
                return;
            }
            let host = v
                .pointer("/params/requestId")
                .and_then(Value::as_str)
                .and_then(|id| ids.get(id));
            if !host.is_some_and(|h| blocked.is_some_and(|b| under(h, b))) {
                s.failed += 1;
            }
        }
        Some("Runtime.exceptionThrown") => s.errors += 1,
        Some("Log.entryAdded") => {
            let level = v.pointer("/params/entry/level").and_then(Value::as_str);
            let source = v.pointer("/params/entry/source").and_then(Value::as_str);
            if level == Some("error") && source != Some("network") {
                s.errors += 1;
            }
        }
        _ => {}
    }
}

async fn drain(
    rx: &mut mpsc::UnboundedReceiver<Value>,
    until: Instant,
    blocked: Option<&str>,
    ids: &mut FxHashMap<String, String>,
    s: &mut Snapshot,
) {
    while let Ok(Some(v)) = tokio::time::timeout_at(until, rx.recv()).await {
        count(&v, blocked, ids, s);
    }
}

pub async fn snapshot(b: &Browser, url: &str, opts: &Options, blocked: Option<&str>) -> Snapshot {
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
            return Snapshot {
                error: Some(e.to_string()),
                ..Snapshot::default()
            };
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
        for m in [
            "Network.enable",
            "Page.enable",
            "Runtime.enable",
            "Log.enable",
        ] {
            b.call(Some(&session), m, json!({})).await?;
        }
        let mut s = Snapshot::default();
        let mut ids = FxHashMap::default();
        let started = Instant::now();
        b.notify(&session, "Page.navigate", &json!({ "url": url }));
        if opts.consent {
            drain(&mut rx, started + FIRST_CONSENT, blocked, &mut ids, &mut s).await;
            let _ = b
                .call(
                    Some(&session),
                    "Runtime.evaluate",
                    json!({ "expression": CONSENT_JS, "returnByValue": true }),
                )
                .await;
        }
        drain(&mut rx, started + opts.dwell, blocked, &mut ids, &mut s).await;
        let m = b
            .call(
                Some(&session),
                "Runtime.evaluate",
                json!({ "expression": MEASURE_JS, "returnByValue": true }),
            )
            .await?;
        let text = m
            .pointer("/result/value")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("page gave no measurement"))?;
        let v: Value = serde_json::from_str(text)?;
        s.title = v["t"].as_str().unwrap_or_default().trim().to_string();
        s.text = v["x"].as_u64().unwrap_or(0) as usize;
        s.controls = v["c"].as_u64().unwrap_or(0) as usize;
        s.frames = v["f"].as_u64().unwrap_or(0) as usize;
        drop(rx);
        b.forget(&session);
        Ok::<Snapshot, anyhow::Error>(s)
    };
    let s = run.await.unwrap_or_else(|e| Snapshot {
        error: Some(e.to_string()),
        ..Snapshot::default()
    });
    let _ = b
        .call(
            None,
            "Target.disposeBrowserContext",
            json!({ "browserContextId": ctx }),
        )
        .await;
    s
}

fn dropped(
    what: &str,
    base: &[&Snapshot],
    blocked: usize,
    field: fn(&Snapshot) -> usize,
    floor: usize,
) -> Option<String> {
    let lo = base.iter().map(|s| field(s)).min()?;
    let hi = base.iter().map(|s| field(s)).max()?;
    if lo < floor {
        return None;
    }
    let drop = lo.saturating_sub(blocked);
    (drop > (2 * (hi - lo)).max(lo / 4)).then(|| format!("{what} {lo} -> {blocked}"))
}

pub fn judge(base: &[Snapshot], blocked: &Snapshot) -> Judgement {
    let ok: Vec<&Snapshot> = base.iter().filter(|s| s.error.is_none()).collect();
    let mut j = Judgement::default();
    if ok.is_empty() {
        j.notes
            .push("page did not load without blocking either".into());
        return j;
    }
    j.known = true;
    if let Some(e) = &blocked.error {
        j.reasons.push(format!("page did not load: {e}"));
    } else {
        j.reasons.extend(dropped(
            "visible text",
            &ok,
            blocked.text,
            |s| s.text,
            MIN_TEXT,
        ));
        j.reasons.extend(dropped(
            "links and controls",
            &ok,
            blocked.controls,
            |s| s.controls,
            MIN_CONTROLS,
        ));
        let title = &ok[0].title;
        if !title.is_empty() && ok.iter().all(|s| &s.title == title) && &blocked.title != title {
            j.reasons
                .push(format!("title {title:?} -> {:?}", blocked.title));
        }
    }
    if blocked.error.is_none() {
        j.notes.extend(dropped(
            "visible frames",
            &ok,
            blocked.frames,
            |s| s.frames,
            MIN_FRAMES,
        ));
    }
    let errors = ok.iter().map(|s| s.errors).max().unwrap_or(0);
    if blocked.errors > errors + EXTRA_ERRORS {
        j.notes
            .push(format!("script errors {errors} -> {}", blocked.errors));
    }
    let failed = ok.iter().map(|s| s.failed).max().unwrap_or(0);
    if blocked.failed > failed + EXTRA_FAILED {
        j.notes.push(format!(
            "other failed requests {failed} -> {}",
            blocked.failed
        ));
    }
    j.breaks = !j.reasons.is_empty();
    j
}

fn launch(opts: &Options, display: Option<&Display>, extra: Vec<String>) -> Launch {
    Launch {
        headful: opts.headful,
        user_agent: crate::cdp::ANDROID_UA,
        display: display.map(|d| d.name.clone()),
        width: opts.width,
        height: opts.height,
        extra,
    }
}

pub fn block_rule(host: &str) -> String {
    format!("--host-resolver-rules=MAP {host} ~NOTFOUND, MAP *.{host} ~NOTFOUND")
}

pub async fn run(
    cases: Vec<Case>,
    opts: Options,
    work: &Path,
    tx: mpsc::Sender<Outcome>,
) -> Result<()> {
    let display = if opts.headful {
        Some(Display::start(500 + std::process::id() % 400, opts.width, opts.height).await?)
    } else {
        None
    };
    let mut pages: Vec<String> = cases.iter().flat_map(|c| c.pages.iter().cloned()).collect();
    pages.sort_unstable();
    pages.dedup();
    let base_browser = Browser::launch(
        &launch(&opts, display.as_ref(), Vec::new()),
        &work.join("base"),
    )
    .await?;
    let mut base: FxHashMap<String, Vec<Snapshot>> = FxHashMap::default();
    for page in &pages {
        let mut runs = Vec::with_capacity(BASE_RUNS);
        for _ in 0..BASE_RUNS {
            runs.push(snapshot(&base_browser, page, &opts, None).await);
        }
        base.insert(page.clone(), runs);
    }
    base_browser.close().await;
    let base = Arc::new(base);
    let opts = Arc::new(opts);
    let sem = Arc::new(Semaphore::new(opts.par.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (n, case) in cases.into_iter().enumerate() {
        let permit = sem.clone().acquire_owned().await?;
        wait_for_memory().await;
        let profile = work.join(format!("blocked-{n}"));
        let l = launch(&opts, display.as_ref(), vec![block_rule(&case.host)]);
        let (base, opts, tx) = (base.clone(), opts.clone(), tx.clone());
        set.spawn(async move {
            match Browser::launch(&l, &profile).await {
                Ok(b) => {
                    for page in &case.pages {
                        let blocked = snapshot(&b, page, &opts, Some(&case.host)).await;
                        let runs = base.get(page).cloned().unwrap_or_default();
                        let judgement = judge(&runs, &blocked);
                        let _ = tx
                            .send(Outcome {
                                host: case.host.clone(),
                                page: page.clone(),
                                base: runs,
                                blocked,
                                judgement,
                            })
                            .await;
                    }
                    b.close().await;
                }
                Err(e) => eprintln!("breakage {}: {e}", case.host),
            }
            drop(permit);
        });
    }
    while set.join_next().await.is_some() {}
    if let Some(d) = display {
        d.stop().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(text: usize, controls: usize, title: &str, errors: usize) -> Snapshot {
        Snapshot {
            title: title.into(),
            text,
            controls,
            errors,
            ..Snapshot::default()
        }
    }

    #[test]
    fn judges_only_clear_changes_as_breakage() {
        let base = vec![snap(5000, 120, "Shop", 1), snap(5200, 118, "Shop", 1)];
        assert!(!judge(&base, &snap(4900, 117, "Shop", 6)).breaks);
        assert!(!judge(&base, &snap(4900, 117, "Shop", 6)).notes.is_empty());
        assert!(judge(&base, &snap(300, 4, "Shop", 1)).breaks);
        assert!(judge(&base, &snap(5000, 120, "Error", 1)).breaks);
        let failed = Snapshot {
            error: Some("timeout".into()),
            ..Snapshot::default()
        };
        assert!(judge(&base, &failed).breaks);
        assert!(!judge(std::slice::from_ref(&failed), &snap(10, 1, "", 0)).known);
        let framed = |f: usize| Snapshot {
            frames: f,
            ..snap(5000, 120, "Shop", 1)
        };
        let j = judge(&[framed(2), framed(2)], &framed(0));
        assert!(!j.breaks);
        assert_eq!(j.notes, ["visible frames 2 -> 0"]);
        assert!(judge(&[framed(2), framed(2)], &framed(2)).notes.is_empty());
        assert_eq!(
            block_rule("t.shop.com"),
            "--host-resolver-rules=MAP t.shop.com ~NOTFOUND, MAP *.t.shop.com ~NOTFOUND"
        );
    }
}
