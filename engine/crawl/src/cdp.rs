use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

pub const ANDROID_UA: &str = "Mozilla/5.0 (Linux; Android 15; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36";
pub const IOS_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1";
pub const DESKTOP_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Profile {
    #[default]
    Android,
    Ios,
    Desktop,
}

impl Profile {
    pub fn user_agent(self) -> &'static str {
        match self {
            Self::Android => ANDROID_UA,
            Self::Ios => IOS_UA,
            Self::Desktop => DESKTOP_UA,
        }
    }

    pub fn size(self) -> (u32, u32) {
        match self {
            Self::Android => (412, 915),
            Self::Ios => (390, 844),
            Self::Desktop => (1366, 900),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Desktop => "desktop",
        }
    }
}
const DOH: &str =
    r#"{"dns_over_https":{"mode":"secure","templates":"https://cloudflare-dns.com/dns-query"}}"#;
const PORT_WAIT: Duration = Duration::from_secs(30);
const CALL_LIMIT: Duration = Duration::from_secs(30);

type Pending = Arc<Mutex<FxHashMap<u64, oneshot::Sender<Value>>>>;
type Sessions = Arc<Mutex<FxHashMap<String, mpsc::UnboundedSender<Value>>>>;

pub struct Launch {
    pub headful: bool,
    pub user_agent: &'static str,
    pub display: Option<String>,
    pub width: u32,
    pub height: u32,
    pub extra: Vec<String>,
}

pub struct Browser {
    child: Child,
    profile: PathBuf,
    out: mpsc::UnboundedSender<Message>,
    pending: Pending,
    sessions: Sessions,
    next: AtomicU64,
}

fn binary() -> String {
    std::env::var("STELLA_CHROMIUM").unwrap_or_else(|_| "chromium".into())
}

async fn devtools_url(profile: &Path) -> Result<String> {
    let file = profile.join("DevToolsActivePort");
    let deadline = tokio::time::Instant::now() + PORT_WAIT;
    loop {
        if let Ok(text) = tokio::fs::read_to_string(&file).await {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                return Ok(format!("ws://127.0.0.1:{port}{path}"));
            }
        }
        if tokio::time::Instant::now() > deadline {
            bail!("chromium did not open its devtools port");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

impl Browser {
    pub async fn launch(opts: &Launch, profile: &Path) -> Result<Self> {
        let _ = tokio::fs::remove_dir_all(profile).await;
        tokio::fs::create_dir_all(profile).await?;
        tokio::fs::write(profile.join("Local State"), DOH).await?;
        let mut cmd = Command::new(binary());
        cmd.args([
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-sync",
            "--disable-component-update",
            "--disable-background-networking",
            "--mute-audio",
            "--remote-debugging-port=0",
            "--enable-features=AsyncDns",
        ])
        .arg(format!("--window-size={},{}", opts.width, opts.height))
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("--user-agent={}", opts.user_agent))
        .args(&opts.extra)
        .arg("about:blank")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
        if opts.headful {
            cmd.arg("--ozone-platform=x11");
            if let Some(d) = &opts.display {
                cmd.env("DISPLAY", d);
            }
        } else {
            cmd.args(["--headless=new", "--disable-gpu"]);
        }
        let child = cmd.spawn().context("start chromium")?;
        let url = devtools_url(profile).await?;
        let (ws, _) = tokio_tungstenite::connect_async(url.as_str()).await?;
        let (mut sink, mut stream) = ws.split();
        let (out, mut out_rx) = mpsc::unbounded_channel::<Message>();
        tokio::spawn(async move {
            while let Some(m) = out_rx.recv().await {
                if sink.send(m).await.is_err() {
                    break;
                }
            }
        });
        let pending: Pending = Arc::default();
        let sessions: Sessions = Arc::default();
        let (p, s) = (pending.clone(), sessions.clone());
        tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                let Message::Text(text) = msg else { continue };
                let Ok(v) = serde_json::from_str::<Value>(text.as_str()) else {
                    continue;
                };
                if let Some(id) = v.get("id").and_then(Value::as_u64) {
                    if let Some(tx) = p.lock().ok().and_then(|mut m| m.remove(&id)) {
                        let _ = tx.send(v);
                    }
                    continue;
                }
                let Some(sid) = v.get("sessionId").and_then(Value::as_str) else {
                    continue;
                };
                let Ok(mut map) = s.lock() else { continue };
                let Some(tx) = map.get(sid).cloned() else {
                    continue;
                };
                if v.get("method").and_then(Value::as_str) == Some("Target.attachedToTarget")
                    && let Some(child) = v.pointer("/params/sessionId").and_then(Value::as_str)
                {
                    map.insert(child.to_string(), tx.clone());
                }
                drop(map);
                let _ = tx.send(v);
            }
        });
        Ok(Self {
            child,
            profile: profile.to_path_buf(),
            out,
            pending,
            sessions,
            next: AtomicU64::new(1),
        })
    }

    pub async fn call(&self, session: Option<&str>, method: &str, params: Value) -> Result<Value> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut msg = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .map_err(|_| anyhow!("cdp lock"))?
            .insert(id, tx);
        self.out
            .send(Message::Text(msg.to_string().into()))
            .map_err(|_| anyhow!("cdp socket closed"))?;
        let v = tokio::time::timeout(CALL_LIMIT, rx)
            .await
            .map_err(|_| anyhow!("{method} timed out"))??;
        if let Some(e) = v.get("error") {
            bail!("{method}: {e}");
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    pub fn notify(&self, session: &str, method: &str, params: &Value) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let msg = json!({ "id": id, "method": method, "params": params, "sessionId": session });
        let _ = self.out.send(Message::Text(msg.to_string().into()));
    }

    pub fn subscribe(&self, session: &str) -> mpsc::UnboundedReceiver<Value> {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut m) = self.sessions.lock() {
            m.insert(session.to_string(), tx);
        }
        rx
    }

    pub fn forget(&self, session: &str) {
        if let Ok(mut m) = self.sessions.lock() {
            m.retain(|k, v| k != session && !v.is_closed());
        }
    }

    pub async fn close(mut self) {
        let _ = self.call(None, "Browser.close", json!({})).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
        let _ = self.child.kill().await;
        let _ = tokio::fs::remove_dir_all(&self.profile).await;
    }
}

pub struct Display {
    child: Child,
    pub name: String,
}

impl Display {
    pub async fn start(number: u32, width: u32, height: u32) -> Result<Self> {
        let name = format!(":{number}");
        let child = Command::new("Xvfb")
            .arg(&name)
            .args([
                "-screen",
                "0",
                &format!("{width}x{height}x24"),
                "-nolisten",
                "tcp",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("start Xvfb")?;
        tokio::time::sleep(Duration::from_millis(800)).await;
        Ok(Self { child, name })
    }

    pub async fn stop(mut self) {
        let _ = self.child.kill().await;
    }
}
