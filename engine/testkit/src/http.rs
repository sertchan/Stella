use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

const MAX_HEADERS: usize = 64;

#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub close: bool,
    pub delay: Duration,
}

impl Reply {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            close: false,
            delay: Duration::ZERO,
        }
    }

    pub fn ok(body: &str) -> Self {
        Self::new(200).body(body)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: impl AsRef<[u8]>) -> Self {
        self.body = body.as_ref().to_vec();
        self
    }

    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }

    pub fn delay(mut self, d: Duration) -> Self {
        self.delay = d;
        self
    }
}

#[derive(Clone)]
pub struct Site {
    routes: HashMap<String, Reply>,
    fallback: Reply,
}

impl Default for Site {
    fn default() -> Self {
        Self {
            routes: HashMap::new(),
            fallback: Reply::new(404),
        }
    }
}

impl Site {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn route(mut self, path: &str, reply: Reply) -> Self {
        self.routes.insert(path.into(), reply);
        self
    }

    pub fn fallback(mut self, reply: Reply) -> Self {
        self.fallback = reply;
        self
    }

    fn reply(&self, path: &str) -> &Reply {
        self.routes
            .get(path)
            .or_else(|| self.routes.get(path.split('?').next().unwrap_or(path)))
            .unwrap_or(&self.fallback)
    }
}

#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
}

pub struct Http {
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<Seen>>>,
    task: JoinHandle<()>,
}

impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Http {
    pub async fn plain(site: Site) -> Result<Self> {
        Self::start(site, None).await
    }

    pub async fn tls(site: Site, names: &[&str]) -> Result<Self> {
        let key = rcgen::generate_simple_self_signed(
            names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>(),
        )?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![key.cert.der().clone()], der)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self::start(site, Some(TlsAcceptor::from(Arc::new(cfg)))).await
    }

    async fn start(site: Site, tls: Option<TlsAcceptor>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let log = Arc::new(Mutex::new(Vec::new()));
        let site = Arc::new(site);
        let l = log.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let site = site.clone();
                let log = l.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            if let Ok(s) = acceptor.accept(stream).await {
                                serve(s, &site, &log).await;
                            }
                        }
                        None => serve(stream, &site, &log).await,
                    }
                });
            }
        });
        Ok(Self { addr, log, task })
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

fn parse(buf: &[u8]) -> Result<Option<(usize, Seen, bool)>> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let httparse::Status::Complete(n) = req.parse(buf)? else {
        return Ok(None);
    };
    let headers: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    let get = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let close = get("connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    let seen = Seen {
        method: req.method.ok_or_else(|| anyhow!("no method"))?.to_string(),
        path: req.path.ok_or_else(|| anyhow!("no path"))?.to_string(),
        host: get("host").unwrap_or_default(),
        headers,
    };
    Ok(Some((n, seen, close)))
}

fn render(r: &Reply, close: bool) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {} X\r\n", r.status).into_bytes();
    for (k, v) in &r.headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", r.body.len()).as_bytes());
    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&r.body);
    out
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, site: &Site, log: &Mutex<Vec<Seen>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let Ok(parsed) = parse(&buf) else {
            return;
        };
        let Some((n, seen, asked_close)) = parsed else {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(k) => buf.extend_from_slice(&chunk[..k]),
            }
            continue;
        };
        buf.drain(..n);
        let reply = site.reply(&seen.path).clone();
        if let Ok(mut l) = log.lock() {
            l.push(seen);
        }
        if !reply.delay.is_zero() {
            tokio::time::sleep(reply.delay).await;
        }
        let close = asked_close || reply.close;
        if s.write_all(&render(&reply, close)).await.is_err() || close {
            let _ = s.shutdown().await;
            return;
        }
    }
}
