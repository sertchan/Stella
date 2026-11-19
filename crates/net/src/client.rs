use anyhow::{Result, anyhow, bail};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::HeaderMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

struct OwnResolver;

impl Resolve for OwnResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = stella_dns::stub::lookup_a(&host).await;
            if addrs.is_empty() {
                return Err(format!("no address for {host}").into());
            }
            let it: Addrs = Box::new(addrs.into_iter().map(|a| SocketAddr::from((a, 0))));
            Ok(it)
        })
    }
}

pub struct Options {
    pub timeout: Duration,
    pub redirects: usize,
    pub insecure: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            redirects: 5,
            insecure: false,
        }
    }
}

pub fn build(opts: &Options) -> Result<reqwest::Client> {
    crate::install_crypto();
    Ok(reqwest::Client::builder()
        .user_agent(stella_core::config::USER_AGENT)
        .dns_resolver(Arc::new(OwnResolver))
        .connect_timeout(Duration::from_secs(5))
        .timeout(opts.timeout)
        .redirect(reqwest::redirect::Policy::limited(opts.redirects))
        .tls_danger_accept_invalid_certs(opts.insecure)
        .pool_max_idle_per_host(32)
        .build()?)
}

pub struct Page {
    pub status: u16,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

const DPI_TRIES: usize = 5;
const DPI_PAUSE: Duration = Duration::from_millis(600);

pub async fn fetch(client: &reqwest::Client, url: &str, cap: usize) -> Result<Page> {
    let mut last = anyhow!("no attempt");
    for _ in 0..DPI_TRIES {
        match client.get(url).send().await {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                let final_url = resp.url().to_string();
                let headers = resp.headers().clone();
                let mut body = Vec::new();
                while body.len() < cap {
                    match resp.chunk().await {
                        Ok(Some(c)) => body.extend_from_slice(&c[..c.len().min(cap - body.len())]),
                        Ok(None) | Err(_) => break,
                    }
                }
                return Ok(Page {
                    status,
                    url: final_url,
                    headers,
                    body,
                });
            }
            Err(e) => {
                let retry = e.is_connect();
                last = e.into();
                if !retry {
                    break;
                }
                tokio::time::sleep(DPI_PAUSE).await;
            }
        }
    }
    Err(last)
}

pub async fn download(client: &reqwest::Client, url: &str, path: &Path, cap: u64) -> Result<u64> {
    let mut last = anyhow!("no attempt");
    for _ in 0..DPI_TRIES {
        let mut resp = match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                last = e.into();
                tokio::time::sleep(DPI_PAUSE).await;
                continue;
            }
        };
        if !resp.status().is_success() {
            bail!("{url}: status {}", resp.status());
        }
        let part = path.with_extension("part");
        let mut file = tokio::fs::File::create(&part).await?;
        let mut n = 0u64;
        let mut broken = false;
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    n += c.len() as u64;
                    if n > cap {
                        bail!("{url}: larger than {cap} bytes");
                    }
                    file.write_all(&c).await?;
                }
                Ok(None) => break,
                Err(e) => {
                    last = e.into();
                    broken = true;
                    break;
                }
            }
        }
        file.flush().await?;
        drop(file);
        if broken {
            tokio::time::sleep(DPI_PAUSE).await;
            continue;
        }
        tokio::fs::rename(&part, path).await?;
        return Ok(n);
    }
    Err(last)
}
