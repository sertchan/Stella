use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use stella_net::http::{Conn, Resp};
use stella_net::limit::Limiter;
use stella_net::tls;
use tokio::task::JoinSet;

pub const RANDOM: &str = "?random";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Battery {
    Lite,
    Full,
}

const LITE: &[&str] = &["/", "/healthy", "/i", RANDOM];
const FULL_EXTRA: &[&str] = &[
    "/matomo.js",
    "/js/script.js",
    "/script.js",
    "/static/array.js",
    "/p.js",
    "/lib.min.js",
    "/health",
];

impl Battery {
    pub fn paths(self) -> Vec<&'static str> {
        match self {
            Self::Lite => LITE.to_vec(),
            Self::Full => LITE.iter().chain(FULL_EXTRA).copied().collect(),
        }
    }
}

pub struct HostProbe {
    pub host: String,
    pub ip: IpAddr,
    pub results: Vec<(&'static str, Option<Resp>)>,
    pub sans: Vec<String>,
}

impl HostProbe {
    pub fn get(&self, path: &str) -> Option<&Resp> {
        self.results
            .iter()
            .find(|(p, _)| *p == path)
            .and_then(|(_, r)| r.as_ref())
    }

    pub fn answered(&self) -> bool {
        self.results.iter().any(|(_, r)| r.is_some())
    }
}

#[derive(Clone)]
pub struct Prober {
    connector: tokio_rustls::TlsConnector,
    limiter: Arc<Limiter>,
    pub timeout: Duration,
    pub tries: usize,
    pub cap: usize,
}

const DPI_PAUSE: Duration = Duration::from_millis(600);
const PATH_TRIES: usize = 2;

impl Prober {
    pub fn new(limiter: Arc<Limiter>) -> Self {
        stella_net::install_crypto();
        Self {
            connector: tls::insecure_connector(),
            limiter,
            timeout: Duration::from_secs(6),
            tries: 5,
            cap: 64 * 1024,
        }
    }

    pub async fn probe(&self, host: &str, ip: IpAddr, battery: Battery) -> HostProbe {
        let mut rng = stella_core::rng::Rng::seeded();
        let random_path = format!("/{}", rng.label());
        let paths = battery.paths();
        let mut results: Vec<(&'static str, Option<Resp>)> =
            paths.iter().map(|p| (*p, None)).collect();
        let mut sans = Vec::new();
        let mut next = 0usize;
        let mut connect_fails = 0usize;
        let mut path_fails = 0usize;
        while next < paths.len() && connect_fails < self.tries {
            let Some(permit) = self.limiter.slot().await else {
                break;
            };
            match tls::connect(&self.connector, host, ip, self.timeout).await {
                Ok(stream) => {
                    connect_fails = 0;
                    if sans.is_empty() {
                        sans = tls::sans(&stream);
                    }
                    let mut conn = Conn::new(stream);
                    while next < paths.len() {
                        let path = if paths[next] == RANDOM {
                            random_path.as_str()
                        } else {
                            paths[next]
                        };
                        let got = tokio::time::timeout(
                            self.timeout,
                            conn.get(host, path, stella_core::config::USER_AGENT, self.cap),
                        )
                        .await;
                        match got {
                            Ok(Ok(r)) => {
                                let close = r.close;
                                results[next].1 = Some(r);
                                next += 1;
                                path_fails = 0;
                                if close {
                                    break;
                                }
                            }
                            _ => {
                                path_fails += 1;
                                if path_fails >= PATH_TRIES {
                                    next += 1;
                                    path_fails = 0;
                                }
                                break;
                            }
                        }
                    }
                }
                Err(_) => connect_fails += 1,
            }
            drop(permit);
            if next < paths.len() && connect_fails > 0 {
                tokio::time::sleep(DPI_PAUSE).await;
            }
        }
        HostProbe {
            host: host.to_string(),
            ip,
            results,
            sans,
        }
    }
}

pub async fn probe_all(
    prober: &Prober,
    items: Vec<(String, IpAddr, Battery)>,
    concurrency: usize,
    mut on_result: impl FnMut(HostProbe),
) {
    let mut set = JoinSet::new();
    let mut it = items.into_iter();
    loop {
        while set.len() < concurrency.max(1) {
            let Some((host, ip, battery)) = it.next() else {
                break;
            };
            let p = prober.clone();
            set.spawn(async move { p.probe(&host, ip, battery).await });
        }
        match set.join_next().await {
            Some(Ok(r)) => on_result(r),
            Some(Err(_)) => {}
            None => break,
        }
    }
}

pub fn head(body: &[u8], n: usize) -> String {
    let s = String::from_utf8_lossy(&body[..body.len().min(n * 2)]);
    let mut out = String::with_capacity(n);
    let mut space = false;
    for c in s.chars() {
        if out.len() >= n {
            break;
        }
        if c.is_whitespace() {
            if !space {
                out.push(' ');
            }
            space = true;
        } else if !c.is_control() {
            out.push(c);
            space = false;
        }
    }
    out
}
