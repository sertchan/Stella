use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use stella_core::progress::{self, Progress};
use stella_net::http::{Conn, Resp};
use stella_net::limit::Limiter;
use stella_net::tls::{self, Fail};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;

pub const RANDOM: &str = "?random";
pub const FOLLOWED: &str = "/@followed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Battery {
    Lite,
    Staged { tracking: bool },
    Full,
}

pub const LITE: &[&str] = &["/", "/healthy", "/i", RANDOM];
pub const FULL_EXTRA: &[&str] = &[
    "/matomo.js",
    "/js/script.js",
    "/script.js",
    "/static/array.js",
    "/p.js",
    "/lib.min.js",
    "/health",
];

pub struct HostProbe {
    pub host: String,
    pub ip: IpAddr,
    pub results: Vec<(&'static str, Option<Resp>)>,
    pub sans: Vec<String>,
    pub tls: String,
    pub fails: Vec<Fail>,
    pub requests: usize,
    pub elapsed: Duration,
    pub sequential: bool,
    pub connects: usize,
    pub plain_http: bool,
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
    pub tcp_timeout: Duration,
    pub tls_timeout: Duration,
    pub budget: Duration,
    pub cap: usize,
    pub tls_port: u16,
    pub plain_port: u16,
}

const DPI_PAUSE: Duration = Duration::from_millis(600);
const PATH_TRIES: usize = 2;
const PIPELINE_STEP: Duration = Duration::from_millis(1500);
const SCRIPT_WAIT: Duration = Duration::from_secs(4);
const SILENT_TIMEOUTS: usize = 2;
const SPREAD: usize = 3;
const PLAIN_PORT: u16 = 80;

struct Session<'a> {
    prober: &'a Prober,
    host: &'a str,
    ip: IpAddr,
    deadline: Instant,
    conn: Option<(Conn<TlsStream<TcpStream>>, OwnedSemaphorePermit)>,
    sans: Vec<String>,
    print: String,
    fails: Vec<Fail>,
    requests: usize,
    dead: bool,
    timeouts: usize,
    connects: usize,
    sequential: bool,
}

impl<'a> Session<'a> {
    fn left(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    async fn open(&mut self) -> bool {
        while !self.dead {
            let Some(permit) = self.prober.limiter.slot().await else {
                self.dead = true;
                break;
            };
            let left = self.left();
            if left.is_zero() {
                self.dead = true;
                break;
            }
            let tcp = self.prober.tcp_timeout.min(left);
            let handshake = self.prober.tls_timeout.min(left);
            let hs = self.prober.limiter.handshake().await;
            let connected = tls::connect(
                &self.prober.connector,
                self.host,
                std::net::SocketAddr::new(self.ip, self.prober.tls_port),
                tcp,
                handshake,
            )
            .await;
            drop(hs);
            match connected {
                Ok(stream) => {
                    if self.sans.is_empty() {
                        self.sans = tls::sans(&stream);
                    }
                    if self.print.is_empty() {
                        self.print = tls::print(&stream);
                    }
                    self.conn = Some((Conn::new(stream), permit));
                    self.connects += 1;
                    return true;
                }
                Err(f) => {
                    drop(permit);
                    self.fails.push(f);
                    let seen = self.fails.iter().filter(|x| **x == f).count();
                    if seen > f.retries() {
                        self.dead = true;
                        break;
                    }
                    tokio::time::sleep(DPI_PAUSE.min(self.left())).await;
                }
            }
        }
        false
    }

    async fn fetch_many(
        &mut self,
        paths: &[&str],
        first_wait: Duration,
    ) -> (Vec<Option<Resp>>, usize) {
        let pipelining = !self.sequential;
        let mut out: Vec<Option<Resp>> = (0..paths.len()).map(|_| None).collect();
        let mut next = 0usize;
        let mut stalls = 0usize;
        let ua = stella_core::config::USER_AGENT;
        while next < paths.len() && stalls < PATH_TRIES && !self.dead {
            if self.conn.is_none() && !self.open().await {
                break;
            }
            let batch_len = if self.sequential {
                1
            } else {
                paths.len() - next
            };
            let batch = &paths[next..next + batch_len];
            let left = self.left();
            let Some((conn, _)) = self.conn.as_mut() else {
                break;
            };
            if left.is_zero()
                || tokio::time::timeout(left, conn.send_many(self.host, batch, ua))
                    .await
                    .map_or(true, |r| r.is_err())
            {
                self.conn = None;
                stalls += 1;
                continue;
            }
            let mut progressed = false;
            for i in 0..batch.len() {
                let wait = if i == 0 { first_wait } else { PIPELINE_STEP }.min(self.left());
                let Some((conn, _)) = self.conn.as_mut() else {
                    break;
                };
                match tokio::time::timeout(wait, conn.read_next(self.prober.cap)).await {
                    Ok(Ok(r)) => {
                        self.requests += 1;
                        progressed = true;
                        let close = r.close;
                        out[next] = Some(r);
                        next += 1;
                        if close {
                            self.conn = None;
                            break;
                        }
                    }
                    Ok(Err(_)) => {
                        self.conn = None;
                        if i > 0 {
                            self.sequential = true;
                        }
                        break;
                    }
                    Err(_) => {
                        self.conn = None;
                        if i == 0 {
                            self.timeouts += 1;
                            if self.requests == 0 && self.timeouts >= SILENT_TIMEOUTS {
                                self.dead = true;
                            }
                            next += 1;
                            progressed = true;
                        } else {
                            self.sequential = true;
                        }
                        break;
                    }
                }
            }
            if pipelining && self.sequential {
                return (out, next);
            }
            if progressed {
                stalls = 0;
            } else {
                stalls += 1;
            }
        }
        let done = paths.len();
        (out, done)
    }

    fn child(&self) -> Session<'a> {
        Session {
            prober: self.prober,
            host: self.host,
            ip: self.ip,
            deadline: self.deadline,
            conn: None,
            sans: Vec::new(),
            print: String::new(),
            fails: Vec::new(),
            requests: 0,
            dead: false,
            timeouts: 0,
            connects: 0,
            sequential: true,
        }
    }

    async fn fetch_all(&mut self, paths: &[&str], first_wait: Duration) -> Vec<Option<Resp>> {
        let (mut out, rest) = self.fetch_many(paths, first_wait).await;
        if rest >= paths.len() || self.dead {
            return out;
        }
        let tail = &paths[rest..];
        let k = SPREAD.min(tail.len());
        let mut idx: Vec<Vec<usize>> = vec![Vec::new(); k];
        for i in 0..tail.len() {
            idx[i % k].push(i);
        }
        let mut children: Vec<Session<'a>> = (0..k).map(|_| self.child()).collect();
        let runs = children.iter_mut().zip(idx.iter()).map(|(c, ix)| {
            let ps: Vec<&str> = ix.iter().map(|&i| tail[i]).collect();
            async move { c.fetch_many(&ps, first_wait).await.0 }
        });
        let got = futures_util::future::join_all(runs).await;
        for (ix, res) in idx.iter().zip(got) {
            for (&i, r) in ix.iter().zip(res) {
                out[rest + i] = r;
            }
        }
        for c in children {
            self.requests += c.requests;
            self.connects += c.connects;
            self.fails.extend(c.fails);
        }
        out
    }
}

impl Prober {
    pub fn new(limiter: Arc<Limiter>) -> Self {
        stella_net::install_crypto();
        Self {
            connector: tls::insecure_connector(),
            limiter,
            timeout: Duration::from_secs(6),
            tcp_timeout: Duration::from_millis(2500),
            tls_timeout: Duration::from_secs(4),
            budget: Duration::from_secs(20),
            cap: 64 * 1024,
            tls_port: tls::TLS_PORT,
            plain_port: PLAIN_PORT,
        }
    }

    pub async fn probe(&self, host: &str, ip: IpAddr, battery: Battery) -> HostProbe {
        let started = Instant::now();
        let mut rng = stella_core::rng::Rng::seeded();
        let random_path = format!("/{}", rng.label());
        let mut s = Session {
            prober: self,
            host,
            ip,
            deadline: started + self.budget,
            conn: None,
            sans: Vec::new(),
            print: String::new(),
            fails: Vec::new(),
            requests: 0,
            dead: false,
            timeouts: 0,
            connects: 0,
            sequential: false,
        };
        let mut results: Vec<(&'static str, Option<Resp>)> = Vec::new();
        let first: Vec<&'static str> = match battery {
            Battery::Full => LITE.iter().chain(FULL_EXTRA).copied().collect(),
            Battery::Lite | Battery::Staged { .. } => LITE.to_vec(),
        };
        let real: Vec<&str> = first
            .iter()
            .map(|p| {
                if *p == RANDOM {
                    random_path.as_str()
                } else {
                    p
                }
            })
            .collect();
        let got = s.fetch_all(&real, self.timeout).await;
        results.extend(first.iter().copied().zip(got));
        if let Battery::Staged { tracking } = battery
            && !s.dead
            && results.iter().any(|(_, r)| r.is_some())
        {
            let target = results
                .iter()
                .find(|(q, _)| *q == "/")
                .and_then(|(_, r)| r.as_ref())
                .filter(|r| (300..400).contains(&r.status))
                .and_then(|r| crate::rules::same_host_target(&r.location, host));
            if let Some(t) = target {
                let r = s
                    .fetch_all(&[t.as_str()], self.timeout)
                    .await
                    .pop()
                    .flatten();
                results.push((FOLLOWED, r));
            }
            let get = |p: &str| {
                results
                    .iter()
                    .find(|(q, _)| *q == p)
                    .and_then(|(_, r)| r.as_ref())
            };
            let second = crate::rules::stage_two(get("/"), get(FOLLOWED), tracking);
            if !s.dead && !second.is_empty() {
                let got = s.fetch_all(&second, SCRIPT_WAIT.min(self.timeout)).await;
                results.extend(second.iter().copied().zip(got));
            }
        }
        let tls_failed = !results.iter().any(|(_, r)| r.is_some())
            && s.fails
                .iter()
                .any(|f| matches!(f, Fail::TlsOther | Fail::TlsTimeout | Fail::TlsReset));
        let mut plain_http = false;
        if tls_failed && !s.left().is_zero() {
            let got = self.plain_http(host, ip, &real, s.left()).await;
            if got.iter().any(Option::is_some) {
                plain_http = true;
                s.connects += 1;
                s.requests += got.iter().filter(|r| r.is_some()).count();
                results = first.iter().copied().zip(got).collect();
            }
        }
        HostProbe {
            host: host.to_string(),
            ip,
            results,
            sans: std::mem::take(&mut s.sans),
            tls: std::mem::take(&mut s.print),
            fails: std::mem::take(&mut s.fails),
            requests: s.requests,
            elapsed: started.elapsed(),
            sequential: s.sequential,
            connects: s.connects,
            plain_http,
        }
    }

    async fn plain_http(
        &self,
        host: &str,
        ip: IpAddr,
        paths: &[&str],
        left: Duration,
    ) -> Vec<Option<Resp>> {
        let mut out: Vec<Option<Resp>> = Vec::with_capacity(paths.len());
        if let Some(_permit) = self.limiter.slot().await {
            let hs = self.limiter.handshake().await;
            let tcp = tokio::time::timeout(
                self.tcp_timeout.min(left),
                TcpStream::connect((ip, self.plain_port)),
            )
            .await;
            drop(hs);
            if let Ok(Ok(stream)) = tcp {
                let mut conn = Conn::new(stream);
                for p in paths {
                    let got = tokio::time::timeout(
                        self.timeout,
                        conn.get(host, p, stella_core::config::USER_AGENT, self.cap),
                    )
                    .await;
                    match got {
                        Ok(Ok(r)) => {
                            let close = r.close;
                            out.push(Some(r));
                            if close {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
        }
        out.resize_with(paths.len(), || None);
        out
    }
}

pub async fn probe_all(
    prober: &Prober,
    items: Vec<(String, IpAddr, Battery)>,
    concurrency: usize,
    mut on_result: impl FnMut(HostProbe) -> bool,
) {
    let mut progress = Progress::new("probe", items.len());
    let mut started: FxHashMap<tokio::task::Id, (String, std::time::Instant)> =
        FxHashMap::default();
    let (mut done, mut hits) = (0usize, 0usize);
    let mut tick = tokio::time::interval(progress::EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.reset();
    let mut set = JoinSet::new();
    let mut it = items.into_iter();
    loop {
        while set.len() < concurrency.max(1) {
            let Some((host, ip, battery)) = it.next() else {
                break;
            };
            let p = prober.clone();
            let name = host.clone();
            let h = set.spawn(async move { p.probe(&host, ip, battery).await });
            started.insert(h.id(), (name, std::time::Instant::now()));
        }
        tokio::select! {
            next = set.join_next_with_id() => match next {
                Some(Ok((id, r))) => {
                    started.remove(&id);
                    done += 1;
                    hits += usize::from(on_result(r));
                }
                Some(Err(e)) => {
                    started.remove(&e.id());
                    done += 1;
                }
                None => break,
            },
            _ = tick.tick() => {
                let slow = progress::slowest(
                    started.values().map(|(h, t)| (h.as_str(), *t)),
                    progress::SLOWEST,
                );
                progress.print(done, set.len(), Some(hits), &slow);
            }
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
