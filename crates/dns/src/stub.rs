use crate::chase;
use crate::wire::{self, Message};
use anyhow::Result;
use rustc_hash::FxHashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

pub struct Stub {
    sock: UdpSocket,
    id: u16,
    buf: Vec<u8>,
    rx: Vec<u8>,
}

impl Stub {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            sock: UdpSocket::bind("0.0.0.0:0").await?,
            id: stella_core::rng::Rng::seeded().next_u64() as u16,
            buf: Vec::with_capacity(512),
            rx: vec![0u8; 4096],
        })
    }

    pub async fn ask(
        &mut self,
        server: SocketAddr,
        name: &str,
        qtype: u16,
        rd: bool,
        dnssec: bool,
        timeout: Duration,
    ) -> Option<Message> {
        self.id = self.id.wrapping_add(1);
        if !wire::encode_query(&mut self.buf, self.id, name, qtype, rd, dnssec) {
            return None;
        }
        self.sock.send_to(&self.buf, server).await.ok()?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (n, from) = tokio::time::timeout_at(deadline, self.sock.recv_from(&mut self.rx))
                .await
                .ok()?
                .ok()?;
            if from != server {
                continue;
            }
            if let Some(m) = wire::parse(&self.rx[..n])
                && m.id == self.id
            {
                return Some(m);
            }
        }
    }
}

static CACHE: LazyLock<Mutex<FxHashMap<String, Vec<Ipv4Addr>>>> =
    LazyLock::new(|| Mutex::new(FxHashMap::default()));

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const LOOKUP_TRIES: usize = 4;

pub async fn lookup_a(name: &str) -> Vec<Ipv4Addr> {
    lookup_a_with(&stella_core::config::resolvers(), name).await
}

pub async fn lookup_a_with(servers: &[SocketAddr], name: &str) -> Vec<Ipv4Addr> {
    let key = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(v) = CACHE.lock().ok().and_then(|c| c.get(&key).cloned()) {
        return v;
    }
    if servers.is_empty() {
        return Vec::new();
    }
    let Ok(mut stub) = Stub::new().await else {
        return Vec::new();
    };
    let mut target = key.clone();
    for attempt in 0..LOOKUP_TRIES * 2 {
        let server = servers[attempt % servers.len()];
        let Some(m) = stub
            .ask(server, &target, wire::A, true, false, LOOKUP_TIMEOUT)
            .await
        else {
            continue;
        };
        if m.rcode != wire::NOERROR {
            if m.rcode == wire::NXDOMAIN {
                break;
            }
            continue;
        }
        let (chain, addrs) = chase::follow(&m, &target);
        if !addrs.is_empty() {
            if let Ok(mut c) = CACHE.lock() {
                c.insert(key, addrs.clone());
            }
            return addrs;
        }
        match chain.last() {
            Some(t) => target.clone_from(t),
            None => break,
        }
    }
    Vec::new()
}
