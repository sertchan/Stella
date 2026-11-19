use crate::wire::{self, Message};
use anyhow::Result;
use rustc_hash::FxHashMap;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

#[derive(Clone)]
pub struct Config {
    pub servers: Vec<SocketAddr>,
    pub qps: u32,
    pub timeout: Duration,
    pub tries: u8,
    pub sockets: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            servers: stella_core::config::resolvers(),
            qps: 2000,
            timeout: Duration::from_millis(2500),
            tries: 4,
            sockets: 8,
        }
    }
}

#[derive(Clone)]
pub struct Query {
    pub name: String,
    pub qtype: u16,
    pub server: Option<SocketAddr>,
    pub rd: bool,
    pub dnssec: bool,
}

impl Query {
    pub fn recursive(name: String, qtype: u16) -> Self {
        Self {
            name,
            qtype,
            server: None,
            rd: true,
            dnssec: false,
        }
    }
}

pub struct Reply<'a> {
    pub query: &'a Query,
    pub msg: Option<Message>,
}

struct Pending {
    qi: usize,
    attempt: u8,
    deadline: Instant,
}

const TICK: Duration = Duration::from_millis(10);
const TICKS_PER_SECOND: u32 = 100;

pub async fn run(cfg: &Config, queries: &[Query], mut on_reply: impl FnMut(Reply)) -> Result<()> {
    if queries.is_empty() {
        return Ok(());
    }
    let sockets = cfg.sockets.max(1);
    let (tx, mut rx) = mpsc::channel::<(usize, Vec<u8>)>(65_536);
    let mut socks = Vec::with_capacity(sockets);
    let mut readers = Vec::with_capacity(sockets);
    for i in 0..sockets {
        let s = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let r = s.clone();
        let tx = tx.clone();
        readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, _)) = r.recv_from(&mut buf).await {
                if tx.send((i, buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
        }));
        socks.push(s);
    }
    drop(tx);

    let mut queue: VecDeque<(usize, u8)> = (0..queries.len()).map(|i| (i, 0)).collect();
    let mut pending: FxHashMap<(usize, u16), Pending> = FxHashMap::default();
    let mut deadlines: BinaryHeap<Reverse<(Instant, usize, u16)>> = BinaryHeap::new();
    let mut next_id = vec![0u16; sockets];
    let mut outstanding = queries.len();
    let mut rr = 0usize;
    let mut sock_rr = 0usize;
    let mut credit = 0f64;
    let per_tick = f64::from(cfg.qps.max(1)) / f64::from(TICKS_PER_SECOND);
    let max_inflight =
        (cfg.qps as usize * cfg.timeout.as_secs().max(1) as usize * 2).clamp(256, sockets * 60_000);
    let mut buf = Vec::with_capacity(512);
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    while outstanding > 0 {
        tokio::select! {
            got = rx.recv() => {
                let Some((si, data)) = got else { break };
                let Some(msg) = wire::parse(&data) else { continue };
                let Some(p) = pending.remove(&(si, msg.id)) else { continue };
                let q = &queries[p.qi];
                if !msg.qname.eq_ignore_ascii_case(q.name.trim_end_matches('.')) || msg.qtype != q.qtype {
                    pending.insert((si, msg.id), p);
                    continue;
                }
                let retry = matches!(msg.rcode, wire::SERVFAIL | wire::REFUSED) && p.attempt + 1 < cfg.tries;
                if retry {
                    queue.push_front((p.qi, p.attempt + 1));
                } else {
                    outstanding -= 1;
                    on_reply(Reply { query: q, msg: Some(msg) });
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                while let Some(Reverse((at, si, id))) = deadlines.peek().copied() {
                    if at > now {
                        break;
                    }
                    deadlines.pop();
                    let expired = pending.get(&(si, id)).is_some_and(|p| p.deadline == at);
                    if !expired {
                        continue;
                    }
                    let Some(p) = pending.remove(&(si, id)) else { continue };
                    if p.attempt + 1 < cfg.tries {
                        queue.push_front((p.qi, p.attempt + 1));
                    } else {
                        outstanding -= 1;
                        on_reply(Reply { query: &queries[p.qi], msg: None });
                    }
                }
                credit = (credit + per_tick).min(per_tick * 4.0 + 1.0);
                while credit >= 1.0 && pending.len() < max_inflight {
                    let Some((qi, attempt)) = queue.pop_front() else { break };
                    let q = &queries[qi];
                    let server = q.server.unwrap_or_else(|| {
                        rr = rr.wrapping_add(1);
                        cfg.servers[rr % cfg.servers.len()]
                    });
                    sock_rr = (sock_rr + 1) % sockets;
                    let si = sock_rr;
                    let mut id = next_id[si];
                    let mut guard = 0;
                    while pending.contains_key(&(si, id)) && guard < 65_536 {
                        id = id.wrapping_add(1);
                        guard += 1;
                    }
                    next_id[si] = id.wrapping_add(1);
                    if !wire::encode_query(&mut buf, id, &q.name, q.qtype, q.rd, q.dnssec) {
                        outstanding -= 1;
                        on_reply(Reply { query: q, msg: None });
                        continue;
                    }
                    match socks[si].try_send_to(&buf, server) {
                        Ok(_) => {
                            credit -= 1.0;
                            let deadline = now + cfg.timeout;
                            pending.insert((si, id), Pending { qi, attempt, deadline });
                            deadlines.push(Reverse((deadline, si, id)));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            queue.push_front((qi, attempt));
                            break;
                        }
                        Err(_) => {
                            if attempt + 1 < cfg.tries {
                                queue.push_back((qi, attempt + 1));
                            } else {
                                outstanding -= 1;
                                on_reply(Reply { query: q, msg: None });
                            }
                        }
                    }
                }
            }
        }
    }
    for r in readers {
        r.abort();
    }
    Ok(())
}
