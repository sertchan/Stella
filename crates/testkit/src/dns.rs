use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

pub const A: u16 = 1;
pub const NS: u16 = 2;
pub const CNAME: u16 = 5;
pub const SOA: u16 = 6;
pub const TXT: u16 = 16;
pub const AAAA: u16 = 28;
pub const OPT: u16 = 41;
pub const NSEC: u16 = 47;
pub const HTTPS: u16 = 65;
pub const AXFR: u16 = 252;

pub const NOERROR: u8 = 0;
pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;
pub const REFUSED: u8 = 5;

const ECS_OPTION: u16 = 8;
const BIND_TRIES: usize = 32;

#[derive(Clone, Debug)]
pub enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Soa(String, String),
    Txt(Vec<String>),
    Nsec(String),
    Https(u16, String, Vec<String>),
}

impl Data {
    fn rtype(&self) -> u16 {
        match self {
            Data::A(_) => A,
            Data::Aaaa(_) => AAAA,
            Data::Cname(_) => CNAME,
            Data::Ns(_) => NS,
            Data::Soa(..) => SOA,
            Data::Txt(_) => TXT,
            Data::Nsec(_) => NSEC,
            Data::Https(..) => HTTPS,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rr {
    pub owner: String,
    pub data: Data,
}

pub fn rr(owner: &str, data: Data) -> Rr {
    Rr {
        owner: owner.to_ascii_lowercase(),
        data,
    }
}

pub fn a(owner: &str, ip: [u8; 4]) -> Rr {
    rr(owner, Data::A(Ipv4Addr::from(ip)))
}

pub fn cname(owner: &str, target: &str) -> Rr {
    rr(owner, Data::Cname(target.into()))
}

pub fn ns(owner: &str, target: &str) -> Rr {
    rr(owner, Data::Ns(target.into()))
}

pub fn soa(owner: &str, mname: &str, rname: &str) -> Rr {
    rr(owner, Data::Soa(mname.into(), rname.into()))
}

pub fn nsec(owner: &str, next: &str) -> Rr {
    rr(owner, Data::Nsec(next.into()))
}

#[derive(Clone, Debug, Default)]
pub struct Answer {
    pub rcode: u8,
    pub answers: Vec<Rr>,
    pub authority: Vec<Rr>,
}

impl Answer {
    pub fn records(answers: Vec<Rr>) -> Self {
        Self {
            rcode: NOERROR,
            answers,
            authority: Vec::new(),
        }
    }

    pub fn rcode(rcode: u8) -> Self {
        Self {
            rcode,
            ..Self::default()
        }
    }

    pub fn authority(mut self, rrs: Vec<Rr>) -> Self {
        self.authority = rrs;
        self
    }
}

type Key = (String, u16, Option<[u8; 3]>);

#[derive(Clone, Default)]
pub struct Zone {
    answers: HashMap<Key, Answer>,
    silent: HashSet<String>,
    failures: HashMap<String, usize>,
    transfers: HashMap<String, Vec<Rr>>,
}

impl Zone {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn answer(mut self, name: &str, qtype: u16, answer: Answer) -> Self {
        self.answers
            .insert((name.to_ascii_lowercase(), qtype, None), answer);
        self
    }

    pub fn subnet(mut self, name: &str, qtype: u16, subnet: [u8; 3], answer: Answer) -> Self {
        self.answers
            .insert((name.to_ascii_lowercase(), qtype, Some(subnet)), answer);
        self
    }

    pub fn record(mut self, rr: Rr) -> Self {
        let key = (rr.owner.clone(), rr.data.rtype(), None);
        self.answers
            .entry(key)
            .or_insert_with(|| Answer::records(Vec::new()))
            .answers
            .push(rr);
        self
    }

    pub fn silent(mut self, name: &str) -> Self {
        self.silent.insert(name.to_ascii_lowercase());
        self
    }

    pub fn failing(mut self, name: &str, times: usize) -> Self {
        self.failures.insert(name.to_ascii_lowercase(), times);
        self
    }

    pub fn transfer(mut self, zone: &str, rrs: Vec<Rr>) -> Self {
        self.transfers.insert(zone.to_ascii_lowercase(), rrs);
        self
    }

    fn lookup(&self, name: &str, qtype: u16, subnet: Option<[u8; 3]>) -> Answer {
        let exact = subnet
            .and_then(|s| self.answers.get(&(name.to_string(), qtype, Some(s))))
            .or_else(|| self.answers.get(&(name.to_string(), qtype, None)));
        if let Some(a) = exact {
            return a.clone();
        }
        let mut rest = name;
        while let Some((_, parent)) = rest.split_once('.') {
            let wild = format!("*.{parent}");
            if let Some(a) = self.answers.get(&(wild.clone(), qtype, None)) {
                let mut a = a.clone();
                for r in &mut a.answers {
                    if r.owner == wild {
                        r.owner = name.to_string();
                    }
                }
                return a;
            }
            rest = parent;
        }
        Answer::rcode(NXDOMAIN)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Asked {
    pub name: String,
    pub qtype: u16,
    pub rd: bool,
    pub dnssec: bool,
    pub subnet: Option<[u8; 3]>,
    pub tcp: bool,
}

struct Query {
    id: u16,
    rd: bool,
    question: Vec<u8>,
    asked: Asked,
}

pub struct Dns {
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<Asked>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Dns {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

struct State {
    zone: Zone,
    failures: Mutex<HashMap<String, usize>>,
    log: Arc<Mutex<Vec<Asked>>>,
}

impl Dns {
    pub async fn start(zone: Zone) -> Result<Self> {
        let (udp, tcp) = bind_pair().await?;
        let addr = udp.local_addr()?;
        let log = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(State {
            failures: Mutex::new(zone.failures.clone()),
            zone,
            log: log.clone(),
        });
        let s = state.clone();
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = udp.recv_from(&mut buf).await {
                if let Some(reply) = s.reply(&buf[..n], false) {
                    let _ = udp.send_to(&reply, from).await;
                }
            }
        });
        let s = state.clone();
        let tcp_task = tokio::spawn(async move {
            while let Ok((stream, _)) = tcp.accept().await {
                let s = s.clone();
                tokio::spawn(async move { s.serve_tcp(stream).await });
            }
        });
        Ok(Self {
            addr,
            log,
            tasks: vec![udp_task, tcp_task],
        })
    }

    pub fn asked(&self) -> Vec<Asked> {
        self.log.lock().map(|l| l.clone()).unwrap_or_default()
    }
}

async fn bind_pair() -> Result<(UdpSocket, TcpListener)> {
    for _ in 0..BIND_TRIES {
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        if let Ok(tcp) = TcpListener::bind(udp.local_addr()?).await {
            return Ok((udp, tcp));
        }
    }
    bail!("no free port for both udp and tcp")
}

impl State {
    fn reply(&self, packet: &[u8], tcp: bool) -> Option<Vec<u8>> {
        let q = parse_query(packet, tcp)?;
        if let Ok(mut l) = self.log.lock() {
            l.push(q.asked.clone());
        }
        let name = q.asked.name.clone();
        if self.zone.silent.contains(&name) {
            return None;
        }
        if let Ok(mut f) = self.failures.lock()
            && let Some(left) = f.get_mut(&name)
            && *left > 0
        {
            *left -= 1;
            return Some(encode(&q, &Answer::rcode(SERVFAIL)));
        }
        let answer = self.zone.lookup(&name, q.asked.qtype, q.asked.subnet);
        Some(encode(&q, &answer))
    }

    async fn serve_tcp(&self, mut stream: TcpStream) {
        let mut buf = Vec::new();
        loop {
            let Ok(len) = stream.read_u16().await else {
                return;
            };
            buf.resize(usize::from(len), 0);
            if stream.read_exact(&mut buf).await.is_err() {
                return;
            }
            let Some(q) = parse_query(&buf, true) else {
                return;
            };
            let messages = if q.asked.qtype == AXFR {
                if let Ok(mut l) = self.log.lock() {
                    l.push(q.asked.clone());
                }
                match self.zone.transfers.get(&q.asked.name) {
                    Some(rrs) => rrs
                        .chunks(2)
                        .map(|c| encode(&q, &Answer::records(c.to_vec())))
                        .collect(),
                    None => vec![encode(&q, &Answer::rcode(REFUSED))],
                }
            } else {
                self.reply(&buf, true).into_iter().collect()
            };
            for m in messages {
                let mut framed = (m.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&m);
                if stream.write_all(&framed).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn parse_query(b: &[u8], tcp: bool) -> Option<Query> {
    let id = u16_at(b, 0)?;
    let flags = u16_at(b, 2)?;
    let ar = u16_at(b, 10)?;
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*b.get(pos)?);
        pos += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(b.get(pos..pos + len)?).to_ascii_lowercase());
        pos += len;
    }
    let qtype = u16_at(b, pos)?;
    let question = b.get(12..pos + 4)?.to_vec();
    pos += 4;
    let mut dnssec = false;
    let mut subnet = None;
    for _ in 0..ar {
        if *b.get(pos)? != 0 {
            break;
        }
        let rtype = u16_at(b, pos + 1)?;
        let ttl_flags = u16_at(b, pos + 7)?;
        let rdlen = usize::from(u16_at(b, pos + 9)?);
        let rdata = b.get(pos + 11..pos + 11 + rdlen)?;
        if rtype == OPT {
            dnssec = ttl_flags & 0x8000 != 0;
            let mut o = 0;
            while o + 4 <= rdata.len() {
                let code = u16_at(rdata, o)?;
                let len = usize::from(u16_at(rdata, o + 2)?);
                let val = rdata.get(o + 4..o + 4 + len)?;
                if code == ECS_OPTION && val.len() >= 7 {
                    subnet = Some([val[4], val[5], val[6]]);
                }
                o += 4 + len;
            }
        }
        pos += 11 + rdlen;
    }
    Some(Query {
        id,
        rd: flags & 0x0100 != 0,
        question,
        asked: Asked {
            name: labels.join("."),
            qtype,
            rd: flags & 0x0100 != 0,
            dnssec,
            subnet,
            tcp,
        },
    })
}

fn push_name(out: &mut Vec<u8>, name: &str) {
    for l in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        if l == "\\000" {
            out.push(1);
            out.push(0);
            continue;
        }
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
}

fn rdata(d: &Data) -> Vec<u8> {
    let mut o = Vec::new();
    match d {
        Data::A(ip) => o.extend_from_slice(&ip.octets()),
        Data::Aaaa(ip) => o.extend_from_slice(&ip.octets()),
        Data::Cname(n) | Data::Ns(n) => push_name(&mut o, n),
        Data::Soa(m, r) => {
            push_name(&mut o, m);
            push_name(&mut o, r);
            for v in [1u32, 7200, 3600, 1_209_600, 300] {
                o.extend_from_slice(&v.to_be_bytes());
            }
        }
        Data::Txt(parts) => {
            for p in parts {
                o.push(p.len() as u8);
                o.extend_from_slice(p.as_bytes());
            }
        }
        Data::Nsec(next) => {
            push_name(&mut o, next);
            o.extend_from_slice(&[0, 1, 0x40]);
        }
        Data::Https(priority, target, alpn) => {
            o.extend_from_slice(&priority.to_be_bytes());
            push_name(&mut o, target);
            if !alpn.is_empty() {
                let mut v = Vec::new();
                for a in alpn {
                    v.push(a.len() as u8);
                    v.extend_from_slice(a.as_bytes());
                }
                o.extend_from_slice(&1u16.to_be_bytes());
                o.extend_from_slice(&(v.len() as u16).to_be_bytes());
                o.extend_from_slice(&v);
            }
        }
    }
    o
}

fn push_rr(out: &mut Vec<u8>, r: &Rr) {
    push_name(out, &r.owner);
    out.extend_from_slice(&r.data.rtype().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&60u32.to_be_bytes());
    let d = rdata(&r.data);
    out.extend_from_slice(&(d.len() as u16).to_be_bytes());
    out.extend_from_slice(&d);
}

fn encode(q: &Query, a: &Answer) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&q.id.to_be_bytes());
    let flags = 0x8000u16 | 0x0080 | if q.rd { 0x0100 } else { 0 } | u16::from(a.rcode);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(a.answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(a.authority.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&q.question);
    for r in a.answers.iter().chain(&a.authority) {
        push_rr(&mut out, r);
    }
    out
}
