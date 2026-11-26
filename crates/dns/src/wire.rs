use std::net::Ipv4Addr;

pub const A: u16 = 1;
pub const NS: u16 = 2;
pub const CNAME: u16 = 5;
pub const SOA: u16 = 6;
pub const OPT: u16 = 41;
pub const NSEC: u16 = 47;
pub const AXFR: u16 = 252;

pub const NOERROR: u8 = 0;
pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;
pub const REFUSED: u8 = 5;

const EDNS_UDP_SIZE: u16 = 1232;
const EDNS_DO: u32 = 0x8000;
const MAX_POINTER_HOPS: usize = 64;
const ECS_OPTION: u16 = 8;
const ECS_FAMILY_V4: u16 = 1;
const ECS_PREFIX: u8 = 24;

#[derive(Clone, Debug, PartialEq)]
pub enum Data {
    A(Ipv4Addr),
    Name(String),
    Nsec(String),
    Other,
}

#[derive(Clone, Debug)]
pub struct Record {
    pub owner: String,
    pub rtype: u16,
    pub data: Data,
}

#[derive(Clone, Debug, Default)]
pub struct Message {
    pub id: u16,
    pub rcode: u8,
    pub tc: bool,
    pub qname: String,
    pub qtype: u16,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
}

pub fn labels(name: &str) -> Option<Vec<Vec<u8>>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Some(Vec::new());
    }
    let bytes = name.as_bytes();
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                let d = bytes.get(i + 1..i + 4)?;
                if d.iter().all(u8::is_ascii_digit) {
                    let v = (d[0] - b'0') as u16 * 100
                        + (d[1] - b'0') as u16 * 10
                        + (d[2] - b'0') as u16;
                    cur.push(u8::try_from(v).ok()?);
                    i += 4;
                } else {
                    cur.push(bytes[i + 1]);
                    i += 2;
                }
            }
            b'.' => {
                if cur.is_empty() || cur.len() > 63 {
                    return None;
                }
                out.push(std::mem::take(&mut cur));
                i += 1;
            }
            b => {
                cur.push(b);
                i += 1;
            }
        }
    }
    if cur.is_empty() || cur.len() > 63 {
        return None;
    }
    out.push(cur);
    Some(out)
}

pub fn encode_query(
    buf: &mut Vec<u8>,
    id: u16,
    name: &str,
    qtype: u16,
    rd: bool,
    dnssec: bool,
) -> bool {
    buf.clear();
    let Some(ls) = labels(name) else {
        return false;
    };
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&(if rd { 0x0100u16 } else { 0 }).to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&(u16::from(dnssec)).to_be_bytes());
    for l in &ls {
        buf.push(l.len() as u8);
        buf.extend_from_slice(l);
    }
    buf.push(0);
    if buf.len() > 12 + 255 {
        return false;
    }
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    if dnssec {
        buf.push(0);
        buf.extend_from_slice(&OPT.to_be_bytes());
        buf.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
        buf.extend_from_slice(&EDNS_DO.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
    }
    true
}

pub fn add_ecs(buf: &mut Vec<u8>, subnet: [u8; 3]) -> bool {
    if buf.len() < 12 || buf[10..12] != [0, 0] {
        return false;
    }
    buf[10..12].copy_from_slice(&1u16.to_be_bytes());
    buf.push(0);
    buf.extend_from_slice(&OPT.to_be_bytes());
    buf.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(&11u16.to_be_bytes());
    buf.extend_from_slice(&ECS_OPTION.to_be_bytes());
    buf.extend_from_slice(&7u16.to_be_bytes());
    buf.extend_from_slice(&ECS_FAMILY_V4.to_be_bytes());
    buf.push(ECS_PREFIX);
    buf.push(0);
    buf.extend_from_slice(&subnet);
    true
}

fn push_label(out: &mut String, label: &[u8]) {
    if !out.is_empty() {
        out.push('.');
    }
    for &b in label {
        let c = b.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
            out.push(c as char);
        } else {
            out.push('\\');
            out.push_str(&format!("{c:03}"));
        }
    }
}

fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    let mut hops = 0;
    loop {
        let len = *buf.get(pos)? as usize;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    return Some((out, end.unwrap_or(pos + 1)));
                }
                push_label(&mut out, buf.get(pos + 1..pos + 1 + len)?);
                pos += 1 + len;
                if out.len() > 1024 {
                    return None;
                }
            }
            0xc0 => {
                let ptr = ((len & 0x3f) << 8) | *buf.get(pos + 1)? as usize;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS || ptr >= buf.len() {
                    return None;
                }
                pos = ptr;
            }
            _ => return None,
        }
    }
}

fn u16_at(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?))
}

fn read_records(buf: &[u8], mut pos: usize, count: usize, out: &mut Vec<Record>) -> Option<usize> {
    for _ in 0..count {
        let (owner, p) = read_name(buf, pos)?;
        let rtype = u16_at(buf, p)?;
        let rdlen = u16_at(buf, p + 8)? as usize;
        let rd = p + 10;
        let rdata = buf.get(rd..rd + rdlen)?;
        let data = match rtype {
            A if rdlen == 4 => Data::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            CNAME | NS => Data::Name(read_name(buf, rd)?.0),
            NSEC => Data::Nsec(read_name(buf, rd)?.0),
            _ => Data::Other,
        };
        out.push(Record { owner, rtype, data });
        pos = rd + rdlen;
    }
    Some(pos)
}

pub fn parse(buf: &[u8]) -> Option<Message> {
    let id = u16_at(buf, 0)?;
    let flags = u16_at(buf, 2)?;
    let qd = u16_at(buf, 4)? as usize;
    let an = u16_at(buf, 6)? as usize;
    let ns = u16_at(buf, 8)? as usize;
    let mut msg = Message {
        id,
        rcode: (flags & 0x000f) as u8,
        tc: flags & 0x0200 != 0,
        ..Message::default()
    };
    let mut pos = 12;
    for i in 0..qd {
        let (q, p) = read_name(buf, pos)?;
        if i == 0 {
            msg.qname = q;
            msg.qtype = u16_at(buf, p)?;
        }
        pos = p + 4;
    }
    pos = read_records(buf, pos, an, &mut msg.answers)?;
    if read_records(buf, pos, ns, &mut msg.authority).is_none() {
        msg.authority.clear();
    }
    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(q: &[u8]) -> Vec<u8> {
        let mut r = q.to_vec();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 2;
        r.extend_from_slice(&[
            0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'c', b'd', b'n', 0xc0, 18,
        ]);
        let target = r.len() - 6;
        r.extend_from_slice(&[
            0xc0,
            target as u8,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            60,
            0,
            4,
            10,
            1,
            2,
            3,
        ]);
        r
    }

    #[test]
    fn round_trips() {
        let mut q = Vec::new();
        assert!(encode_query(
            &mut q,
            0xbeef,
            "Track.Example.com",
            A,
            true,
            false
        ));
        let r = answer(&q);
        let m = parse(&r).expect("parse");
        assert_eq!(m.id, 0xbeef);
        assert_eq!(m.qname, "track.example.com");
        assert_eq!(m.answers[0].data, Data::Name("cdn.example.com".into()));
        assert_eq!(m.answers[1].owner, "cdn.example.com");
        assert_eq!(m.answers[1].data, Data::A(Ipv4Addr::new(10, 1, 2, 3)));
    }

    #[test]
    fn escapes_binary_labels() {
        let ls = labels("\\000.a.example.com").expect("labels");
        assert_eq!(ls[0], vec![0u8]);
        let mut s = String::new();
        push_label(&mut s, &[0]);
        assert_eq!(s, "\\000");
        let mut q = Vec::new();
        assert!(encode_query(
            &mut q,
            1,
            "\\000.example.com",
            NSEC,
            false,
            true
        ));
        assert_eq!(parse(&q).expect("parse").qname, "\\000.example.com");
    }

    #[test]
    fn adds_client_subnet() {
        let mut q = Vec::new();
        encode_query(&mut q, 1, "a.com", A, true, false);
        let plain = q.len();
        assert!(add_ecs(&mut q, [81, 2, 69]));
        assert_eq!(q[11], 1);
        assert_eq!(&q[plain + 11..], &[0, 8, 0, 7, 0, 1, 24, 0, 81, 2, 69]);
        assert!(!add_ecs(&mut q, [1, 2, 3]));
        assert_eq!(parse(&q).expect("parse").qname, "a.com");
    }

    #[test]
    fn rejects_pointer_loops() {
        let mut q = Vec::new();
        encode_query(&mut q, 1, "a.com", A, true, false);
        q[7] = 1;
        q.extend_from_slice(&[0xc0, (q.len()) as u8]);
        assert!(parse(&q).is_none());
    }

    #[test]
    fn survives_hostile_packets() {
        let mut rng = stella_core::rng::Rng::seeded();
        let mut seeds: Vec<Vec<u8>> = Vec::new();
        for name in ["a.com", "x.y.example.org", "\\000.example.com"] {
            let mut q = Vec::new();
            encode_query(&mut q, 7, name, A, true, true);
            seeds.push(q);
        }
        for _ in 0..400_000 {
            let mut p = if rng.below(4) == 0 {
                let n = rng.below(600) as usize;
                (0..n).map(|_| rng.next_u64() as u8).collect()
            } else {
                seeds[rng.below(seeds.len() as u64) as usize].clone()
            };
            for _ in 0..=rng.below(8) {
                if p.is_empty() {
                    break;
                }
                let i = rng.below(p.len() as u64) as usize;
                match rng.below(4) {
                    0 => p[i] = rng.next_u64() as u8,
                    1 => p.truncate(i),
                    2 => p
                        .splice(i..i, (0..rng.below(40)).map(|_| rng.next_u64() as u8))
                        .for_each(drop),
                    _ => p[i] = [0xc0, 0x00, 0xff, 0x3f][rng.below(4) as usize],
                }
            }
            let _ = parse(&p);
        }
    }
}
