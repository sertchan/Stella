const XML_CHUNK: u16 = 0x0003;
const STRING_POOL: u16 = 0x0001;
const UTF8_FLAG: u32 = 0x100;
const MAX_STRINGS: usize = 200_000;

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn utf8_len(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let first = *b.get(i)? as usize;
    if first & 0x80 == 0 {
        return Some((first, 1));
    }
    let second = *b.get(i + 1)? as usize;
    Some((((first & 0x7f) << 8) | second, 2))
}

fn utf16_len(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let first = u16_at(b, i)? as usize;
    if first & 0x8000 == 0 {
        return Some((first, 2));
    }
    let second = u16_at(b, i + 2)? as usize;
    Some((((first & 0x7fff) << 16) | second, 4))
}

fn read_string(b: &[u8], pos: usize, utf8: bool) -> Option<String> {
    if utf8 {
        let (_, a) = utf8_len(b, pos)?;
        let (len, c) = utf8_len(b, pos + a)?;
        let start = pos + a + c;
        Some(String::from_utf8_lossy(b.get(start..start + len)?).into_owned())
    } else {
        let (len, a) = utf16_len(b, pos)?;
        let start = pos + a;
        let raw = b.get(start..start + len * 2)?;
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }
}

pub fn is_axml(data: &[u8]) -> bool {
    u16_at(data, 0) == Some(XML_CHUNK)
}

pub fn strings(data: &[u8]) -> Option<Vec<String>> {
    if !is_axml(data) {
        return None;
    }
    let mut pos = usize::from(u16_at(data, 2)?);
    while pos + 8 <= data.len() {
        let kind = u16_at(data, pos)?;
        let header = usize::from(u16_at(data, pos + 2)?);
        let size = u32_at(data, pos + 4)? as usize;
        if size < 8 {
            return None;
        }
        if kind == STRING_POOL {
            let count = (u32_at(data, pos + 8)? as usize).min(MAX_STRINGS);
            let flags = u32_at(data, pos + 16)?;
            let start = pos + u32_at(data, pos + 20)? as usize;
            let utf8 = flags & UTF8_FLAG != 0;
            let mut out = Vec::with_capacity(count);
            for i in 0..count {
                let off = u32_at(data, pos + header + i * 4)? as usize;
                if let Some(s) = read_string(data, start + off, utf8) {
                    out.push(s);
                }
            }
            return Some(out);
        }
        pos += size;
    }
    None
}

const NETWORK_CONFIG: &str = "network-security-config";

pub fn network_config(strings: &[String]) -> bool {
    strings.iter().any(|s| s == NETWORK_CONFIG)
}

pub fn host_like(s: &str) -> Option<String> {
    let t = s.trim().trim_start_matches("*.");
    if t.contains('/') || t.contains(':') || !t.contains('.') {
        return None;
    }
    let host = stella_core::name::normalize(t)?;
    let tld = host.rsplit('.').next()?;
    (tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_lowercase())).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(strings: &[&str], utf8: bool) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for s in strings {
            offsets.push(data.len() as u32);
            if utf8 {
                data.push(s.chars().count() as u8);
                data.push(s.len() as u8);
                data.extend_from_slice(s.as_bytes());
                data.push(0);
            } else {
                let units: Vec<u16> = s.encode_utf16().collect();
                data.extend_from_slice(&(units.len() as u16).to_le_bytes());
                for u in units {
                    data.extend_from_slice(&u.to_le_bytes());
                }
                data.extend_from_slice(&[0, 0]);
            }
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let header = 28usize;
        let strings_start = header + offsets.len() * 4;
        let size = strings_start + data.len();
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&STRING_POOL.to_le_bytes());
        chunk.extend_from_slice(&(header as u16).to_le_bytes());
        chunk.extend_from_slice(&(size as u32).to_le_bytes());
        chunk.extend_from_slice(&(offsets.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes());
        chunk.extend_from_slice(&(if utf8 { UTF8_FLAG } else { 0 }).to_le_bytes());
        chunk.extend_from_slice(&(strings_start as u32).to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes());
        for o in offsets {
            chunk.extend_from_slice(&o.to_le_bytes());
        }
        chunk.extend_from_slice(&data);
        let mut file = Vec::new();
        file.extend_from_slice(&XML_CHUNK.to_le_bytes());
        file.extend_from_slice(&8u16.to_le_bytes());
        file.extend_from_slice(&((8 + chunk.len()) as u32).to_le_bytes());
        file.extend_from_slice(&chunk);
        file
    }

    #[test]
    fn reads_utf16_and_utf8_string_pools() {
        let words = [
            "domain-config",
            "events.vendor.io",
            "https://t.vendor.io/v1/collect",
        ];
        for utf8 in [false, true] {
            assert_eq!(
                strings(&pool(&words, utf8)).expect("pool"),
                words.map(String::from)
            );
        }
        assert!(strings(b"<?xml version=\"1.0\"?>").is_none());
        let mut cut = pool(&words, false);
        cut.truncate(40);
        assert!(strings(&cut).is_none_or(|s| s.len() < 3));
    }

    #[test]
    fn keeps_host_like_strings() {
        let nsc: Vec<String> = [
            "network-security-config",
            "domain-config",
            "domain",
            "api.vendor.io",
        ]
        .map(String::from)
        .to_vec();
        assert!(network_config(&nsc));
        assert!(!network_config(&nsc[1..]));
        assert_eq!(
            host_like("Events.Vendor.io").as_deref(),
            Some("events.vendor.io")
        );
        assert_eq!(
            host_like("*.cdn.vendor.io").as_deref(),
            Some("cdn.vendor.io")
        );
        for no in [
            "domain-config",
            "https://a.io/x",
            "1.2.3.4",
            "localhost",
            "true",
        ] {
            assert!(host_like(no).is_none(), "{no}");
        }
    }
}
