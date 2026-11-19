use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD, URL_SAFE};
use regex::bytes::Regex;
use std::io::Read;
use std::sync::LazyLock;

pub static URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)https?://[a-z0-9_.-]+\.[a-z]{2,24}(?::[0-9]{2,5})?(?:/[a-z0-9_./%{}$~+=-]{0,200})?",
    )
    .expect("URL regex")
});
pub static URL_WITH_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)https?://[a-z0-9_.-]+\.[a-z]{2,24}(?::[0-9]{2,5})?/[a-z0-9_./%{}$~+=-]{2,200}")
        .expect("URL_WITH_PATH regex")
});

const XOR_WINDOW: usize = 260;
const XOR_HITS_PER_KEY: usize = 200;
const REV_WINDOW: usize = 200;
const RUN_CAP: usize = 64 * 1024;
const INFLATE_CAP: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    B64,
    Hex,
    Rev,
    Esc,
    Pct,
    Rot13,
}

struct Markers {
    ac: AhoCorasick,
    kinds: Vec<Kind>,
}

fn b64_markers() -> Vec<String> {
    let mut out = Vec::new();
    for engine in [&STANDARD, &URL_SAFE] {
        for align in 0..3usize {
            let mut raw = vec![b'A'; align];
            raw.extend_from_slice(b"http");
            let enc = engine.encode(&raw);
            let first = (8 * align).div_ceil(6);
            let last = (8 * align + 32) / 6;
            if last > first {
                out.push(enc[first..last].to_string());
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

static MARKERS: LazyLock<Markers> = LazyLock::new(|| {
    let mut pats: Vec<String> = Vec::new();
    let mut kinds = Vec::new();
    for m in b64_markers() {
        pats.push(m);
        kinds.push(Kind::B64);
    }
    for (p, k) in [
        ("68747470", Kind::Hex),
        ("//:ptth", Kind::Rev),
        ("//:sptth", Kind::Rev),
        ("\\u0068\\u0074", Kind::Esc),
        ("\\x68\\x74", Kind::Esc),
        ("http%3a%2f%2f", Kind::Pct),
        ("https%3a%2f%2f", Kind::Pct),
        ("uggc://", Kind::Rot13),
        ("uggcf://", Kind::Rot13),
    ] {
        pats.push(p.to_string());
        kinds.push(k);
    }
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::Standard)
        .build(&pats)
        .expect("marker automaton");
    Markers { ac, kinds }
});

static XOR: LazyLock<(AhoCorasick, Vec<u8>)> = LazyLock::new(|| {
    let mut pats = Vec::new();
    let mut keys = Vec::new();
    for k in 1..=255u8 {
        for p in [&b"https://"[..], &b"http://"[..]] {
            pats.push(p.iter().map(|c| c ^ k).collect::<Vec<u8>>());
            keys.push(k);
        }
    }
    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(&pats)
        .expect("xor automaton");
    (ac, keys)
});

fn is_b64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'-' | b'_' | b'=')
}

fn run_around(data: &[u8], start: usize, end: usize, ok: impl Fn(u8) -> bool) -> (usize, usize) {
    let mut s = start;
    while s > 0 && ok(data[s - 1]) && start - s < RUN_CAP {
        s -= 1;
    }
    let mut e = end;
    while e < data.len() && ok(data[e]) && e - end < RUN_CAP {
        e += 1;
    }
    (s, e)
}

fn urls(data: &[u8]) -> Vec<String> {
    URL.find_iter(data)
        .map(|m| {
            String::from_utf8_lossy(m.as_bytes())
                .trim_end_matches('.')
                .to_string()
        })
        .collect()
}

static LOOSE: LazyLock<[GeneralPurpose; 2]> = LazyLock::new(|| {
    let cfg = GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    [
        GeneralPurpose::new(&alphabet::STANDARD, cfg),
        GeneralPurpose::new(&alphabet::URL_SAFE, cfg),
    ]
});

fn b64_decode(run: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for skip in 0..4 {
        if skip >= run.len() {
            break;
        }
        let body: Vec<u8> = run[skip..].iter().copied().filter(|c| *c != b'=').collect();
        let usable = if body.len() % 4 == 1 {
            body.len() - 1
        } else {
            body.len()
        };
        for engine in LOOSE.iter() {
            if let Ok(d) = engine.decode(&body[..usable]) {
                out.push(d);
            }
        }
    }
    out
}

fn hex_decode(run: &[u8]) -> Vec<u8> {
    run.as_chunks::<2>()
        .0
        .iter()
        .filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

fn unescape(run: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(run);
    let mut out = Vec::new();
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            let (digits, step) = match b[i + 1] {
                b'u' => (b.get(i + 2..i + 6), 6),
                b'x' => (b.get(i + 2..i + 4), 4),
                _ => (None, 1),
            };
            if let Some(v) = digits
                .and_then(|d| std::str::from_utf8(d).ok())
                .and_then(|d| u32::from_str_radix(d, 16).ok())
            {
                out.push(v as u8);
                i += step;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn pct_decode(run: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(run.len());
    let mut i = 0;
    while i < run.len() {
        if run[i] == b'%'
            && let Some(v) = run
                .get(i + 1..i + 3)
                .and_then(|d| std::str::from_utf8(d).ok())
                .and_then(|d| u8::from_str_radix(d, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(run[i]);
        i += 1;
    }
    out
}

fn rot13(run: &[u8]) -> Vec<u8> {
    run.iter()
        .map(|&c| match c {
            b'a'..=b'z' => (c - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (c - b'A' + 13) % 26 + b'A',
            _ => c,
        })
        .collect()
}

fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let ok = match data.get(..2)? {
        [0x1f, 0x8b] => flate2::read::MultiGzDecoder::new(data)
            .take(INFLATE_CAP)
            .read_to_end(&mut out)
            .is_ok(),
        [0x78, 0x9c] | [0x78, 0xda] | [0x78, 0x01] => flate2::read::ZlibDecoder::new(data)
            .take(INFLATE_CAP)
            .read_to_end(&mut out)
            .is_ok(),
        _ => false,
    };
    (ok && !out.is_empty()).then_some(out)
}

pub fn scan(data: &[u8], dex: bool, emit: &mut impl FnMut(&'static str, String)) {
    scan_depth(data, dex, 0, emit);
}

fn scan_depth(data: &[u8], dex: bool, depth: u8, emit: &mut impl FnMut(&'static str, String)) {
    let mut last_run = (usize::MAX, usize::MAX);
    for m in MARKERS.ac.find_overlapping_iter(data) {
        let kind = MARKERS.kinds[m.pattern().as_usize()];
        let (s, e) = (m.start(), m.end());
        match kind {
            Kind::B64 => {
                let run = run_around(data, s, e, is_b64);
                if run == last_run {
                    continue;
                }
                last_run = run;
                for d in b64_decode(&data[run.0..run.1]) {
                    for u in urls(&d) {
                        emit("b64", u);
                    }
                    if depth == 0
                        && let Some(z) = inflate(&d)
                    {
                        scan_depth(&z, false, depth + 1, emit);
                    }
                }
            }
            Kind::Hex => {
                let (rs, re) = run_around(data, s, e, |c| c.is_ascii_hexdigit());
                let start = rs + (s - rs) % 2;
                for u in urls(&hex_decode(&data[start..re])) {
                    emit("hex", u);
                }
            }
            Kind::Rev => {
                let from = s.saturating_sub(REV_WINDOW);
                let mut w = data[from..e].to_vec();
                w.reverse();
                for u in urls(&w) {
                    emit("rev", u);
                }
            }
            Kind::Esc => {
                let (rs, re) = run_around(data, s, e, |c| {
                    c.is_ascii_alphanumeric() || matches!(c, b'\\' | b'.' | b'/' | b'-' | b'_')
                });
                for u in urls(&unescape(&data[rs..re])) {
                    emit("esc", u);
                }
            }
            Kind::Pct => {
                let (_, re) = run_around(data, s, e, |c| {
                    c.is_ascii_alphanumeric() || matches!(c, b'%' | b'.' | b'-' | b'_')
                });
                for u in urls(&pct_decode(&data[s..re])) {
                    emit("pct", u);
                }
            }
            Kind::Rot13 => {
                let (_, re) = run_around(data, s, e, |c| {
                    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'/' | b'-' | b'_' | b':')
                });
                for u in urls(&rot13(&data[s..re])) {
                    emit("rot13", u);
                }
            }
        }
    }
    if !dex {
        let (ac, keys) = &*XOR;
        let mut per_key = [0usize; 256];
        for m in ac.find_iter(data) {
            let k = keys[m.pattern().as_usize()];
            if per_key[k as usize] >= XOR_HITS_PER_KEY {
                continue;
            }
            per_key[k as usize] += 1;
            let end = (m.start() + XOR_WINDOW).min(data.len());
            let d: Vec<u8> = data[m.start()..end].iter().map(|c| c ^ k).collect();
            if let Some(u) = urls(&d).into_iter().next() {
                emit("xor", u);
            }
        }
    }
    if depth == 0
        && let Some(z) = inflate(data)
    {
        scan_depth(&z, false, depth + 1, emit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(data: &[u8], dex: bool) -> Vec<(&'static str, String)> {
        let mut v = Vec::new();
        scan(data, dex, &mut |m, u| v.push((m, u)));
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn decodes_hidden_urls() {
        let url = "https://evt.vendor.io/v1/collect";
        let mut blob = b"xx\"".to_vec();
        blob.extend_from_slice(STANDARD.encode(url).as_bytes());
        blob.extend_from_slice(b"\" ");
        blob.extend_from_slice(
            url.bytes()
                .map(|c| format!("{c:02x}"))
                .collect::<String>()
                .as_bytes(),
        );
        blob.extend_from_slice(b" ");
        blob.extend_from_slice(url.bytes().rev().collect::<Vec<u8>>().as_slice());
        blob.extend_from_slice(b" uggcf://rig.iraqbe.vb/i1/pbyyrpg ");
        blob.extend_from_slice(b"https%3A%2F%2Fevt.vendor.io%2Fv1%2Fcollect ");
        let got = found(&blob, true);
        let methods: Vec<&str> = got
            .iter()
            .filter(|(_, u)| u == url)
            .map(|(m, _)| *m)
            .collect();
        assert_eq!(methods, ["b64", "hex", "pct", "rev", "rot13"]);
    }

    #[test]
    fn finds_single_byte_xor_outside_dex() {
        let url = b"https://t.vendor.io/ping";
        let mut blob = vec![0u8; 16];
        blob.extend(url.iter().map(|c| c ^ 0x5a));
        blob.extend([b'"' ^ 0x5a; 8]);
        assert_eq!(
            found(&blob, false),
            [("xor", "https://t.vendor.io/ping".to_string())]
        );
        assert!(found(&blob, true).is_empty());
    }

    #[test]
    fn inflates_zlib_assets() {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(
            &mut e,
            STANDARD.encode("http://a.vendor.io/x/log").as_bytes(),
        )
        .expect("write");
        let z = e.finish().expect("finish");
        assert_eq!(
            found(&z, false),
            [("b64", "http://a.vendor.io/x/log".to_string())]
        );
    }
}
