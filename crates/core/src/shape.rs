const HEX_RUN: usize = 8;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

pub fn mask(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.is_empty() {
            return;
        }
        if run.chars().all(|c| c.is_ascii_digit()) {
            out.push('N');
        } else if run.len() >= HEX_RUN && run.chars().all(|c| c.is_ascii_hexdigit()) {
            out.push('H');
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

pub fn masked_without_host(body: &[u8], host: &str) -> String {
    let masked = mask(body);
    let own = mask(host.as_bytes());
    if own.is_empty() {
        return masked;
    }
    masked.replace(&own, "HOST")
}

pub fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV_OFFSET, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(FNV_PRIME)
    })
}

pub fn digest(body: &[u8], host: &str) -> String {
    if body.is_empty() {
        return String::new();
    }
    format!("{:016x}", fnv1a(masked_without_host(body, host).as_bytes()))
}

pub fn length_bucket(length: i64) -> u8 {
    match length {
        ..=0 => 0,
        1..=64 => 1,
        65..=512 => 2,
        513..=4096 => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_numbers_and_hex() {
        assert_eq!(mask(b"Request 12345 id=deadbeef01"), "request N id=H");
        assert_eq!(mask(b"cafe 2024"), "cafe N");
    }

    #[test]
    fn digest_ignores_ids_and_own_host() {
        let a = digest(b"<p>sst.shop-a.com 1732 ab12cd34ef</p>", "sst.shop-a.com");
        let b = digest(b"<p>sst.shop-b.de 99 99aabbccdd</p>", "sst.shop-b.de");
        assert_eq!(a, b);
        assert_ne!(a, digest(b"<p>other text</p>", "sst.shop-a.com"));
        assert_eq!(digest(b"", "x.com"), "");
    }

    #[test]
    fn fnv_matches_reference_vectors() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn buckets_lengths() {
        assert_eq!(
            [0, 1, 64, 65, 512, 513, 4096, 4097, -1].map(length_bucket),
            [0, 1, 1, 2, 2, 3, 3, 4, 0]
        );
    }
}
