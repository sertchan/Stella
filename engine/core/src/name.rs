pub fn normalize(raw: &str) -> Option<String> {
    let s = raw.trim().trim_end_matches('.');
    let s = s.strip_prefix("*.").unwrap_or(s);
    if s.len() < 4 || s.len() > 253 {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut label_len = 0usize;
    let mut labels = 1usize;
    for b in s.bytes() {
        let c = b.to_ascii_lowercase();
        match c {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {
                label_len += 1;
                if label_len > 63 {
                    return None;
                }
            }
            b'.' => {
                if label_len == 0 {
                    return None;
                }
                label_len = 0;
                labels += 1;
            }
            _ => return None,
        }
        out.push(c as char);
    }
    if label_len == 0 || labels < 2 || out.starts_with('_') {
        return None;
    }
    let tld = out.rsplit('.').next()?;
    let alpha = tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_lowercase());
    if !(alpha || tld.starts_with("xn--")) || tld == "arpa" {
        return None;
    }
    Some(out)
}

pub fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    let mut next = Some(0usize);
    std::iter::from_fn(move || {
        let start = next?;
        let s = &name[start..];
        next = s.find('.').map(|i| start + i + 1);
        Some(s)
    })
}

pub fn parent(name: &str) -> Option<&str> {
    let rest = &name[name.find('.')? + 1..];
    rest.contains('.').then_some(rest)
}

pub fn subdomain<'a>(host: &'a str, regdom: &str) -> &'a str {
    if host.len() > regdom.len() + 1 && host.ends_with(regdom) {
        &host[..host.len() - regdom.len() - 1]
    } else {
        ""
    }
}

pub fn host_of_url(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("wss://"))
        .or_else(|| url.strip_prefix("ws://"))?;
    let end = rest.find(['/', ':', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..end];
    let host = host.rsplit('@').next().unwrap_or(host);
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(
            normalize("*.Track.Example.COM."),
            Some("track.example.com".into())
        );
        assert_eq!(normalize("_dmarc.example.com"), None);
        assert_eq!(normalize("1.0.0.127.in-addr.arpa"), None);
        assert_eq!(normalize("a..b.com"), None);
        assert_eq!(normalize("example.c0m"), None);
        assert_eq!(
            normalize("xn--p1ai.xn--p1ai"),
            Some("xn--p1ai.xn--p1ai".into())
        );
        assert_eq!(normalize("localhost"), None);
    }

    #[test]
    fn walks_suffixes() {
        let v: Vec<_> = suffixes("a.b.example.com").collect();
        assert_eq!(
            v,
            ["a.b.example.com", "b.example.com", "example.com", "com"]
        );
        assert_eq!(parent("a.b.example.com"), Some("b.example.com"));
        assert_eq!(parent("example.com"), None);
        assert_eq!(subdomain("a.b.example.com", "example.com"), "a.b");
        assert_eq!(subdomain("example.com", "example.com"), "");
    }

    #[test]
    fn extracts_url_host() {
        assert_eq!(host_of_url("https://x.y.com:443/a?b"), Some("x.y.com"));
        assert_eq!(host_of_url("wss://u@x.y.com/a"), Some("x.y.com"));
        assert_eq!(host_of_url("data:x"), None);
    }
}
