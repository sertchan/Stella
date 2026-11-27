use rustc_hash::FxHashSet;
use std::io::{Cursor, Read};

pub const MEMBER_CAP: u64 = 16 * 1024 * 1024;
const CRX_MAGIC: &[u8] = b"Cr24";
const CRX3: u32 = 3;
const CRX2: u32 = 2;
const CHROME_VERSION: &str = "140.0";

pub enum Store {
    Chrome(String),
    Firefox(String),
}

impl Store {
    pub fn parse(line: &str) -> Option<Self> {
        let (store, id) = line.trim().split_once(':')?;
        let id = id.trim();
        let ok = !id.is_empty()
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'));
        if !ok {
            return None;
        }
        match store {
            "chrome" => Some(Self::Chrome(id.to_ascii_lowercase())),
            "firefox" => Some(Self::Firefox(id.to_string())),
            _ => None,
        }
    }

    pub fn key(&self) -> String {
        match self {
            Self::Chrome(id) => format!("chrome:{id}"),
            Self::Firefox(slug) => format!("firefox:{slug}"),
        }
    }

    pub fn file_name(&self) -> String {
        match self {
            Self::Chrome(id) => format!("chrome-{id}.crx"),
            Self::Firefox(slug) => format!("firefox-{}.xpi", slug.replace(['@', '.'], "_")),
        }
    }
}

pub fn chrome_url(id: &str) -> String {
    format!(
        "https://clients2.google.com/service/update2/crx?response=redirect&prodversion={CHROME_VERSION}&acceptformat=crx2,crx3&x=id%3D{id}%26uc"
    )
}

pub fn firefox_api(slug: &str) -> String {
    format!("https://addons.mozilla.org/api/v5/addons/addon/{slug}/")
}

pub fn firefox_file(api: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(api).ok()?;
    let url = v.pointer("/current_version/file/url")?.as_str()?;
    url.starts_with("https://").then(|| url.to_string())
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

pub fn zip_part(data: &[u8]) -> Option<&[u8]> {
    if !data.starts_with(CRX_MAGIC) {
        return data.starts_with(b"PK").then_some(data);
    }
    let start = match u32_at(data, 4)? {
        CRX3 => 12 + u32_at(data, 8)? as usize,
        CRX2 => 16 + u32_at(data, 8)? as usize + u32_at(data, 12)? as usize,
        _ => return None,
    };
    data.get(start..)
}

fn pattern_host(p: &str) -> Option<String> {
    let rest = p.split_once("://").map_or(p, |(_, r)| r);
    let host = rest.split('/').next()?.trim_start_matches("*.");
    if host.is_empty() || host == "*" || host.contains('*') {
        return None;
    }
    stella_core::name::normalize(host).filter(|h| h.contains('.'))
}

pub fn manifest_hosts(manifest: &[u8]) -> Vec<String> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(manifest) else {
        return Vec::new();
    };
    let mut patterns: Vec<&str> = Vec::new();
    for key in [
        "host_permissions",
        "optional_host_permissions",
        "permissions",
    ] {
        patterns.extend(
            v[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p.as_str()),
        );
    }
    for cs in v["content_scripts"].as_array().into_iter().flatten() {
        patterns.extend(
            cs["matches"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p.as_str()),
        );
    }
    patterns.extend(
        v.pointer("/externally_connectable/matches")
            .and_then(|m| m.as_array())
            .into_iter()
            .flatten()
            .filter_map(|p| p.as_str()),
    );
    let mut out: Vec<String> = patterns
        .into_iter()
        .filter(|p| p.contains("://"))
        .filter_map(pattern_host)
        .collect::<FxHashSet<_>>()
        .into_iter()
        .collect();
    out.sort_unstable();
    out
}

pub fn hosts(data: &[u8]) -> Option<Vec<String>> {
    let mut zip = zip::ZipArchive::new(Cursor::new(zip_part(data)?)).ok()?;
    let mut set: FxHashSet<String> = FxHashSet::default();
    for i in 0..zip.len() {
        let Ok(mut f) = zip.by_index(i) else { continue };
        if f.is_dir() || f.size() > MEMBER_CAP {
            continue;
        }
        let Ok(name) = f.name().map(|n| n.to_ascii_lowercase()) else {
            continue;
        };
        let wanted = name.ends_with(".js")
            || name.ends_with(".json")
            || name.ends_with(".html")
            || name.ends_with(".mjs");
        if !wanted {
            continue;
        }
        let mut buf = Vec::with_capacity(f.size() as usize);
        if f.read_to_end(&mut buf).is_err() {
            continue;
        }
        if name == "manifest.json" {
            set.extend(manifest_hosts(&buf));
        }
        set.extend(crate::scripts::hosts_in_script(&buf));
    }
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort_unstable();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zipped(files: &[(&str, &str)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (n, d) in files {
            w.start_file(*n, zip::write::SimpleFileOptions::default())
                .expect("start");
            w.write_all(d.as_bytes()).expect("write");
        }
        w.finish().expect("finish").into_inner()
    }

    #[test]
    fn reads_crx3_and_manifest_hosts() {
        let manifest = r#"{"manifest_version":3,"host_permissions":["https://*.vendor.io/*","<all_urls>"],
            "permissions":["storage","https://api.tracker.net/"],
            "content_scripts":[{"matches":["*://*.shop.com/*","https://*/*"]}],
            "externally_connectable":{"matches":["https://app.vendor.io/*"]}}"#;
        let z = zipped(&[
            ("manifest.json", manifest),
            ("bg.js", "fetch('https://ev.collect.io/v1/e')"),
            ("icon.png", "https://no.png.io/x"),
        ]);
        let mut crx = b"Cr24".to_vec();
        crx.extend_from_slice(&3u32.to_le_bytes());
        crx.extend_from_slice(&5u32.to_le_bytes());
        crx.extend_from_slice(b"hdr!!");
        crx.extend_from_slice(&z);
        let got = hosts(&crx).expect("crx");
        assert_eq!(
            got,
            [
                "api.tracker.net",
                "app.vendor.io",
                "ev.collect.io",
                "shop.com",
                "vendor.io"
            ]
        );
        assert_eq!(hosts(&z).expect("xpi"), got);
        assert!(hosts(b"Cr24\x09\x00\x00\x00").is_none());
    }

    #[test]
    fn parses_store_lines_and_firefox_api() {
        assert!(matches!(Store::parse("chrome:ABCdef"), Some(Store::Chrome(id)) if id == "abcdef"));
        assert!(matches!(
            Store::parse("firefox:ublock-origin"),
            Some(Store::Firefox(_))
        ));
        assert!(Store::parse("chrome:../x").is_none());
        assert!(Store::parse("edge:abc").is_none());
        let api = br#"{"current_version":{"file":{"url":"https://addons.mozilla.org/firefox/downloads/file/1/x.xpi"}}}"#;
        assert_eq!(
            firefox_file(api).as_deref(),
            Some("https://addons.mozilla.org/firefox/downloads/file/1/x.xpi")
        );
        assert!(chrome_url("abc").contains("x=id%3Dabc%26uc"));
    }
}
