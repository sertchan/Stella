use std::io::{Cursor, Read};

pub const LATEST: &str = "https://registry.npmjs.org/third-party-web/latest";
const MEMBER: &str = "package/dist/entities.json";
pub const CATEGORIES: &[&str] = &["ad", "analytics", "marketing", "tag-manager"];

#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub domain: String,
    pub zone: bool,
    pub entity: String,
    pub category: String,
}

pub fn tarball_url(latest: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(latest).ok()?;
    let url = v.pointer("/dist/tarball")?.as_str()?;
    url.starts_with("https://").then(|| url.to_string())
}

pub fn entities_json(tgz: &[u8]) -> Option<Vec<u8>> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(tgz)));
    for entry in archive.entries().ok()? {
        let mut e = entry.ok()?;
        if e.path().ok()?.to_string_lossy() == MEMBER {
            let mut out = Vec::new();
            e.read_to_end(&mut out).ok()?;
            return Some(out);
        }
    }
    None
}

pub fn entries(json: &[u8]) -> Vec<Entry> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in v.as_array().into_iter().flatten() {
        let category = e["category"].as_str().unwrap_or_default();
        if !CATEGORIES.contains(&category) {
            continue;
        }
        let entity = e["name"].as_str().unwrap_or_default();
        for d in e["domains"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
        {
            let zone = d.starts_with("*.");
            let Some(domain) = stella_core::name::normalize(d.trim_start_matches("*.")) else {
                continue;
            };
            out.push(Entry {
                domain,
                zone,
                entity: entity.to_string(),
                category: category.to_string(),
            });
        }
    }
    out.sort_unstable_by(|a, b| a.domain.cmp(&b.domain));
    out.dedup_by(|a, b| a.domain == b.domain);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reads_ad_and_analytics_domains_from_the_package() {
        let json = br#"[{"name":"Ad Co","category":"ad","domains":["*.adco.net","px.adco.io"]},
            {"name":"Fonts","category":"cdn","domains":["fonts.example.net"]},
            {"name":"Stats","category":"analytics","domains":["*.stats.io","*.adco.net"]}]"#;
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let mut h = tar::Header::new_gnu();
            h.set_size(json.len() as u64);
            h.set_cksum();
            b.append_data(&mut h, MEMBER, &json[..]).expect("append");
            b.finish().expect("finish");
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).expect("gz");
        let body = entities_json(&gz.finish().expect("gz")).expect("member");
        let got: Vec<(String, bool, String)> = entries(&body)
            .into_iter()
            .map(|e| (e.domain, e.zone, e.category))
            .collect();
        assert_eq!(
            got,
            [
                ("adco.net".to_string(), true, "ad".to_string()),
                ("px.adco.io".to_string(), false, "ad".to_string()),
                ("stats.io".to_string(), true, "analytics".to_string()),
            ]
        );
        assert_eq!(
            tarball_url(br#"{"dist":{"tarball":"https://registry.npmjs.org/third-party-web/-/third-party-web-0.30.0.tgz"}}"#).as_deref(),
            Some("https://registry.npmjs.org/third-party-web/-/third-party-web-0.30.0.tgz")
        );
    }
}
