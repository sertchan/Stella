use regex::bytes::Regex;
use serde_json::Value;
use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

const WELL_KNOWN_CAP: usize = 30 * 1024 * 1024;

pub fn parse_ads_txt(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.trim();
            if l.contains('=') {
                return None;
            }
            let mut f = l.split(',');
            let domain = f.next()?.trim();
            let kind = f.nth(1)?.trim().to_ascii_uppercase();
            (kind.starts_with("DIRECT") || kind.starts_with("RESELLER"))
                .then(|| stella_core::name::normalize(domain))
                .flatten()
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

pub fn parse_sellers(body: &[u8]) -> Option<Vec<String>> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let sellers = v.get("sellers")?.as_array()?;
    let mut out: Vec<String> = sellers
        .iter()
        .filter(|s| {
            s.get("seller_type")
                .and_then(Value::as_str)
                .is_some_and(|t| {
                    t.eq_ignore_ascii_case("INTERMEDIARY") || t.eq_ignore_ascii_case("BOTH")
                })
        })
        .filter_map(|s| s.get("domain").and_then(Value::as_str))
        .filter_map(stella_core::name::normalize)
        .collect();
    out.sort_unstable();
    out.dedup();
    Some(out)
}

pub const ATTESTATIONS: &str = ".well-known/privacy-sandbox-attestations.json";

pub fn is_attestation(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("privacy_sandbox_api_attestations").cloned())
        .is_some_and(|a| a.is_array())
}

pub async fn well_known(client: &reqwest::Client, domain: &str, path: &str) -> Option<Vec<u8>> {
    for host in [domain.to_string(), format!("www.{domain}")] {
        let Ok(p) =
            stella_net::client::fetch(client, &format!("https://{host}/{path}"), WELL_KNOWN_CAP)
                .await
        else {
            continue;
        };
        if p.status == 200 && !p.body.is_empty() {
            return Some(p.body);
        }
    }
    None
}

static URL_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)https?:\\?/\\?/([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,24})")
        .expect("URL_HOST regex")
});

pub const PREBID_JS: &str = "https://codeload.github.com/prebid/Prebid.js/tar.gz/refs/heads/master";
pub const PREBID_SERVER: &str =
    "https://codeload.github.com/prebid/prebid-server/tar.gz/refs/heads/master";

pub fn prebid_member(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    (path.contains("/modules/")
        && (file.ends_with("BidAdapter.js")
            || file.ends_with("BidAdapter.ts")
            || file.ends_with("IdSystem.js")))
        || (path.contains("/static/bidder-info/")
            && (file.ends_with(".yaml") || file.ends_with(".yml")))
}

pub fn hosts_in_tarball(
    path: &Path,
    keep: fn(&str) -> bool,
) -> anyhow::Result<Vec<(String, String)>> {
    let file = std::fs::File::open(path)?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut out = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        if !keep(&name) {
            continue;
        }
        let mut body = Vec::new();
        entry.read_to_end(&mut body)?;
        let short = name.rsplit('/').next().unwrap_or(&name).to_string();
        for h in crate::hosts_in(&body, &URL_HOST, 1) {
            out.push((h, short.clone()));
        }
    }
    out.sort_unstable();
    out.dedup_by(|a, b| a.0 == b.0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_privacy_sandbox_attestations() {
        let real = br#"{"privacy_sandbox_api_attestations":[{"attestation_version":"2","attestation_parser_version":"2","enrollment_id":"X1","enrollment_site":"https://adnet.com","platform_attestations":[]}]}"#;
        assert!(is_attestation(real));
        assert!(!is_attestation(b"<html>not found</html>"));
        assert!(!is_attestation(
            br#"{"privacy_sandbox_api_attestations":"x"}"#
        ));
    }

    #[test]
    fn parses_ads_txt_and_sellers() {
        let ads = "# comment\ngoogle.com, pub-1, DIRECT, f08c47fec0942fa0\nRubiconProject.com, 1, RESELLER\ncontact=ads@x.com\nbad line\n";
        assert_eq!(parse_ads_txt(ads), ["google.com", "rubiconproject.com"]);
        let sellers = br#"{"sellers":[{"domain":"a.com","seller_type":"PUBLISHER"},{"domain":"b.io","seller_type":"INTERMEDIARY"},{"domain":"c.net","seller_type":"BOTH"}]}"#;
        assert_eq!(parse_sellers(sellers).expect("json"), ["b.io", "c.net"]);
        assert!(prebid_member("Prebid.js-master/modules/fooBidAdapter.js"));
        assert!(prebid_member(
            "prebid-server-master/static/bidder-info/foo.yaml"
        ));
        assert!(!prebid_member("Prebid.js-master/src/adapter.js"));
    }
}
