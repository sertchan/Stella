use regex::bytes::Regex;
use serde_json::Value;
use std::sync::LazyLock;

pub const GVL: &str = "https://vendor-list.consensu.org/v3/vendor-list.json";
pub const SUBDOMAIN_CENTER: &str = "https://api.subdomain.center/?domain=";

pub struct Vendor {
    pub name: String,
    pub disclosure: String,
}

pub fn gvl_vendors(body: &[u8]) -> Vec<Vendor> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let Some(vendors) = v.get("vendors").and_then(Value::as_object) else {
        return Vec::new();
    };
    vendors
        .values()
        .filter(|x| x.get("deletedDate").is_none())
        .filter_map(|x| {
            Some(Vendor {
                name: x.get("name")?.as_str()?.to_string(),
                disclosure: x.get("deviceStorageDisclosureUrl")?.as_str()?.to_string(),
            })
        })
        .filter(|x| x.disclosure.starts_with("https://"))
        .collect()
}

fn collect_domains(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match (k.as_str(), x) {
                    ("domain", Value::String(s)) => out.push(s.clone()),
                    ("domains", Value::Array(a)) => {
                        for d in a {
                            match d {
                                Value::String(s) => out.push(s.clone()),
                                other => collect_domains(other, out),
                            }
                        }
                    }
                    _ => collect_domains(x, out),
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_domains(x, out)),
        _ => {}
    }
}

pub fn disclosure_hosts(body: &[u8]) -> Vec<String> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let mut raw = Vec::new();
    collect_domains(&v, &mut raw);
    let mut out: Vec<String> = raw
        .iter()
        .map(|d| {
            d.trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .to_string()
        })
        .filter_map(|d| stella_core::name::normalize(&d))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

pub fn passive_names(body: &[u8], zone: &str) -> Option<Vec<String>> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let suffix = format!(".{zone}");
    let mut out: Vec<String> = v
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .filter_map(stella_core::name::normalize)
        .filter(|n| n.ends_with(&suffix))
        .collect();
    out.sort_unstable();
    out.dedup();
    Some(out)
}

static PIXEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"fbq\(\s*.init.\s*,\s*.([0-9]{12,17})|facebook\.com/tr/?\?(?:[^"]*&)?id=([0-9]{12,17})|signals/config/([0-9]{12,17})|"(?:pixel_?[iI]d|fbPixelId|facebookPixelId)"\s*:\s*"?([0-9]{12,17})"#)
        .expect("PIXEL regex")
});
static OPENBRIDGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""openbridge", \{"endpoints":\[[^\]]*\]"#).expect("OPENBRIDGE regex")
});
static BRIDGE_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:endpoint|fallbackDomain|mpcFallbackDomain)":"https:\\/\\/([^"\\/]+)"#)
        .expect("BRIDGE_HOST regex")
});

pub const PIXEL_PREFIX: &str = "FB-";

pub fn pixel_ids(page: &[u8]) -> Vec<String> {
    let mut v: Vec<String> = PIXEL
        .captures_iter(page)
        .filter_map(|c| (1..=4).find_map(|i| c.get(i)))
        .map(|m| format!("{PIXEL_PREFIX}{}", String::from_utf8_lossy(m.as_bytes())))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

pub fn pixel_config_url(id: &str) -> String {
    format!(
        "https://connect.facebook.net/signals/config/{}?v=2.9.439&r=stable",
        id.trim_start_matches(PIXEL_PREFIX)
    )
}

pub fn openbridge_hosts(config: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for block in OPENBRIDGE.find_iter(config) {
        out.extend(crate::hosts_in(block.as_bytes(), &BRIDGE_HOST, 1));
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_vendor_lists_and_pixels() {
        let gvl = br#"{"vendors":{"1":{"name":"A","deviceStorageDisclosureUrl":"https://a.com/d.json"},"2":{"name":"B","deletedDate":"x","deviceStorageDisclosureUrl":"https://b.com/d.json"}}}"#;
        assert_eq!(gvl_vendors(gvl).len(), 1);
        let disc = br#"{"disclosures":[{"identifier":"x","domains":["*.track.a.com"]}],"domains":[{"domain":".sync.a.com","use":"x"}]}"#;
        assert_eq!(disclosure_hosts(disc), ["sync.a.com", "track.a.com"]);
        assert_eq!(
            passive_names(br#"["a.x.com","x.com","b.y.com"]"#, "x.com").expect("json"),
            ["a.x.com"]
        );
        let page = b"fbq('init', '123456789012345'); <img src=\"https://www.facebook.com/tr?id=987654321098765&ev=PageView\">";
        assert_eq!(
            pixel_ids(page),
            ["FB-123456789012345", "FB-987654321098765"]
        );
        let cfg = br#"x("openbridge", {"endpoints":[{"endpoint":"https:\/\/capig.shop.com","fallbackDomain":"https:\/\/gw.shop.io"}]})"#;
        assert_eq!(openbridge_hosts(cfg), ["capig.shop.com", "gw.shop.io"]);
    }
}
