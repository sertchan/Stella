use regex::Regex;
use std::sync::LazyLock;

static PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)/(v[0-9]+/)?(collect|collector|track|tracking|tracker|events?|evt|log|logs|logging|beacon|pixel|px|impression|imp|metrics?|analytics?|stat|stats|statistics|report|reporting|batch|ingest|telemetry|hit|ping|heartbeat|monitor|apm|rum|trace|traces|crash|ubt|ulog|clog|applog|sdklog|sdk/(event|log|config)|ads|adx|adserver|bid|rtb|sync|click|clk|conversion|attribution|install|track_event|collect_event|event_report|log_upload|upload_log)(/|\?|$|\.(gif|php|json|do|js))",
    )
    .expect("PATH regex")
});

static NOISE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(www\.)?(w3\.org|schemas\.|ns\.adobe|xml\.org|apache\.org|github|developer\.|example\.|localhost|127\.|10\.|192\.168|crl\.|ocsp\.|pki\.|cacerts?\.|www\.(google|youtube)\.com)")
        .expect("NOISE regex")
});

pub fn split(url: &str) -> Option<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("HTTPS://"))
        .or_else(|| url.strip_prefix("HTTP://"))?;
    let end = rest.find(['/', ':', '?']).unwrap_or(rest.len());
    let host = stella_core::name::normalize(&rest[..end])?;
    let mut path = &rest[end..];
    if let Some(p) = path.strip_prefix(':') {
        path = p.find('/').map_or("", |i| &p[i..]);
    }
    Some((host, path.to_ascii_lowercase()))
}

pub fn endpoint(url: &str) -> Option<(String, String)> {
    let (host, path) = split(url)?;
    (PATH.is_match(&path) && !NOISE.is_match(&host)).then_some((host, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_telemetry_paths() {
        assert_eq!(
            endpoint("https://Log.Vendor.io:8443/v2/collect?a=1"),
            Some(("log.vendor.io".into(), "/v2/collect?a=1".into()))
        );
        assert!(endpoint("https://api.vendor.io/v1/users").is_none());
        assert!(endpoint("http://www.w3.org/2000/svg/events").is_none());
        assert!(endpoint("https://sdk.vendor.io/sdk/config").is_some());
    }
}
