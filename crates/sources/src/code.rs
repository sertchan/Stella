pub const QUERIES: &[&str] = &[
    "\"server_container_url\" in:file",
    "\"transport_url\" googletagmanager in:file",
    "cloudflare_record sgtm in:file language:HCL",
    "\"stape.io\" in:file",
    "\"tagging_server\" in:file",
    "\"first-party\" tracking CNAME in:file language:HCL",
];

pub const PER_PAGE: usize = 100;

pub fn search_url(query: &str) -> String {
    let q: String = query
        .bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            b' ' => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect();
    format!("https://api.github.com/search/code?q={q}&per_page={PER_PAGE}")
}

pub fn raw_urls(body: &[u8]) -> Vec<String> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    v["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| i["html_url"].as_str())
        .filter_map(|u| {
            let rest = u.strip_prefix("https://github.com/")?;
            let (repo, path) = rest.split_once("/blob/")?;
            Some(format!("https://raw.githubusercontent.com/{repo}/{path}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_search_and_raw_urls() {
        assert_eq!(
            search_url("\"stape.io\" in:file"),
            "https://api.github.com/search/code?q=%22stape.io%22+in%3Afile&per_page=100"
        );
        let body = br#"{"total_count":1,"items":[{"html_url":"https://github.com/acme/infra/blob/0a1b2c/dns/main.tf"},{"html_url":"https://gist.github.com/x"}]}"#;
        assert_eq!(
            raw_urls(body),
            ["https://raw.githubusercontent.com/acme/infra/0a1b2c/dns/main.tf"]
        );
        assert!(raw_urls(b"{}").is_empty());
    }
}
