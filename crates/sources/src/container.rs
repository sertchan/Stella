use crate::hosts_in;
use regex::bytes::Regex;
use std::sync::LazyLock;

const CONTAINER_CAP: usize = 4 * 1024 * 1024;

static SGTM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:server_container_url|transport_url)[^h]{0,40}https?:\\?/\\?/([a-z0-9.-]+)")
        .expect("SGTM regex")
});
static HOSTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)https?:\\?/\\?/([a-z0-9-]+(?:\.[a-z0-9-]+)+)").expect("HOSTS regex")
});

pub fn url(id: &str) -> String {
    if id.starts_with(crate::vendors::PIXEL_PREFIX) {
        crate::vendors::pixel_config_url(id)
    } else if id.starts_with("GTM-") {
        format!("https://www.googletagmanager.com/gtm.js?id={id}")
    } else {
        format!("https://www.googletagmanager.com/gtag/js?id={id}")
    }
}

pub struct Container {
    pub sgtm: Vec<String>,
    pub hosts: Vec<String>,
}

pub fn parse(body: &[u8]) -> Container {
    Container {
        sgtm: hosts_in(body, &SGTM, 1),
        hosts: hosts_in(body, &HOSTS, 1),
    }
}

const TRIES: u64 = 4;
const BACKOFF_MS: u64 = 1500;

pub enum Fetched {
    Found(Container),
    Missing,
    Failed,
}

pub async fn fetch(client: &reqwest::Client, id: &str) -> Fetched {
    for attempt in 0..TRIES {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(BACKOFF_MS * attempt)).await;
        }
        let Ok(page) = stella_net::client::fetch(client, &url(id), CONTAINER_CAP).await else {
            continue;
        };
        match page.status {
            200 if id.starts_with(crate::vendors::PIXEL_PREFIX) => {
                return Fetched::Found(Container {
                    sgtm: crate::vendors::openbridge_hosts(&page.body),
                    hosts: Vec::new(),
                });
            }
            200 => return Fetched::Found(parse(&page.body)),
            400 | 404 => return Fetched::Missing,
            _ => {}
        }
    }
    Fetched::Failed
}

#[cfg(test)]
mod tests {
    #[test]
    fn finds_server_container() {
        let js = br#"{"function":"__googtag","vtp_server_container_url":"https:\/\/sst.shop.com","x":"https://www.google-analytics.com/g/collect"}"#;
        let c = super::parse(js);
        assert_eq!(c.sgtm, ["sst.shop.com"]);
        assert_eq!(c.hosts, ["sst.shop.com", "www.google-analytics.com"]);
    }
}
