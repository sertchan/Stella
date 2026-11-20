use anyhow::{Result, bail};
use regex::bytes::Regex;
use serde_json::Value;
use std::sync::LazyLock;
use std::time::Duration;

pub const REPO: &str = "hagezi/dns-blocklists";
pub const LABELS: &[&str] = &["allow", "deny"];
const PER_PAGE: usize = 100;
const TRIES: u64 = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ListKind {
    Dns,
    Plain,
    Content,
}

pub const EXCEPTION_LISTS: &[(&str, &str, ListKind)] = &[
    (
        "adguard-dns",
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        ListKind::Dns,
    ),
    (
        "adguard-dns-exceptions",
        "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt",
        ListKind::Dns,
    ),
    (
        "anudeep-allow",
        "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
        ListKind::Plain,
    ),
    (
        "adguard-base",
        "https://filters.adtidy.org/extension/ublock/filters/2.txt",
        ListKind::Content,
    ),
    (
        "adguard-tracking",
        "https://filters.adtidy.org/extension/ublock/filters/3.txt",
        ListKind::Content,
    ),
    (
        "easylist",
        "https://easylist.to/easylist/easylist.txt",
        ListKind::Content,
    ),
    (
        "easyprivacy",
        "https://easylist.to/easylist/easyprivacy.txt",
        ListKind::Content,
    ),
    (
        "ublock-unbreak",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
        ListKind::Content,
    ),
    (
        "ublock-privacy",
        "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
        ListKind::Content,
    ),
];

pub const DNS: &str = "dns";
pub const DNS_EXACT: &str = "dns-exact";
pub const CONTENT: &str = "content";

pub const PENDING: &str = "pending";
pub const GRANTED: &str = "granted";
pub const DECLINED: &str = "declined";
pub const VOID: &str = "void";

const ISSUE_NOISE: &[&str] = &[
    "github.com",
    "githubusercontent.com",
    "github.io",
    "dnsbunker.org",
    "hagezi.org",
];

static BARE_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]+)*\.[a-z]{2,24})\b")
        .expect("BARE_HOST regex")
});

pub fn clean_host(token: &str) -> Option<String> {
    let mut t = token
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '<' | '>'))
        .to_ascii_lowercase();
    for p in ["https://", "http://", "@@", "||", "|", "*."] {
        if let Some(rest) = t.strip_prefix(p) {
            t = rest.to_string();
        }
    }
    let end = t
        .find(['/', '^', '$', ':', '?', '#', '*'])
        .unwrap_or(t.len());
    let host = t[..end].trim_matches('.');
    stella_core::name::normalize(host)
}

fn domain_block(body: &str) -> Option<Vec<String>> {
    let mut lines = body.lines();
    lines.find(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("###") && l.contains("domain") && l.contains("block")
    })?;
    let mut out = Vec::new();
    let mut fenced = false;
    for l in lines {
        let t = l.trim();
        if t.starts_with("```") {
            if fenced {
                break;
            }
            fenced = true;
            continue;
        }
        if t.starts_with("###") {
            break;
        }
        out.extend(t.split([' ', '\t', ',']).filter_map(clean_host));
    }
    (!out.is_empty()).then_some(out)
}

pub fn issue_hosts(title: &str, body: &str, listed_tld: impl Fn(&str) -> bool) -> Vec<String> {
    let mut v = domain_block(body).unwrap_or_else(|| {
        let text = format!("{title}\n{body}");
        crate::hosts_in(text.as_bytes(), &BARE_HOST, 1)
            .into_iter()
            .filter(|h| {
                !ISSUE_NOISE
                    .iter()
                    .any(|n| h == n || h.ends_with(&format!(".{n}")))
            })
            .collect()
    });
    v.retain(|h| h.contains('.') && listed_tld(h));
    v.sort_unstable();
    v.dedup();
    v
}

pub fn outcome(label: &str, state: &str, reason: Option<&str>, labels: &[&str]) -> &'static str {
    let has = |l: &str| labels.iter().any(|x| x.eq_ignore_ascii_case(l));
    if ["duplicate", "invalid", "garbage", "off topic", "test"]
        .iter()
        .any(|l| has(l))
    {
        return VOID;
    }
    if state == "open" {
        return PENDING;
    }
    let declined = [
        "wontfix",
        "not-worth-it",
        "layer-8-problem",
        "unable to reproduce",
    ]
    .iter()
    .any(|l| has(l))
        || reason == Some("not_planned");
    if declined {
        return DECLINED;
    }
    let granted = if label == "allow" {
        has("false positive/unblocked") || reason == Some("completed")
    } else {
        [
            "already included",
            "scheduled-next-release",
            "fixed-pending-release",
            "hotfix",
        ]
        .iter()
        .any(|l| has(l))
            || reason == Some("completed")
    };
    if granted { GRANTED } else { DECLINED }
}

pub struct Issue {
    pub number: i64,
    pub updated: String,
    pub outcome: &'static str,
    pub hosts: Vec<String>,
}

pub fn parse_issues(
    body: &[u8],
    label: &str,
    listed_tld: impl Fn(&str) -> bool + Copy,
) -> Result<Vec<Issue>> {
    let v: Value = serde_json::from_slice(body)?;
    let Some(items) = v.as_array() else {
        bail!(
            "unexpected reply: {}",
            String::from_utf8_lossy(&body[..body.len().min(200)])
        );
    };
    Ok(items
        .iter()
        .filter(|i| i.get("pull_request").is_none())
        .filter_map(|i| {
            let labels: Vec<&str> = i
                .get("labels")?
                .as_array()?
                .iter()
                .filter_map(|l| l.get("name").and_then(Value::as_str))
                .collect();
            Some(Issue {
                number: i.get("number")?.as_i64()?,
                updated: i.get("updated_at")?.as_str()?.to_string(),
                outcome: outcome(
                    label,
                    i.get("state")?.as_str()?,
                    i.get("state_reason").and_then(Value::as_str),
                    &labels,
                ),
                hosts: issue_hosts(
                    i.get("title").and_then(Value::as_str).unwrap_or(""),
                    i.get("body").and_then(Value::as_str).unwrap_or(""),
                    listed_tld,
                ),
            })
        })
        .collect())
}

pub fn issues_url(label: &str, since: Option<&str>, page: usize) -> String {
    let mut u = format!(
        "https://api.github.com/repos/{REPO}/issues?labels={label}&state=all&sort=updated&direction=asc&per_page={PER_PAGE}&page={page}"
    );
    if let Some(s) = since {
        u.push_str("&since=");
        u.push_str(s);
    }
    u
}

pub fn last_page(n: usize) -> bool {
    n < PER_PAGE
}

pub async fn github_get(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
) -> Result<Vec<u8>> {
    let mut last = anyhow::anyhow!("no attempt");
    for t in 0..TRIES {
        if t > 0 {
            tokio::time::sleep(Duration::from_secs(3 * t)).await;
        }
        let mut req = client
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(tok) = token {
            req = req.bearer_auth(tok);
        }
        match req.send().await {
            Ok(r) => {
                let status = r.status();
                let body = r.bytes().await?.to_vec();
                if status.is_success() {
                    return Ok(body);
                }
                last = anyhow::anyhow!(
                    "github {status}: {}",
                    String::from_utf8_lossy(&body[..body.len().min(200)])
                );
                if status.as_u16() == 403 || status.as_u16() == 401 {
                    break;
                }
            }
            Err(e) => last = e.into(),
        }
    }
    Err(last)
}

fn rule_host(rest: &str) -> Option<(String, char)> {
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
        .unwrap_or(rest.len());
    let next = rest[end..].chars().next().unwrap_or('^');
    let host = stella_core::name::normalize(&rest[..end])?;
    host.contains('.').then_some((host, next))
}

pub fn exceptions(text: &str, kind: ListKind) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = text
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            match kind {
                ListKind::Plain => {
                    let l = l.split('#').next()?.trim();
                    let h = stella_core::name::normalize(l)?;
                    h.contains('.').then_some((h, DNS_EXACT))
                }
                ListKind::Dns => {
                    let (h, next) = rule_host(l.strip_prefix("@@||")?)?;
                    matches!(next, '^' | '$').then_some((h, DNS))
                }
                ListKind::Content => {
                    let (h, next) = rule_host(l.strip_prefix("@@||")?)?;
                    matches!(next, '^' | '/' | '$').then_some((h, CONTENT))
                }
            }
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_issue_domains_and_outcomes() {
        let body = "### Which domain(s) need to be unblocked?\n\n```yaml\nhub.outsideinc.com\n*.cdn.example.org, https://x.example.net/path\n```\n\n### Why\n\nsee github.com/foo and other.com";
        let any = |_: &str| true;
        assert_eq!(
            issue_hosts("t", body, any),
            ["cdn.example.org", "hub.outsideinc.com", "x.example.net"]
        );
        let loose = issue_hosts("block tracker.shop.de please", "see github.com/x", any);
        assert_eq!(loose, ["tracker.shop.de"]);
        assert_eq!(outcome("allow", "open", None, &[]), PENDING);
        assert_eq!(
            outcome(
                "allow",
                "closed",
                Some("completed"),
                &["allow", "false positive/unblocked"]
            ),
            GRANTED
        );
        assert_eq!(
            outcome("allow", "closed", Some("not_planned"), &["allow"]),
            DECLINED
        );
        assert_eq!(
            outcome("deny", "closed", Some("completed"), &["deny", "duplicate"]),
            VOID
        );
        assert_eq!(
            outcome("deny", "closed", None, &["deny", "already included"]),
            GRANTED
        );
    }

    #[test]
    fn reads_exceptions_by_list_kind() {
        let text = "! c\n@@||ok.example.com^\n@@||opt.example.com^$important\n@@||path.example.com/js/a.js\n@@||*.wild.com^\n||blocked.com^\n";
        assert_eq!(
            exceptions(text, ListKind::Dns),
            [
                ("ok.example.com".to_string(), DNS),
                ("opt.example.com".to_string(), DNS)
            ]
        );
        assert_eq!(exceptions(text, ListKind::Content).len(), 3);
        assert_eq!(
            exceptions("# x\nallowed.example.com\n", ListKind::Plain),
            [("allowed.example.com".to_string(), DNS_EXACT)]
        );
    }
}
