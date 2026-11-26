use rustc_hash::FxHashSet;
use std::sync::LazyLock;

const TRACKING: &[&str] = &[
    "ab",
    "abtest",
    "ad",
    "ads",
    "adserv",
    "adserver",
    "adsrv",
    "adx",
    "analytic",
    "analytics",
    "apm",
    "attribution",
    "audience",
    "beacon",
    "bi",
    "bid",
    "bidder",
    "bids",
    "cdp",
    "click",
    "clicks",
    "clk",
    "cm",
    "collect",
    "collector",
    "conv",
    "conversion",
    "count",
    "counter",
    "crash",
    "crashes",
    "data",
    "datacollect",
    "dc",
    "dmp",
    "dsp",
    "ev",
    "event",
    "events",
    "exp",
    "experiment",
    "fingerprint",
    "fp",
    "gtm",
    "heatmap",
    "hit",
    "hits",
    "id5",
    "identity",
    "imp",
    "impression",
    "ingest",
    "insight",
    "insights",
    "intake",
    "log",
    "logger",
    "logging",
    "logs",
    "match",
    "matomo",
    "measure",
    "measurement",
    "metric",
    "metrics",
    "monitor",
    "monitoring",
    "openrtb",
    "ortb",
    "pbs",
    "perf",
    "ping",
    "piwik",
    "pixel",
    "plausible",
    "prebid",
    "px",
    "recording",
    "replay",
    "report",
    "reporting",
    "reports",
    "rtb",
    "rum",
    "segment",
    "sentry",
    "sgtm",
    "smetrics",
    "sp",
    "ssp",
    "sst",
    "stat",
    "statistics",
    "stats",
    "survey",
    "sync",
    "tag",
    "tags",
    "telemetry",
    "tr",
    "track",
    "tracker",
    "tracking",
    "trk",
    "uid",
    "umami",
    "usersync",
];

const SKIP: &[&str] = &[
    "admin",
    "auth",
    "autodiscover",
    "backup",
    "bak",
    "build",
    "cd",
    "ci",
    "confluence",
    "corp",
    "demo",
    "dev",
    "devel",
    "develop",
    "development",
    "doc",
    "docs",
    "git",
    "gitlab",
    "grafana",
    "imap",
    "int",
    "internal",
    "intranet",
    "jenkins",
    "jira",
    "kibana",
    "legacy",
    "local",
    "localhost",
    "login",
    "mail",
    "mx",
    "old",
    "owa",
    "pop",
    "portal",
    "pre-prod",
    "preprod",
    "preview",
    "qa",
    "sandbox",
    "sbx",
    "smtp",
    "sso",
    "stage",
    "staging",
    "status",
    "stg",
    "test",
    "testing",
    "tst",
    "uat",
    "vpn",
    "webmail",
];

static TRACKING_SET: LazyLock<FxHashSet<&'static str>> =
    LazyLock::new(|| TRACKING.iter().copied().collect());
static SKIP_SET: LazyLock<FxHashSet<&'static str>> =
    LazyLock::new(|| SKIP.iter().copied().collect());

fn pieces(sub: &str) -> impl Iterator<Item = &str> {
    sub.split(['.', '-'])
        .map(|p| p.trim_end_matches(|c: char| c.is_ascii_digit()))
        .filter(|p| !p.is_empty())
}

fn hits(sub: &str, set: &FxHashSet<&'static str>) -> bool {
    if pieces(sub).any(|p| set.contains(p)) {
        return true;
    }
    sub.split('.').any(|label| {
        let parts: Vec<&str> = label.split('-').collect();
        parts.windows(2).any(|w| {
            let joined = format!(
                "{}-{}",
                w[0],
                w[1].trim_end_matches(|c: char| c.is_ascii_digit())
            );
            set.contains(joined.as_str())
        })
    })
}

pub fn tracking(sub: &str) -> bool {
    hits(sub, &TRACKING_SET)
}

pub fn skipped(sub: &str) -> bool {
    hits(sub, &SKIP_SET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_label_pieces() {
        assert!(tracking("sgtm"));
        assert!(tracking("metrics2.eu"));
        assert!(tracking("www-sst"));
        assert!(tracking("ss3.track"));
        assert!(!tracking("trackside"));
        assert!(!tracking("www"));
        assert!(tracking("tr"));
        assert!(!tracking("tm"));
        assert!(skipped("api.staging"));
        assert!(skipped("pre-prod"));
        assert!(skipped("dev2"));
        assert!(!skipped("device"));
    }
}
