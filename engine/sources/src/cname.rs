use regex::Regex;
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::Value;
use std::sync::LazyLock;
use stella_core::known::Known;
use stella_core::psl::Psl;

pub const ADGUARD_TRACKERS: &str = "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers_justdomains.txt";
pub const ADGUARD_ADS: &str = "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.json";
pub const ADGUARD_ADS_MIN: usize = 5;
pub const ADGUARD_MAIL: &str = "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.json";
pub const ADGUARD_MAIL_MIN: usize = 3;
pub const ADGUARD_RISKY: &[&str] = &[
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.json",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.json",
];
pub const ADGUARD_RISKY_MIN: usize = 3;

pub fn overlaps(a: &str, b: &str) -> bool {
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

static GENERIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|\.)(googlehosted\.com|hichina\.com|gname\.net|cdn77\.org|amazon\.com|a2z\.com|taobao\.com|alibabadns\.com|aliyuncs\.com|aliyuncsslbintl\.com|kunlun[a-z0-9]*\.com|railway\.app|azurecontainerapps\.io|awsapprunner\.com|yunjiasu-cdn\.net|ksyuncdn\.com|byteoversea\.net|cdnfree\.org|dnsapi[0-9]*\.com|smoxycdn\.net|yjs-cdn\.com|vercel-dns[0-9-]*\.com|netlify\.app|onrender\.com|fly\.dev|herokudns\.com|ondigitalocean\.app|cloudapp\.azure\.com|windows\.net|qiniudns\.com|tdnsstic[0-9]*\.cn|jomodns\.com|ovscdns\.com|cdngslb\.com|kasserver\.com|cdnhwc[0-9]*\.com|wpengine\.com|myshopify\.com|shopify\.com|squarespace\.com|wixdns\.net|github\.io)$")
        .expect("GENERIC regex")
});

fn brands(zones: &FxHashSet<String>) -> usize {
    zones
        .iter()
        .filter_map(|z| z.split('.').next())
        .collect::<FxHashSet<_>>()
        .len()
}

pub fn generic(suffix: &str) -> bool {
    GENERIC.is_match(suffix) || crate::variants::infrastructure(suffix)
}

#[derive(Clone, Debug, PartialEq)]
pub struct Vendor {
    pub suffix: String,
    pub listed: usize,
    pub background: usize,
    pub source: &'static str,
}

pub fn parent(name: &str) -> Option<&str> {
    let (_, rest) = name.split_once('.')?;
    rest.contains('.').then_some(rest)
}

pub fn plain_domains(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with(['#', '!']))
        .filter_map(stella_core::name::normalize)
        .filter(|h| h.contains('.'))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

pub fn disguised_targets(json: &[u8], min: usize) -> Vec<(String, usize)> {
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(json) else {
        return Vec::new();
    };
    let mut count: FxHashMap<String, usize> = FxHashMap::default();
    for t in m.values().filter_map(Value::as_str) {
        if let Some(p) = stella_core::name::normalize(t).as_deref().and_then(parent) {
            *count.entry(p.to_string()).or_default() += 1;
        }
    }
    let mut v: Vec<(String, usize)> = count.into_iter().filter(|(_, n)| *n >= min).collect();
    v.sort_unstable();
    v
}

#[derive(Default)]
pub struct Tally {
    listed: FxHashMap<String, FxHashSet<String>>,
    background: FxHashMap<String, FxHashSet<String>>,
    listed_zones: FxHashSet<String>,
    background_zones: FxHashSet<String>,
}

pub const SEED_MAX_BACKGROUND: usize = 2;

impl Tally {
    pub fn add(&mut self, psl: &Psl, host: &str, chain: &[&str], listed: bool) {
        let zone = psl.icann_regdom_or_self(host);
        let main = host == zone || host.strip_prefix("www.") == Some(zone);
        if listed && main {
            return;
        }
        let (side, zones) = if listed {
            (&mut self.listed, &mut self.listed_zones)
        } else {
            (&mut self.background, &mut self.background_zones)
        };
        zones.insert(zone.to_string());
        for link in chain {
            if psl.icann_regdom_or_self(link) == zone {
                continue;
            }
            for s in stella_core::name::suffixes(link)
                .skip(1)
                .filter(|s| psl.regdom(s).is_some())
            {
                side.entry(s.to_string())
                    .or_default()
                    .insert(zone.to_string());
            }
        }
    }

    pub fn background_of(&self, suffix: &str) -> usize {
        self.background.get(suffix).map_or(0, FxHashSet::len)
    }

    pub fn vendors(&self, known: &Known, min_zones: usize, min_lift: f64) -> Vec<Vendor> {
        let nl = self.listed_zones.len().max(1) as f64;
        let nb = self.background_zones.len().max(1) as f64;
        let mut v: Vec<Vendor> = self
            .listed
            .iter()
            .filter(|(s, z)| brands(z) >= min_zones && !known.contains(s) && !generic(s))
            .filter_map(|(s, z)| {
                let background = self
                    .background
                    .get(s)
                    .map_or(0, |b| b.difference(z).count());
                let lift = (z.len() as f64 / nl) / ((background as f64 + 1.0) / nb);
                (lift >= min_lift).then(|| Vendor {
                    suffix: s.clone(),
                    listed: z.len(),
                    background,
                    source: "learned",
                })
            })
            .collect();
        v.sort_unstable_by_key(|x| x.suffix.len());
        let mut kept: Vec<Vendor> = Vec::with_capacity(v.len());
        for x in v {
            if !kept
                .iter()
                .any(|k| x.suffix.ends_with(&format!(".{}", k.suffix)))
            {
                kept.push(x);
            }
        }
        kept.sort_unstable_by(|a, b| {
            b.listed
                .cmp(&a.listed)
                .then_with(|| a.suffix.cmp(&b.suffix))
        });
        kept
    }
}

pub fn matched<'a>(
    psl: &Psl,
    host: &str,
    chain: &[&'a str],
    vendors: &'a FxHashMap<String, Vendor>,
) -> Option<(&'a str, &'a Vendor)> {
    let zone = psl.icann_regdom_or_self(host);
    chain
        .iter()
        .filter(|l| psl.icann_regdom_or_self(l) != zone)
        .find_map(|l| {
            stella_core::name::suffixes(l)
                .skip(1)
                .find_map(|s| vendors.get(s))
                .map(|v| (*l, v))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learns_vendor_suffixes_against_background() {
        let psl = Psl::parse("com\nnet\n");
        let known = Known::default();
        let mut t = Tally::default();
        for i in 0..10 {
            let host = format!("metrics.shop{i}.com");
            t.add(&psl, &host, &[&format!("c{i}.t.vendor.net")], true);
            t.add(&psl, &format!("www.site{i}.com"), &["edge.cdn.net"], false);
            t.add(&psl, &format!("x.shop{i}.com"), &["edge.cdn.net"], true);
            t.add(
                &psl,
                &format!("a.shop{i}.com"),
                &[&format!("b.shop{i}.com")],
                true,
            );
        }
        let v = t.vendors(&known, 8, 5.0);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].suffix, "vendor.net");
        assert_eq!(t.background_of("cdn.net"), 10);
        let map: FxHashMap<String, Vendor> = v.into_iter().map(|v| (v.suffix.clone(), v)).collect();
        let hit = matched(&psl, "stats.new.com", &["c99.t.vendor.net"], &map);
        assert_eq!(hit.map(|(l, _)| l), Some("c99.t.vendor.net"));
        assert!(matched(&psl, "www.new.com", &["edge.cdn.net"], &map).is_none());
        let ads =
            br#"{"a.x.com":"c1.ads.vendor.io","b.y.com":"c2.ads.vendor.io","c.z.com":"other.io"}"#;
        assert_eq!(
            disguised_targets(ads, 2),
            [("ads.vendor.io".to_string(), 2)]
        );
        assert_eq!(plain_domains("! t\n||x\na8.net\n"), ["a8.net"]);
        assert!(generic("ghs.googlehosted.com") && generic("rsc.cdn77.org"));
        assert!(!generic("eulerian.net") && !generic("trytagging.com"));
        assert!(
            overlaps("sfmc-content.com", "image-sap.sfmc-content.com")
                && overlaps("bnc.lt", "bnc.lt")
        );
        assert!(!overlaps("bnc.lt", "xbnc.lt"));
    }
}
