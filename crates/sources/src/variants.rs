use regex::Regex;
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::LazyLock;
use stella_core::known::Known;
use stella_core::psl::Psl;

const COUNTRIES: &[&str] = &[
    "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "ar", "as", "at", "au", "aw", "az", "ba", "bb",
    "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz",
    "ca", "cd", "cf", "cg", "ch", "ci", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cy", "cz", "de",
    "dj", "dk", "dm", "do", "dz", "ec", "ee", "eg", "er", "es", "et", "eu", "fi", "fj", "fm", "fo",
    "fr", "ga", "gb", "gd", "ge", "gh", "gi", "gl", "gm", "gn", "gr", "gt", "gu", "gy", "hk", "hn",
    "hr", "ht", "hu", "id", "ie", "il", "im", "in", "iq", "ir", "is", "it", "je", "jm", "jo", "jp",
    "ke", "kg", "kh", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu",
    "lv", "ly", "ma", "mc", "md", "me", "mg", "mk", "ml", "mm", "mn", "mo", "mt", "mu", "mv", "mw",
    "mx", "my", "mz", "na", "ne", "ng", "ni", "nl", "no", "np", "nz", "om", "pa", "pe", "pf", "pg",
    "ph", "pk", "pl", "pr", "ps", "pt", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sc", "sd",
    "se", "sg", "si", "sk", "sl", "sn", "so", "sr", "sv", "sy", "sz", "td", "tg", "th", "tj", "tm",
    "tn", "to", "tr", "tt", "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "ve", "vn", "ye", "za",
    "zm", "zw",
];

const REGIONS: &[&str] = &[
    "global",
    "intl",
    "i18n",
    "oversea",
    "overseas",
    "sea",
    "emea",
    "apac",
    "latam",
    "amer",
    "asia",
    "europe",
    "eur",
    "euro",
    "mena",
    "cis",
    "row",
    "ww",
    "world",
    "int",
    "eu1",
    "eu2",
    "eu3",
    "eu4",
    "us1",
    "us2",
    "us3",
    "us4",
    "us5",
    "us6",
    "ap1",
    "ap2",
    "ap3",
    "ap4",
    "in1",
    "au1",
    "jp1",
    "sg1",
    "ca1",
    "uk1",
    "de1",
    "kr1",
    "br1",
    "tr1",
    "ru1",
    "me1",
    "na1",
    "la1",
    "euw",
    "eue",
    "euc",
    "eun",
    "use",
    "usw",
    "usc",
    "use1",
    "use2",
    "usw1",
    "usw2",
    "euw1",
    "euw2",
    "euw3",
    "euc1",
    "eun1",
    "apne",
    "apse",
    "apne1",
    "apse1",
    "apse2",
    "aps1",
    "useast",
    "uswest",
    "useast1",
    "useast2",
    "useast3",
    "useast5",
    "useast8",
    "uswest1",
    "uswest2",
    "useast1a",
    "useast2a",
    "useastred",
    "alisg",
    "alisg2",
    "alicn",
    "alius",
    "alieu",
    "no1a",
    "va",
    "va2",
    "sg2",
    "sg3",
    "my2",
    "maliva",
    "ttp",
    "ttp2",
    "phx",
    "ind",
    "mya",
    "sgp",
    "fra",
    "ams",
    "lon",
    "lhr",
    "nyc",
    "sjc",
    "iad",
    "hkg",
    "nrt",
    "tyo",
    "syd",
    "bom",
    "dxb",
    "ist",
    "gru",
    "cdg",
    "sin",
    "mum",
    "mia",
    "dfw",
    "ord",
    "lax",
    "sea1",
    "waw",
    "mad",
    "mil",
    "fra1",
    "ams1",
    "lon1",
    "nyc1",
    "nyc3",
    "sfo1",
    "sfo2",
    "sfo3",
    "sgp1",
    "tor1",
    "blr1",
    "syd1",
];

const AWS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-central-2",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-southeast-5",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-east-1",
    "sa-east-1",
    "ca-central-1",
    "ca-west-1",
    "me-south-1",
    "me-central-1",
    "af-south-1",
    "il-central-1",
    "mx-central-1",
    "cn-north-1",
    "cn-northwest-1",
];

const GCP: &[&str] = &[
    "us-central1",
    "us-east1",
    "us-east4",
    "us-east5",
    "us-south1",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-west8",
    "europe-west9",
    "europe-west10",
    "europe-west12",
    "europe-north1",
    "europe-central2",
    "europe-southwest1",
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast2",
    "asia-northeast3",
    "asia-south1",
    "asia-south2",
    "asia-southeast1",
    "asia-southeast2",
    "australia-southeast1",
    "me-west1",
    "me-central1",
    "southamerica-east1",
    "northamerica-northeast1",
];

pub const CCTLDS: &[&str] = &[
    "com", "com.tr", "de", "fr", "co.uk", "it", "es", "pl", "nl", "be", "ch", "at", "ru", "ua",
    "ca", "com.au", "com.br", "com.mx", "mx", "cz", "sk", "hu", "ro", "gr", "pt", "se", "dk", "fi",
    "no", "ie", "co.za", "ae", "sa", "com.sa", "in", "co.in", "jp", "co.jp", "kr", "co.kr", "cn",
    "com.cn", "tw", "com.tw", "sg", "com.sg", "my", "com.my", "th", "co.th", "id", "co.id", "ph",
    "com.ph", "vn", "com.vn", "cl", "com.co", "co", "ar", "com.ar", "pe", "com.pe", "bg", "hr",
    "si", "rs", "lt", "lv", "ee", "il", "co.il", "eg", "ma", "kz", "az", "lu", "eu", "nz", "co.nz",
    "hk", "com.hk",
];

const SECOND_LEVEL: &[&str] = &["com", "co", "net", "org", "ac", "or", "ne"];

static INFRA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(edgekey|edgesuite|akadns|akamaiedge|akamaized|akamai|cdn\.cloudflare|b-cdn|amazonaws|cloudfront|azureedge|azurefd|trafficmanager|fastly|fbcdn|cloudapp|azurewebsites|herokuapp|googleusercontent|appspot|run)\.(net|com|app)$")
        .expect("INFRA regex")
});

static GEO: LazyLock<FxHashSet<&'static str>> =
    LazyLock::new(|| COUNTRIES.iter().chain(REGIONS).copied().collect());

pub fn infrastructure(host: &str) -> bool {
    INFRA.is_match(host)
}

fn rebuild(labels: &[&str], i: usize, new: &str) -> String {
    labels
        .iter()
        .enumerate()
        .map(|(k, l)| if k == i { new } else { l })
        .collect::<Vec<_>>()
        .join(".")
}

fn swap_regions(label: &str, family: &[&str], emit: &mut impl FnMut(String)) {
    for r in family.iter().filter(|r| label.contains(*r)) {
        for r2 in family.iter().filter(|r2| *r2 != r) {
            emit(label.replacen(r, r2, 1));
        }
    }
}

pub fn variants(seed: &str, max_num: u32, emit: &mut impl FnMut(String)) {
    if infrastructure(seed) {
        return;
    }
    let labels: Vec<&str> = seed.split('.').collect();
    let mut seen: FxHashSet<String> = FxHashSet::default();
    let mut push = |s: String| {
        if s != seed && seen.insert(s.clone()) {
            emit(s);
        }
    };
    for i in 0..labels.len().saturating_sub(2) {
        let lab = labels[i];
        let mut alt = Vec::new();
        swap_regions(lab, AWS, &mut |l| alt.push(l));
        swap_regions(lab, GCP, &mut |l| alt.push(l));
        let parts: Vec<&str> = lab.split('-').collect();
        let join = |j: usize, new: &str| {
            parts
                .iter()
                .enumerate()
                .map(|(k, p)| {
                    if k == j {
                        new.to_string()
                    } else {
                        (*p).to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("-")
        };
        for (j, part) in parts.iter().enumerate() {
            if GEO.contains(part) {
                for t in GEO.iter().filter(|t| *t != part) {
                    alt.push(join(j, t));
                }
                if parts.len() > 1 {
                    let dropped: Vec<&str> = parts
                        .iter()
                        .enumerate()
                        .filter(|(k, _)| *k != j)
                        .map(|(_, p)| *p)
                        .collect();
                    alt.push(dropped.join("-"));
                }
            }
            if let Some(start) = part.find(|c: char| c.is_ascii_digit()) {
                let len = part[start..]
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(part.len() - start);
                if len <= 3 {
                    let (pre, num, post) = (
                        &part[..start],
                        &part[start..start + len],
                        &part[start + len..],
                    );
                    let n: u32 = num.parse().unwrap_or(0);
                    let top = if n > max_num { n + 5 } else { max_num };
                    for v in 0..=top {
                        let nv = format!("{v:0len$}");
                        if nv != num {
                            alt.push(join(j, &format!("{pre}{nv}{post}")));
                        }
                    }
                }
            }
        }
        for l in alt {
            if !l.is_empty() && !l.starts_with('-') && !l.ends_with('-') {
                push(rebuild(&labels, i, &l));
            }
        }
    }
}

pub fn cctld_twins(host: &str) -> Vec<String> {
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    let brand = if n >= 4 && SECOND_LEVEL.contains(&labels[n - 2]) {
        labels[n - 3]
    } else if n >= 3 {
        labels[n - 2]
    } else {
        return Vec::new();
    };
    CCTLDS
        .iter()
        .map(|t| format!("{}.{brand}.{t}", labels[0]))
        .filter(|c| c != host)
        .collect()
}

pub struct Zone {
    pub zone: String,
    pub listed: Vec<String>,
}

pub fn partial_zones(known: &Known, psl: &Psl) -> Vec<Zone> {
    let mut by_zone: FxHashMap<&str, Vec<&str>> = FxHashMap::default();
    for d in known.domains() {
        let zone = psl.icann_regdom_or_self(d);
        if zone != d {
            by_zone.entry(zone).or_default().push(d);
        }
    }
    let mut out: Vec<Zone> = by_zone
        .into_iter()
        .filter(|(z, _)| !known.contains(z))
        .map(|(z, mut l)| {
            l.sort_unstable();
            Zone {
                zone: z.to_string(),
                listed: l.into_iter().map(str::to_string).collect(),
            }
        })
        .collect();
    out.sort_unstable_by(|a, b| a.zone.cmp(&b.zone));
    out
}

pub fn learned_labels(known: &Known, psl: &Psl, top: usize) -> Vec<(String, usize)> {
    let mut count: FxHashMap<&str, usize> = FxHashMap::default();
    for d in known.domains() {
        let zone = psl.icann_regdom_or_self(d);
        let sub = stella_core::name::subdomain(d, zone);
        let Some(first) = sub.split('.').next().filter(|l| !l.is_empty()) else {
            continue;
        };
        if stella_core::token::tracking(first) && !stella_core::token::skipped(first) {
            *count.entry(first).or_default() += 1;
        }
    }
    let mut v: Vec<(String, usize)> = count.into_iter().map(|(l, n)| (l.to_string(), n)).collect();
    v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(top);
    v
}

pub fn sibling_seed(listed: &[String]) -> Option<&String> {
    listed
        .iter()
        .find(|h| stella_core::token::tracking(h.split('.').next().unwrap_or("")))
        .or_else(|| listed.first())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(seed: &str) -> Vec<String> {
        let mut v = Vec::new();
        variants(seed, 3, &mut |s| v.push(s));
        v
    }

    #[test]
    fn swaps_regions_numbers_and_countries() {
        let v = all("log-eu.tiktokv.com");
        assert!(v.contains(&"log-us.tiktokv.com".to_string()));
        assert!(v.contains(&"log.tiktokv.com".to_string()));
        let v = all("stats3.example.com");
        assert!(v.contains(&"stats0.example.com".to_string()));
        assert!(!v.contains(&"stats3.example.com".to_string()));
        let v = all("t.eu-west-1.collect.example.com");
        assert!(v.contains(&"t.us-east-1.collect.example.com".to_string()));
        assert!(all("x.eu.cloudfront.net").is_empty());
        let t = cctld_twins("sgtm.omio.de");
        assert!(t.contains(&"sgtm.omio.fr".to_string()));
        assert!(cctld_twins("sst.brand.co.uk").contains(&"sst.brand.de".to_string()));
    }

    #[test]
    fn finds_partial_zones_and_labels() {
        let mut k = Known::default();
        k.add(
            "pro",
            "tracking.shop.com\nmetrics.shop.com\nfull.org\na.full.org\n",
        );
        let psl = Psl::parse("com\norg\n");
        let z = partial_zones(&k, &psl);
        assert_eq!(z.len(), 1);
        assert_eq!(z[0].zone, "shop.com");
        let l = learned_labels(&k, &psl, 10);
        assert_eq!(l.len(), 2);
        assert_eq!(
            sibling_seed(&z[0].listed).map(String::as_str),
            Some("metrics.shop.com")
        );
    }
}
