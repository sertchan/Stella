use regex::Regex;
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::LazyLock;

static ID_KEYS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|&)(?:uid|cid|tid|pid|sid|vid|event|ev|evt|ea|ec|fbp|_ga|gclid|uuid|visitor|session|client_?id|user_?id|did|aid|tagid|pixel_?id|account|adid|cb|rnd|random|ord)=")
        .expect("ID_KEYS regex")
});
static COLLECTOR_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"pixel|beacon|collect|track|event|log|ping|hit|imp|sync|match|\.gif")
        .expect("COLLECTOR_PATH regex")
});

pub const MIN_SITES: usize = 2;
const PREVALENT: usize = 5;
const POST_SHARE: f64 = 0.2;
const ID_SHARE: f64 = 0.3;
const PATH_SHARE: f64 = 0.3;

#[derive(Default)]
struct Acc {
    sites: FxHashSet<String>,
    requests: usize,
    post: usize,
    id: usize,
    path: usize,
}

#[derive(Debug, PartialEq)]
pub struct Score {
    pub host: String,
    pub sites: usize,
    pub requests: usize,
    pub post: f64,
    pub id: f64,
    pub path: f64,
    pub score: u8,
}

#[derive(Default)]
pub struct Scorer {
    acc: FxHashMap<String, Acc>,
}

impl Scorer {
    pub fn add(&mut self, site: &str, method: &str, url: &str) {
        let Some(host) = stella_core::name::host_of_url(url) else {
            return;
        };
        let host = host.to_ascii_lowercase();
        let rest = url.split_once("://").map_or("", |(_, r)| r);
        let path_and_query = rest
            .find('/')
            .map_or("", |i| &rest[i..])
            .to_ascii_lowercase();
        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((&path_and_query, ""));
        let a = self.acc.entry(host).or_default();
        if !a.sites.contains(site) {
            a.sites.insert(site.to_string());
        }
        a.requests += 1;
        a.post += usize::from(method.eq_ignore_ascii_case("POST"));
        a.id += usize::from(ID_KEYS.is_match(query));
        a.path += usize::from(COLLECTOR_PATH.is_match(path));
    }

    pub fn finish(self) -> Vec<Score> {
        let mut out: Vec<Score> = self
            .acc
            .into_iter()
            .filter(|(_, a)| a.sites.len() >= MIN_SITES)
            .map(|(host, a)| {
                let n = a.requests as f64;
                let (post, id, path) = (a.post as f64 / n, a.id as f64 / n, a.path as f64 / n);
                let score = u8::from(a.sites.len() >= PREVALENT)
                    + u8::from(post > POST_SHARE)
                    + u8::from(id > ID_SHARE)
                    + u8::from(path > PATH_SHARE);
                Score {
                    host,
                    sites: a.sites.len(),
                    requests: a.requests,
                    post,
                    id,
                    path,
                    score,
                }
            })
            .collect();
        out.sort_unstable_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then(b.sites.cmp(&a.sites))
                .then_with(|| a.host.cmp(&b.host))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_signal_adds_one_point_only_above_its_share() {
        let score = |reqs: &[(&str, &str, &str)]| {
            let mut s = Scorer::default();
            for (site, method, url) in reqs {
                s.add(site, method, url);
            }
            s.finish().into_iter().map(|x| x.score).collect::<Vec<_>>()
        };
        assert_eq!(
            score(&[
                ("a", "GET", "https://h.io/x"),
                ("b", "GET", "https://h.io/y")
            ]),
            [0]
        );
        assert_eq!(
            score(&[
                ("a", "POST", "https://h.io/x"),
                ("b", "GET", "https://h.io/y")
            ]),
            [1]
        );
        assert_eq!(
            score(&[
                ("a", "GET", "https://h.io/x?uid=1"),
                ("b", "GET", "https://h.io/pixel.gif"),
            ]),
            [2]
        );
        assert_eq!(
            score(&[
                ("a", "GET", "https://h.io/x?uid=1"),
                ("a", "GET", "https://h.io/a"),
                ("a", "GET", "https://h.io/b"),
                ("b", "GET", "https://h.io/c"),
            ]),
            [0]
        );
        assert!(score(&[("a", "POST", "https://solo.io/collect?uid=1")]).is_empty());
        assert!(score(&[("a", "GET", "not a url"), ("b", "GET", "")]).is_empty());
    }

    #[test]
    fn scores_collectors_above_assets() {
        let mut s = Scorer::default();
        for site in ["a", "b", "c", "d", "e"] {
            s.add(site, "POST", "https://c.vendor.io/v1/collect?cid=1&ev=pv");
            s.add(site, "GET", "https://cdn.vendor.io/lib.js");
        }
        s.add("a", "GET", "https://only.one.io/x");
        let out = s.finish();
        assert_eq!((out[0].host.as_str(), out[0].score), ("c.vendor.io", 4));
        assert_eq!((out[1].host.as_str(), out[1].score), ("cdn.vendor.io", 1));
        assert_eq!(out.len(), 2);
    }
}
