use crate::deob::{self, URL_WITH_PATH};
use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use std::sync::LazyLock;

const MEMBER_CAP: u64 = 120 * 1024 * 1024;
const NESTED_DEPTH: u8 = 2;
pub const AXML_HOST: &str = "axml-host";

static MEMBERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^classes\d*\.dex$|\.so$|^resources\.arsc$|^assets/|^res/raw/|\.json$|\.js$|\.xml$|\.bin$|\.dat$)")
        .expect("MEMBERS regex")
});

const GAME_ENGINES: &[&str] = &[
    "libunity.so",
    "libil2cpp.so",
    "libue4.so",
    "libunreal.so",
    "libcocos2d",
    "libgodot_android.so",
    "assets/bin/data/managed/",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Found {
    pub method: String,
    pub url: String,
    pub member: String,
}

pub enum Outcome {
    Scanned(Vec<Found>),
    Game(String),
}

fn members<R: Read + Seek>(
    zip: &mut zip::ZipArchive<R>,
    prefix: &str,
    depth: u8,
    out: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    for i in 0..zip.len() {
        let mut f = match zip.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if f.is_dir() || f.size() > MEMBER_CAP {
            continue;
        }
        let Ok(name) = f.name().map(|n| n.into_owned()) else {
            continue;
        };
        let nested = name.to_ascii_lowercase().ends_with(".apk");
        if !nested && !MEMBERS.is_match(&name) {
            continue;
        }
        let mut data = Vec::with_capacity(f.size() as usize);
        if f.read_to_end(&mut data).is_err() {
            continue;
        }
        drop(f);
        if nested {
            if depth < NESTED_DEPTH
                && let Ok(mut inner) = zip::ZipArchive::new(Cursor::new(data))
            {
                members(&mut inner, &format!("{prefix}{name}!"), depth + 1, out)?;
            }
            continue;
        }
        out.push((format!("{prefix}{name}"), data));
    }
    Ok(())
}

pub fn game_engine(names: &[String]) -> Option<String> {
    names.iter().find_map(|n| {
        let l = n.to_ascii_lowercase();
        GAME_ENGINES
            .iter()
            .find(|g| l.contains(*g))
            .map(|g| (*g).to_string())
    })
}

pub fn scan(path: &Path) -> Result<Outcome> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(path)?)?;
    let mut list = Vec::new();
    members(&mut zip, "", 0, &mut list)?;
    let names: Vec<String> = list.iter().map(|(n, _)| n.clone()).collect();
    if let Some(engine) = game_engine(&names) {
        return Ok(Outcome::Game(engine));
    }
    let mut found: Vec<Found> = list
        .par_iter()
        .flat_map_iter(|(name, data)| {
            let mut v = Vec::new();
            for m in URL_WITH_PATH.find_iter(data) {
                v.push(Found {
                    method: "plain".into(),
                    url: String::from_utf8_lossy(m.as_bytes())
                        .trim_end_matches('.')
                        .to_string(),
                    member: name.clone(),
                });
            }
            if let Some(strings) = crate::axml::strings(data) {
                let text = strings.join("\n");
                for m in URL_WITH_PATH.find_iter(text.as_bytes()) {
                    v.push(Found {
                        method: "axml".into(),
                        url: String::from_utf8_lossy(m.as_bytes())
                            .trim_end_matches('.')
                            .to_string(),
                        member: name.clone(),
                    });
                }
                if crate::axml::network_config(&strings) {
                    for h in strings.iter().filter_map(|s| crate::axml::host_like(s)) {
                        v.push(Found {
                            method: AXML_HOST.into(),
                            url: format!("https://{h}/"),
                            member: name.clone(),
                        });
                    }
                }
            }
            let dex = name.to_ascii_lowercase().ends_with(".dex");
            deob::scan(data, dex, &mut |method, url| {
                v.push(Found {
                    method: method.into(),
                    url,
                    member: name.clone(),
                });
            });
            v.into_iter()
        })
        .collect();
    found.sort_unstable();
    found.dedup_by(|a, b| a.method == b.method && a.url == b.url);
    Ok(Outcome::Scanned(found))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn apk(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (n, d) in entries {
            w.start_file(*n, zip::write::SimpleFileOptions::default())
                .expect("start");
            w.write_all(d).expect("write");
        }
        w.finish().expect("finish").into_inner()
    }

    #[test]
    fn scans_nested_members_and_skips_games() -> Result<()> {
        let inner = apk(&[("classes.dex", b"\x00https://evt.vendor.io/v2/track?x=1\x00")]);
        let outer = apk(&[
            ("base.apk", &inner),
            (
                "assets/c.json",
                b"{\"u\":\"aHR0cHM6Ly9iLnZlbmRvci5pby9sb2c=\"}",
            ),
            ("icon.png", b"https://no.png/x"),
        ]);
        let dir = std::env::temp_dir().join(format!("stella-apk-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let p = dir.join("t.pkg");
        std::fs::write(&p, &outer)?;
        let Outcome::Scanned(found) = scan(&p)? else {
            panic!("game")
        };
        let urls: Vec<(&str, &str)> = found
            .iter()
            .map(|f| (f.method.as_str(), f.url.as_str()))
            .collect();
        assert_eq!(
            urls,
            [
                ("b64", "https://b.vendor.io/log"),
                ("plain", "https://evt.vendor.io/v2/track")
            ]
        );
        assert_eq!(found[1].member, "base.apk!classes.dex");
        std::fs::write(&p, apk(&[("lib/arm64-v8a/libil2cpp.so", b"x")]))?;
        assert!(matches!(scan(&p)?, Outcome::Game(_)));
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
