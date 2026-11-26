use rustc_hash::FxHashSet;
use std::io::{Cursor, Read};

pub const ARCHIVE_CAP: usize = 200 * 1024 * 1024;
const MEMBER_CAP: u64 = 64 * 1024 * 1024;
const NESTED_DEPTH: u8 = 2;
const SCANNED: &[&str] = &[
    ".js",
    ".mjs",
    ".cjs",
    ".json",
    ".class",
    ".xml",
    ".properties",
    ".py",
    ".dll",
    ".swift",
    ".m",
    ".h",
    ".kt",
    ".java",
    ".plist",
    ".txt",
    ".dex",
];

#[derive(Debug, PartialEq, Eq)]
pub enum Package {
    Npm(String),
    Maven { group: String, artifact: String },
    Pypi(String),
    Nuget(String),
    Github { owner: String, repo: String },
}

fn clean(s: &str) -> bool {
    !s.is_empty()
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '/'))
}

impl Package {
    pub fn parse(line: &str) -> Option<Self> {
        let (kind, rest) = line.trim().split_once(':')?;
        if !clean(rest.trim()) && !rest.contains(':') {
            return None;
        }
        let rest = rest.trim();
        match kind {
            "npm" if clean(rest) => Some(Self::Npm(rest.to_string())),
            "maven" => {
                let (g, a) = rest.split_once(':')?;
                (clean(g) && clean(a) && !g.contains('/') && !a.contains('/')).then(|| {
                    Self::Maven {
                        group: g.to_string(),
                        artifact: a.to_string(),
                    }
                })
            }
            "pypi" if clean(rest) && !rest.contains('/') => Some(Self::Pypi(rest.to_string())),
            "nuget" if clean(rest) && !rest.contains('/') => {
                Some(Self::Nuget(rest.to_ascii_lowercase()))
            }
            "github" => {
                let (o, r) = rest.split_once('/')?;
                (clean(o) && clean(r) && !r.contains('/')).then(|| Self::Github {
                    owner: o.to_string(),
                    repo: r.to_string(),
                })
            }
            _ => None,
        }
    }

    pub fn key(&self) -> String {
        match self {
            Self::Npm(p) => format!("npm:{p}"),
            Self::Maven { group, artifact } => format!("maven:{group}:{artifact}"),
            Self::Pypi(p) => format!("pypi:{p}"),
            Self::Nuget(p) => format!("nuget:{p}"),
            Self::Github { owner, repo } => format!("github:{owner}/{repo}"),
        }
    }

    pub fn index_url(&self) -> String {
        match self {
            Self::Npm(p) => format!("https://registry.npmjs.org/{p}/latest"),
            Self::Maven { group, artifact } => format!(
                "https://repo1.maven.org/maven2/{}/{artifact}/maven-metadata.xml",
                group.replace('.', "/")
            ),
            Self::Pypi(p) => format!("https://pypi.org/pypi/{p}/json"),
            Self::Nuget(p) => format!("https://api.nuget.org/v3-flatcontainer/{p}/index.json"),
            Self::Github { owner, repo } => {
                format!("https://api.github.com/repos/{owner}/{repo}/zipball")
            }
        }
    }

    pub fn archive_urls(&self, index: &[u8]) -> Vec<String> {
        match self {
            Self::Npm(_) => json(index)
                .and_then(|v| v.pointer("/dist/tarball")?.as_str().map(String::from))
                .into_iter()
                .collect(),
            Self::Maven { group, artifact } => {
                let text = String::from_utf8_lossy(index);
                let Some(v) = tag(&text, "release").or_else(|| tag(&text, "latest")) else {
                    return Vec::new();
                };
                let base = format!(
                    "https://repo1.maven.org/maven2/{}/{artifact}/{v}/{artifact}-{v}",
                    group.replace('.', "/")
                );
                vec![format!("{base}.aar"), format!("{base}.jar")]
            }
            Self::Pypi(_) => json(index)
                .and_then(|v| {
                    let urls = v["urls"].as_array()?;
                    let pick = urls
                        .iter()
                        .find(|u| u["packagetype"] == "bdist_wheel")
                        .or_else(|| urls.first())?;
                    pick["url"].as_str().map(String::from)
                })
                .into_iter()
                .collect(),
            Self::Nuget(p) => json(index)
                .and_then(|v| {
                    let last = v["versions"]
                        .as_array()?
                        .last()?
                        .as_str()?
                        .to_ascii_lowercase();
                    Some(format!(
                        "https://api.nuget.org/v3-flatcontainer/{p}/{last}/{p}.{last}.nupkg"
                    ))
                })
                .into_iter()
                .collect(),
            Self::Github { .. } => Vec::new(),
        }
    }
}

fn json(b: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(b).ok()
}

fn tag(text: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = text.find(&open)? + open.len();
    let end = start + text[start..].find("</")?;
    let v = text[start..end].trim();
    clean(v).then(|| v.to_string())
}

fn scanned(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SCANNED.iter().any(|s| n.ends_with(s)) || !n.rsplit('/').next().unwrap_or("").contains('.')
}

fn nested(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".jar") || n.ends_with(".aar") || n.ends_with(".zip") || n.ends_with(".whl")
}

fn scan_zip(data: &[u8], depth: u8, set: &mut FxHashSet<String>) -> bool {
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(data)) else {
        return false;
    };
    for i in 0..zip.len() {
        let Ok(mut f) = zip.by_index(i) else { continue };
        if f.is_dir() || f.size() > MEMBER_CAP {
            continue;
        }
        let Ok(name) = f.name().map(|n| n.into_owned()) else {
            continue;
        };
        let inner = nested(&name);
        if !inner && !scanned(&name) {
            continue;
        }
        let mut buf = Vec::with_capacity(f.size() as usize);
        if f.read_to_end(&mut buf).is_err() {
            continue;
        }
        if inner {
            if depth < NESTED_DEPTH {
                scan_zip(&buf, depth + 1, set);
            }
            continue;
        }
        set.extend(crate::scripts::hosts_in_script(&buf));
    }
    true
}

fn scan_tgz(data: &[u8], set: &mut FxHashSet<String>) -> bool {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(data)));
    let Ok(entries) = archive.entries() else {
        return false;
    };
    let mut any = false;
    for entry in entries {
        let Ok(mut e) = entry else { break };
        any = true;
        let Ok(path) = e.path().map(|p| p.to_string_lossy().into_owned()) else {
            continue;
        };
        if e.size() > MEMBER_CAP || !scanned(&path) {
            continue;
        }
        let mut buf = Vec::new();
        if e.read_to_end(&mut buf).is_ok() {
            set.extend(crate::scripts::hosts_in_script(&buf));
        }
    }
    any
}

pub fn hosts_in_archive(data: &[u8]) -> Option<Vec<String>> {
    let mut set: FxHashSet<String> = FxHashSet::default();
    let ok = if data.starts_with(b"PK") {
        scan_zip(data, 0, &mut set)
    } else if data.starts_with(&[0x1f, 0x8b]) {
        scan_tgz(data, &mut set)
    } else {
        false
    };
    if !ok {
        return None;
    }
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort_unstable();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zipped(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (n, d) in files {
            w.start_file(*n, zip::write::SimpleFileOptions::default())
                .expect("start");
            w.write_all(d).expect("write");
        }
        w.finish().expect("finish").into_inner()
    }

    #[test]
    fn parses_packages_and_index_files() {
        assert_eq!(
            Package::parse("maven:com.appsflyer:af-android-sdk"),
            Some(Package::Maven {
                group: "com.appsflyer".into(),
                artifact: "af-android-sdk".into()
            })
        );
        assert_eq!(
            Package::parse("npm:@segment/analytics-next").map(|p| p.key()),
            Some("npm:@segment/analytics-next".into())
        );
        assert!(Package::parse("npm:../../etc").is_none());
        assert!(Package::parse("github:a/b/c").is_none());
        let maven = Package::parse("maven:com.adjust.sdk:adjust-android").expect("maven");
        let meta = b"<metadata><versioning><latest>5.1.0</latest><release>5.0.2</release></versioning></metadata>";
        assert_eq!(
            maven.archive_urls(meta)[0],
            "https://repo1.maven.org/maven2/com/adjust/sdk/adjust-android/5.0.2/adjust-android-5.0.2.aar"
        );
        let npm = Package::Npm("x".into());
        assert_eq!(
            npm.archive_urls(
                br#"{"dist":{"tarball":"https://registry.npmjs.org/x/-/x-1.0.0.tgz"}}"#
            ),
            ["https://registry.npmjs.org/x/-/x-1.0.0.tgz"]
        );
        let pypi = Package::Pypi("mixpanel".into());
        let idx = br#"{"urls":[{"packagetype":"sdist","url":"https://files.pythonhosted.org/a.tar.gz"},{"packagetype":"bdist_wheel","url":"https://files.pythonhosted.org/a.whl"}]}"#;
        assert_eq!(
            pypi.archive_urls(idx),
            ["https://files.pythonhosted.org/a.whl"]
        );
        let nuget = Package::Nuget("segment.analytics".into());
        assert_eq!(
            nuget.archive_urls(br#"{"versions":["1.0.0","2.1.0"]}"#),
            [
                "https://api.nuget.org/v3-flatcontainer/segment.analytics/2.1.0/segment.analytics.2.1.0.nupkg"
            ]
        );
    }

    #[test]
    fn scans_nested_aar_and_tgz() {
        let jar = zipped(&[(
            "com/v/Api.class",
            b"\x01\x00\x1bhttps://sdk.vendor.io/v2/ev\x00",
        )]);
        let aar = zipped(&[
            ("classes.jar", &jar),
            ("AndroidManifest.xml", b"<x/>"),
            ("res/a.png", b"https://no.png.io/"),
        ]);
        assert_eq!(hosts_in_archive(&aar).expect("aar"), ["sdk.vendor.io"]);
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let body = b"fetch('https://api.track.io/i')";
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append_data(&mut h, "package/dist/index.js", &body[..])
                .expect("append");
            b.finish().expect("finish");
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).expect("gz");
        assert_eq!(
            hosts_in_archive(&gz.finish().expect("gz")).expect("tgz"),
            ["api.track.io"]
        );
        assert!(hosts_in_archive(b"plain text").is_none());
    }
}
