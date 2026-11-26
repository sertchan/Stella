use rustc_hash::FxHashSet;
use std::io::{Cursor, Read};

pub const ARCHIVE_CAP: usize = 200 * 1024 * 1024;
const MEMBER_CAP: u64 = 64 * 1024 * 1024;
const NESTED_DEPTH: u8 = 2;
const AR_MAGIC: &[u8] = b"!<arch>\n";
const AR_HEADER: usize = 60;
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
    ".xcprivacy",
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
    File(std::path::PathBuf),
    Pod(String),
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
            "pod" if clean(rest) && !rest.contains('/') => Some(Self::Pod(rest.to_string())),
            "file" => {
                let p = std::path::PathBuf::from(rest);
                (p.is_absolute() && !rest.contains("..")).then_some(Self::File(p))
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
            Self::File(p) => format!("file:{}", p.display()),
            Self::Pod(p) => format!("pod:{p}"),
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
            Self::File(p) => p.display().to_string(),
            Self::Pod(p) => pod_versions_url(p),
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
            Self::Pod(p) => pod_latest(&String::from_utf8_lossy(index), p)
                .map(|v| vec![pod_spec_url(p, &v)])
                .unwrap_or_default(),
            Self::Github { .. } | Self::File(_) => Vec::new(),
        }
    }
}

fn pod_shard(name: &str) -> [char; 3] {
    let h: Vec<char> = stella_core::md5::hex(name.as_bytes()).chars().collect();
    [h[0], h[1], h[2]]
}

pub fn pod_versions_url(name: &str) -> String {
    let [a, b, c] = pod_shard(name);
    format!("https://cdn.cocoapods.org/all_pods_versions_{a}_{b}_{c}.txt")
}

pub fn pod_spec_url(name: &str, version: &str) -> String {
    let [a, b, c] = pod_shard(name);
    format!("https://cdn.cocoapods.org/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json")
}

pub fn pod_latest(versions: &str, name: &str) -> Option<String> {
    let line = versions
        .lines()
        .find(|l| l.split('/').next() == Some(name))?;
    let last = line
        .split('/')
        .skip(1)
        .filter(|v| !v.contains('-'))
        .last()?;
    clean(last).then(|| last.to_string())
}

pub fn pod_archive_urls(spec: &[u8]) -> Vec<String> {
    let Some(v) = json(spec) else {
        return Vec::new();
    };
    if let Some(http) = v.pointer("/source/http").and_then(|h| h.as_str()) {
        return if http.starts_with("https://") {
            vec![http.to_string()]
        } else {
            Vec::new()
        };
    }
    let git = v
        .pointer("/source/git")
        .and_then(|g| g.as_str())
        .unwrap_or_default();
    let tag = v
        .pointer("/source/tag")
        .and_then(|t| t.as_str())
        .unwrap_or_default();
    let Some(repo) = git.strip_prefix("https://github.com/") else {
        return Vec::new();
    };
    let repo = repo.trim_end_matches(".git");
    if tag.is_empty() || !clean(tag) || !clean(repo) {
        return Vec::new();
    }
    vec![format!(
        "https://codeload.github.com/{repo}/zip/refs/tags/{tag}"
    )]
}

pub fn privacy_domains(plist: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(plist);
    let Some(start) = text.find("<key>NSPrivacyTrackingDomains</key>") else {
        return Vec::new();
    };
    let rest = &text[start..];
    let Some(open) = rest.find("<array>") else {
        return Vec::new();
    };
    let end = rest[open..]
        .find("</array>")
        .map_or(rest.len(), |e| open + e);
    rest[open..end]
        .split("<string>")
        .skip(1)
        .filter_map(|s| s.split("</string>").next())
        .filter_map(|d| stella_core::name::normalize(d.trim()))
        .collect()
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
        if name.to_ascii_lowercase().ends_with("privacyinfo.xcprivacy") {
            set.extend(privacy_domains(&buf));
        }
        set.extend(crate::scripts::hosts_in_script(&buf));
    }
    true
}

fn scan_ar(data: &[u8], set: &mut FxHashSet<String>) -> bool {
    let mut pos = AR_MAGIC.len();
    let mut any = false;
    while pos + AR_HEADER <= data.len() {
        let header = &data[pos..pos + AR_HEADER];
        let name = String::from_utf8_lossy(&header[..16])
            .trim()
            .trim_end_matches('/')
            .to_string();
        let Some(size) = String::from_utf8_lossy(&header[48..58])
            .trim()
            .parse::<usize>()
            .ok()
        else {
            break;
        };
        let start = pos + AR_HEADER;
        let Some(body) = data.get(start..start + size) else {
            break;
        };
        any = true;
        if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            scan_tgz(body, set);
        }
        pos = start + size + size % 2;
    }
    any
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
    } else if data.starts_with(AR_MAGIC) {
        scan_ar(data, &mut set)
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

static MAVEN_COORD: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"\b([a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)+):([a-zA-Z0-9_.-]+)\b")
        .expect("MAVEN_COORD regex")
});

pub fn maven_coords(text: &str) -> Vec<String> {
    let mut out: Vec<String> = MAVEN_COORD
        .captures_iter(text)
        .filter_map(|c| {
            let (g, a) = (c.get(1)?.as_str(), c.get(2)?.as_str());
            let version = a.chars().all(|ch| ch.is_ascii_digit() || ch == '.');
            (!version).then(|| format!("maven:{g}:{a}"))
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

pub fn index_links(json: &str, base: &str, part: &str) -> Vec<String> {
    let mut out: Vec<String> = serde_json::from_str::<Vec<String>>(json)
        .unwrap_or_default()
        .into_iter()
        .filter(|h| h.contains(part) && h.starts_with(base))
        .map(|h| h.split(['?', '#']).next().unwrap_or(&h).to_string())
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_index_links_and_maven_coordinates() {
        let json = r#"["https://play.google.com/sdks/details/com-appsflyer?hl=en","https://play.google.com/store","https://play.google.com/sdks/details/com-appsflyer"]"#;
        assert_eq!(
            index_links(json, "https://play.google.com/sdks", "/details/"),
            ["https://play.google.com/sdks/details/com-appsflyer"]
        );
        let text = "Maven: com.appsflyer:af-android-sdk\nVersion 6.15.0\nAlso com.google.android.gms:play-services-ads and 1.2:3.4";
        assert_eq!(
            maven_coords(text),
            [
                "maven:com.appsflyer:af-android-sdk",
                "maven:com.google.android.gms:play-services-ads"
            ]
        );
    }

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
        let tgz = gz.finish().expect("gz");
        assert_eq!(hosts_in_archive(&tgz).expect("tgz"), ["api.track.io"]);
        assert!(hosts_in_archive(b"plain text").is_none());
        let mut ipk = b"!<arch>\n".to_vec();
        for (name, body) in [("debian-binary", &b"2.0\n"[..]), ("data.tar.gz", &tgz[..])] {
            ipk.extend_from_slice(
                format!(
                    "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    0,
                    0,
                    0,
                    100644,
                    body.len()
                )
                .as_bytes(),
            );
            ipk.extend_from_slice(body);
            if body.len() % 2 == 1 {
                ipk.push(b'\n');
            }
        }
        assert_eq!(hosts_in_archive(&ipk).expect("ipk"), ["api.track.io"]);
        assert!(matches!(
            Package::parse("file:/srv/tv/app.ipk"),
            Some(Package::File(_))
        ));
        assert!(Package::parse("file:relative.ipk").is_none());
        assert_eq!(
            pod_versions_url("AppsFlyerFramework"),
            format!("https://cdn.cocoapods.org/all_pods_versions_{}.txt", {
                let h = stella_core::md5::hex(b"AppsFlyerFramework");
                format!("{}_{}_{}", &h[0..1], &h[1..2], &h[2..3])
            })
        );
        assert_eq!(
            pod_latest(
                "Other/1.0\nAppsFlyerFramework/6.0.0/6.15.1/6.16.0-beta\n",
                "AppsFlyerFramework"
            )
            .as_deref(),
            Some("6.15.1")
        );
        assert_eq!(
            pod_archive_urls(br#"{"source":{"git":"https://github.com/AppsFlyerSDK/AppsFlyerFramework.git","tag":"6.15.1"}}"#),
            ["https://codeload.github.com/AppsFlyerSDK/AppsFlyerFramework/zip/refs/tags/6.15.1"]
        );
        assert_eq!(
            pod_archive_urls(br#"{"source":{"http":"https://cdn.vendor.io/sdk.zip"}}"#),
            ["https://cdn.vendor.io/sdk.zip"]
        );
        let plist = br#"<plist><dict><key>NSPrivacyTracking</key><true/><key>NSPrivacyTrackingDomains</key><array><string>t.vendor.io</string><string> Ads.Vendor.io </string></array><key>Other</key><array><string>no.io</string></array></dict></plist>"#;
        assert_eq!(privacy_domains(plist), ["t.vendor.io", "ads.vendor.io"]);
    }
}
