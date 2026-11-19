use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

const APTOIDE_META: &str = "https://ws75.aptoide.com/api/7/app/getMeta?package_name=";
const META_CAP: usize = 1024 * 1024;
const PACKAGE_CAP: u64 = 2 * 1024 * 1024 * 1024;
const APKEEP_LIMIT: Duration = Duration::from_secs(900);

pub fn dir(root: &Path, pkg: &str) -> PathBuf {
    root.join(pkg)
}

pub fn file(root: &Path, pkg: &str) -> PathBuf {
    dir(root, pkg).join(format!("{pkg}.pkg"))
}

pub fn valid_package(pkg: &str) -> bool {
    pkg.len() <= 200
        && pkg.contains('.')
        && pkg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
}

fn is_zip(path: &Path) -> bool {
    std::fs::File::open(path)
        .ok()
        .and_then(|f| zip::ZipArchive::new(f).ok())
        .is_some_and(|z| !z.is_empty())
}

async fn aptoide(client: &reqwest::Client, pkg: &str, out: &Path) -> Result<&'static str> {
    let meta = stella_net::client::fetch(client, &format!("{APTOIDE_META}{pkg}"), META_CAP).await?;
    let json: serde_json::Value = serde_json::from_slice(&meta.body).context("aptoide meta")?;
    let url = json
        .pointer("/data/file/path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("aptoide has no file"))?;
    if !url.starts_with("https://") {
        bail!("aptoide file url {url}");
    }
    stella_net::client::download(client, url, out, PACKAGE_CAP).await?;
    Ok("aptoide")
}

async fn apkeep(pkg: &str, out: &Path) -> Result<&'static str> {
    let work = out.with_extension("apkeep");
    let _ = tokio::fs::remove_dir_all(&work).await;
    tokio::fs::create_dir_all(&work).await?;
    let mut cmd = Command::new("apkeep");
    cmd.args([
        "-a",
        pkg,
        "-d",
        "apk-pure",
        "-o",
        "acknowledge_dangers=true,arch=arm64-v8a",
    ])
    .arg(&work)
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .kill_on_drop(true);
    let status = tokio::time::timeout(APKEEP_LIMIT, cmd.status()).await;
    let mut got = None;
    if matches!(status, Ok(Ok(_))) {
        let mut rd = tokio::fs::read_dir(&work).await?;
        if let Some(e) = rd.next_entry().await? {
            got = Some(e.path());
        }
    }
    let result = match got {
        Some(p) => {
            tokio::fs::rename(&p, out).await?;
            Ok("apkpure")
        }
        None => Err(anyhow!("apkeep found nothing")),
    };
    let _ = tokio::fs::remove_dir_all(&work).await;
    result
}

pub async fn fetch(
    client: &reqwest::Client,
    root: &Path,
    pkg: &str,
) -> Result<(PathBuf, &'static str)> {
    if !valid_package(pkg) {
        bail!("bad package name {pkg}");
    }
    let path = file(root, pkg);
    if is_zip(&path) {
        return Ok((path, "kept"));
    }
    tokio::fs::create_dir_all(dir(root, pkg)).await?;
    let mut how = aptoide(client, pkg, &path).await;
    if how.is_err() || !is_zip(&path) {
        let _ = tokio::fs::remove_file(&path).await;
        how = apkeep(pkg, &path).await;
    }
    let how = how?;
    if !is_zip(&path) {
        let _ = tokio::fs::remove_file(&path).await;
        bail!("{pkg}: download is not a zip");
    }
    Ok((path, how))
}
