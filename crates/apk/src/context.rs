use anyhow::{Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

const JADX_LIMIT: Duration = Duration::from_secs(900);
const CONTEXT_LINES: usize = 3;
const MAX_LINES_PER_HOST: usize = 60;

fn unpack_nested(pkg: &Path, out: &Path) -> Result<Vec<PathBuf>> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(pkg)?)?;
    let mut inner = Vec::new();
    let mut has_dex = false;
    for i in 0..zip.len() {
        let Ok(mut f) = zip.by_index(i) else { continue };
        let Ok(name) = f.name().map(|n| n.into_owned()) else {
            continue;
        };
        if name.ends_with(".dex") {
            has_dex = true;
        }
        if !name.to_ascii_lowercase().ends_with(".apk") || name.contains("..") || name.contains('/')
        {
            continue;
        }
        let dst = out.join(&name);
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        std::fs::write(&dst, data)?;
        inner.push(dst);
    }
    if has_dex {
        inner.push(pkg.to_path_buf());
    }
    Ok(inner)
}

fn java_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            java_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "java") {
            out.push(p);
        }
    }
}

pub fn snippets(root: &Path, hosts: &[String]) -> Vec<(String, String)> {
    let mut files = Vec::new();
    java_files(root, &mut files);
    let mut out: Vec<(String, Vec<String>)> =
        hosts.iter().map(|h| (h.clone(), Vec::new())).collect();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        if !hosts.iter().any(|h| text.contains(h.as_str())) {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
        for (host, acc) in out.iter_mut() {
            for (i, l) in lines.iter().enumerate() {
                if acc.len() >= MAX_LINES_PER_HOST || !l.contains(host.as_str()) {
                    continue;
                }
                let from = i.saturating_sub(CONTEXT_LINES);
                let to = (i + CONTEXT_LINES + 1).min(lines.len());
                for (j, line) in lines.iter().enumerate().take(to).skip(from) {
                    acc.push(format!("{rel}:{}: {}", j + 1, line.trim_end()));
                }
                acc.push("--".into());
            }
        }
    }
    out.into_iter().map(|(h, v)| (h, v.join("\n"))).collect()
}

pub async fn decompile(pkg: &Path, work: &Path) -> Result<PathBuf> {
    let unpacked = work.join("unpacked");
    let out = work.join("jadx");
    let _ = tokio::fs::remove_dir_all(work).await;
    tokio::fs::create_dir_all(&unpacked).await?;
    let inputs = {
        let pkg = pkg.to_path_buf();
        let unpacked = unpacked.clone();
        tokio::task::spawn_blocking(move || unpack_nested(&pkg, &unpacked)).await??
    };
    for (i, input) in inputs.iter().enumerate() {
        let mut cmd = Command::new("jadx");
        cmd.arg("-d")
            .arg(out.join(i.to_string()))
            .args([
                "-j",
                "2",
                "--no-res",
                "--show-bad-code",
                "--log-level",
                "ERROR",
            ])
            .arg(input)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let _ = tokio::time::timeout(JADX_LIMIT, cmd.status())
            .await
            .context("jadx timeout");
    }
    let _ = tokio::fs::remove_dir_all(&unpacked).await;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn collects_lines_around_hosts() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!("stella-ctx-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("a/b"))?;
        std::fs::write(
            dir.join("a/b/X.java"),
            "class X {\n  int a;\n  String U = \"https://t.vendor.io/v1/log\";\n  int b;\n}\n",
        )?;
        let got = super::snippets(&dir, &["t.vendor.io".to_string(), "none.io".to_string()]);
        assert!(got[0].1.contains("a/b/X.java:3:   String U"));
        assert!(got[1].1.is_empty());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
