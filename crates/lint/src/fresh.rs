use crate::report::Finding;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

pub const DAY: i64 = 86_400;

const WHY_LOCK: &str = "Stella builds against the newest compatible release of every crate. Patch and minor releases carry security fixes and bug fixes, and a lock file that lags behind ships known bugs on purpose.";
const WHY_MAJOR: &str = "Direct dependencies follow the newest stable major release. Old majors stop getting fixes, and every month of lag makes the upgrade larger and riskier.";
const WHY_FLAKE: &str = "Nix inputs pin the compiler, the system libraries and every tool. An old pin means an old Rust toolchain and old packages with known security issues.";
const WHY_ACTION: &str = "CI actions run with access to the repository. They are pinned to the commit of their newest stable release, so that fixes arrive and nothing moves without a review.";

fn run(dir: &Path, cmd: &str, args: &[&str]) -> Result<(bool, String, String)> {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("run {cmd}, is it on PATH?"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

pub fn parse_lock_updates(text: &str) -> Vec<(String, String, String)> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            match f[..] {
                ["Updating", name, from, "->", to] => {
                    Some((name.to_string(), from.to_string(), to.to_string()))
                }
                _ => None,
            }
        })
        .collect()
}

pub fn lock(dir: &Path, label: &str) -> Result<Vec<Finding>> {
    let (ok, _, err) = run(dir, "cargo", &["update", "--dry-run"])?;
    if !ok {
        bail!(
            "cargo update --dry-run in {}: {}",
            dir.display(),
            err.trim()
        );
    }
    Ok(parse_lock_updates(&err)
        .into_iter()
        .map(|(name, from, to)| {
            Finding::new("stale-lock", format!("{label} {name}"), WHY_LOCK)
                .found(from)
                .expected(to)
                .fix(format!(
                    "Run cargo update in {label}, build and test, and commit the lock file."
                ))
        })
        .collect())
}

pub fn parse_outdated(text: &str) -> Vec<(String, String, String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let krate = v["crate_name"].as_str().unwrap_or("-").to_string();
        for d in v["dependencies"].as_array().into_iter().flatten() {
            let get = |k: &str| d[k].as_str().unwrap_or("").to_string();
            let (project, latest) = (get("project"), get("latest"));
            if latest.is_empty() || latest == "---" || latest == "Removed" || latest == project {
                continue;
            }
            out.push((krate.clone(), get("name"), project, latest));
        }
    }
    out
}

pub fn majors(dir: &Path, label: &str) -> Result<Vec<Finding>> {
    let (ok, out, err) = run(
        dir,
        "cargo",
        &[
            "outdated",
            "--root-deps-only",
            "--workspace",
            "--format",
            "json",
        ],
    )?;
    if !ok {
        bail!("cargo outdated in {}: {}", dir.display(), err.trim());
    }
    Ok(parse_outdated(&out)
        .into_iter()
        .map(|(krate, name, project, latest)| {
            Finding::new("stale-dependency", format!("{label} {krate} -> {name}"), WHY_MAJOR)
                .found(project)
                .expected(latest.clone())
                .fix(format!(
                    "Raise {name} to {latest} in Cargo.toml, adapt the code to the new API, and run every check."
                ))
        })
        .collect())
}

pub fn lock_times(lock: &str) -> Result<BTreeMap<String, i64>> {
    let v: Value = serde_json::from_str(lock)?;
    let nodes = v["nodes"].as_object().context("flake.lock has no nodes")?;
    Ok(nodes
        .iter()
        .filter_map(|(k, n)| Some((k.clone(), n["locked"]["lastModified"].as_i64()?)))
        .collect())
}

pub fn flake_lag(
    old: &BTreeMap<String, i64>,
    new: &BTreeMap<String, i64>,
    grace_days: i64,
) -> Vec<(String, i64)> {
    old.iter()
        .filter_map(|(k, t)| {
            let lag = (new.get(k)? - t) / DAY;
            (lag > grace_days).then(|| (k.clone(), lag))
        })
        .collect()
}

pub fn flake(dir: &Path, grace_days: i64) -> Result<Vec<Finding>> {
    let tmp = std::env::temp_dir().join(format!("stella-lint-flake-{}.lock", std::process::id()));
    let tmp_s = tmp.to_string_lossy().into_owned();
    let (ok, _, err) = run(
        dir,
        "nix",
        &["flake", "update", "--output-lock-file", &tmp_s],
    )?;
    if !ok {
        bail!("nix flake update: {}", err.trim());
    }
    let old = lock_times(&std::fs::read_to_string(dir.join("flake.lock"))?)?;
    let new = lock_times(&std::fs::read_to_string(&tmp)?)?;
    let _ = std::fs::remove_file(&tmp);
    Ok(flake_lag(&old, &new, grace_days)
        .into_iter()
        .map(|(input, lag)| {
            Finding::new("stale-flake-input", format!("flake.lock {input}"), WHY_FLAKE)
                .found(format!("{lag} days behind its branch"))
                .expected(format!("at most {grace_days} days behind"))
                .fix(format!(
                    "Run nix flake update {input}, run nix flake check and nix build, and commit flake.lock."
                ))
        })
        .collect())
}

pub fn parse_uses(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let rest = l
                .trim()
                .trim_start_matches("- ")
                .strip_prefix("uses:")?
                .trim();
            let (repo, rev) = rest.split_once('@')?;
            (!repo.starts_with('.')).then(|| (repo.to_string(), rev.to_string()))
        })
        .collect()
}

fn gh(dir: &Path, path: &str, jq: &str) -> Result<String> {
    let (ok, out, err) = run(dir, "gh", &["api", path, "--jq", jq])?;
    if !ok {
        bail!("gh api {path}: {}", err.trim());
    }
    Ok(out.trim().to_string())
}

fn yml_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            yml_files(&p, out)?;
        } else if p.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            out.push(p);
        }
    }
    Ok(())
}

pub fn actions(dir: &Path) -> Result<Vec<Finding>> {
    let mut files = Vec::new();
    let github = dir.join(".github");
    if github.is_dir() {
        yml_files(&github, &mut files)?;
    }
    files.sort();
    let mut pins: BTreeMap<(String, String), String> = BTreeMap::new();
    for f in &files {
        let rel = f.strip_prefix(dir).unwrap_or(f).display().to_string();
        for (repo, rev) in parse_uses(&std::fs::read_to_string(f)?) {
            pins.entry((repo, rev)).or_insert(rel.clone());
        }
    }
    let mut out = Vec::new();
    for ((repo, rev), file) in pins {
        let tag = gh(dir, &format!("repos/{repo}/releases/latest"), ".tag_name")?;
        let sha = gh(dir, &format!("repos/{repo}/commits/{tag}"), ".sha")?;
        if rev != sha {
            out.push(
                Finding::new("stale-action", format!("{file} {repo}"), WHY_ACTION)
                    .found(rev.clone())
                    .expected(format!("{sha} ({tag})"))
                    .fix(format!("Replace {repo}@{rev} with {repo}@{sha}.")),
            );
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_update_output() {
        let text = "    Updating crates.io index\n     Locking 2 packages\n    Updating anyhow v1.0.104 -> v1.0.105\n    Updating zip v9.7.3 -> v9.8.2\nwarning: not updating lockfile due to dry run\n";
        assert_eq!(
            parse_lock_updates(text),
            [
                ("anyhow".into(), "v1.0.104".into(), "v1.0.105".into()),
                ("zip".into(), "v9.7.3".into(), "v9.8.2".into())
            ]
        );
    }

    #[test]
    fn parses_cargo_outdated_json() {
        let text = concat!(
            "{\"crate_name\":\"stella\",\"dependencies\":[",
            "{\"name\":\"clap\",\"project\":\"4.6.8\",\"compat\":\"4.6.10\",\"latest\":\"5.0.0\"},",
            "{\"name\":\"tar\",\"project\":\"0.4.46\",\"compat\":\"---\",\"latest\":\"0.4.46\"},",
            "{\"name\":\"old\",\"project\":\"1.0.0\",\"compat\":\"---\",\"latest\":\"Removed\"}]}\n",
            "not json\n"
        );
        assert_eq!(
            parse_outdated(text),
            [(
                "stella".into(),
                "clap".into(),
                "4.6.8".into(),
                "5.0.0".into()
            )]
        );
    }

    #[test]
    fn measures_flake_lag() -> Result<()> {
        let old = lock_times(
            r#"{"nodes":{"nixpkgs":{"locked":{"lastModified":0}},"crane":{"locked":{"lastModified":0}},"root":{}}}"#,
        )?;
        let new = lock_times(&format!(
            r#"{{"nodes":{{"nixpkgs":{{"locked":{{"lastModified":{}}}}},"crane":{{"locked":{{"lastModified":{}}}}}}}}}"#,
            10 * DAY,
            3 * DAY
        ))?;
        assert_eq!(flake_lag(&old, &new, 7), [("nixpkgs".to_string(), 10)]);
        assert!(lock_times("{}").is_err());
        Ok(())
    }

    #[test]
    fn reads_pinned_actions() {
        let yml = "steps:\n  - uses: actions/checkout@abc\n      - uses: ./.github/actions/nix\n    uses: cachix/install-nix-action@def\n  - run: echo uses:x@y\n";
        assert_eq!(
            parse_uses(yml),
            [
                ("actions/checkout".to_string(), "abc".to_string()),
                ("cachix/install-nix-action".to_string(), "def".to_string())
            ]
        );
    }
}
