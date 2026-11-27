use crate::report::{Finding, Section, table};
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

pub const DAY: i64 = 86_400;

const WHY_LOCK: &str = "Stella builds against the newest compatible release of every crate. Patch and minor releases carry security fixes and bug fixes, and a lock file that lags behind ships known bugs on purpose.";
const WHY_MAJOR: &str = "Direct dependencies follow the newest stable major release. Old majors stop getting fixes, and every month of lag makes the upgrade larger and riskier.";
const WHY_FLAKE: &str = "Nix inputs pin the compiler, the system libraries and every tool. An old pin means an old Rust toolchain and old packages with known security issues.";
const WHY_ACTION: &str = "CI actions run with access to the repository. They are pinned to the commit of their newest stable release, so that fixes arrive and nothing moves without a review.";
const WHY_DEPRECATED: &str = "A deprecated action stops getting fixes and its maintainers already point to a replacement. Staying on it means running code in CI that nobody looks after.";

pub type Part = (Section, Vec<Finding>);

pub const WORKSPACE: &str = "engine";

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

fn short(rev: &str) -> String {
    rev.chars().take(12).collect()
}

fn verdict(problems: &[&str]) -> String {
    if problems.is_empty() {
        "ok".to_string()
    } else {
        problems.join(", ")
    }
}

pub fn date(secs: i64) -> String {
    let days = secs.div_euclid(DAY);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub local: bool,
    pub deps: Vec<String>,
}

pub fn lock_packages(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for block in text.split("[[package]]").skip(1) {
        let mut p = Package {
            local: true,
            ..Package::default()
        };
        let mut in_deps = false;
        for line in block.lines().map(str::trim) {
            let value = |key: &str| {
                line.strip_prefix(key)
                    .and_then(|r| r.trim_start().strip_prefix('='))
                    .map(|r| r.trim().trim_matches('"').to_string())
            };
            if in_deps {
                if line.starts_with(']') {
                    in_deps = false;
                } else if let Some(dep) = line.trim_matches([',', '"']).split(' ').next() {
                    p.deps.push(dep.to_string());
                }
            } else if let Some(v) = value("name ") {
                p.name = v;
            } else if let Some(v) = value("version ") {
                p.version = v;
            } else if line.starts_with("source ") {
                p.local = false;
            } else if line.starts_with("dependencies = [") {
                in_deps = !line.ends_with(']');
            }
        }
        out.push(p);
    }
    out
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

pub fn lock(dir: &Path, label: &str) -> Result<Part> {
    let (ok, _, err) = run(dir, "cargo", &["update", "--dry-run"])?;
    if !ok {
        bail!(
            "cargo update --dry-run in {}: {}",
            dir.display(),
            err.trim()
        );
    }
    let packages = std::fs::read_to_string(dir.join("Cargo.lock"))
        .map(|t| lock_packages(&t).len())
        .unwrap_or(0);
    let updates = parse_lock_updates(&err);
    let mut lines = vec![format!(
        "{packages} locked packages, {} with a newer compatible release, from cargo update --dry-run",
        updates.len()
    )];
    if !updates.is_empty() {
        let rows: Vec<[String; 3]> = updates
            .iter()
            .map(|(n, f, t)| [n.clone(), f.clone(), t.clone()])
            .collect();
        lines.extend(table(["package", "locked", "compatible"], &rows));
    }
    let findings = updates
        .into_iter()
        .map(|(name, from, to)| {
            Finding::new("outdated-lockfile", format!("{label} {name}"), WHY_LOCK)
                .found(from)
                .expected(to)
                .fix(format!(
                    "Run cargo update in {label}, build and test, and commit the lock file."
                ))
        })
        .collect();
    Ok((Section::new(label.to_string(), lines), findings))
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

pub fn direct_rows(
    packages: &[Package],
    behind: &[(String, String, String, String)],
) -> (Vec<[String; 4]>, Vec<[String; 4]>) {
    let local: BTreeSet<&str> = packages
        .iter()
        .filter(|p| p.local)
        .map(|p| p.name.as_str())
        .collect();
    let mut versions: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for p in packages.iter().filter(|p| !p.local) {
        versions.entry(&p.name).or_default().push(&p.version);
    }
    let newer: BTreeMap<&str, &str> = behind
        .iter()
        .map(|(_, n, _, l)| (n.as_str(), l.as_str()))
        .collect();
    let mut users: BTreeMap<&str, usize> = BTreeMap::new();
    let mut crates = Vec::new();
    for p in packages.iter().filter(|p| p.local) {
        let deps: BTreeSet<&str> = p
            .deps
            .iter()
            .map(String::as_str)
            .filter(|d| !local.contains(d))
            .collect();
        for d in &deps {
            *users.entry(d).or_default() += 1;
        }
        let late = behind.iter().filter(|(k, ..)| *k == p.name).count();
        crates.push([
            p.name.clone(),
            deps.len().to_string(),
            late.to_string(),
            verdict(if late == 0 { &[] } else { &["outdated"] }),
        ]);
    }
    let deps = users
        .into_iter()
        .map(|(name, used)| {
            let locked = versions.get(name).map(|v| v.join(" ")).unwrap_or_default();
            let (latest, result) = newer
                .get(name)
                .map_or((locked.clone(), "ok".to_string()), |l| {
                    ((*l).to_string(), "outdated".to_string())
                });
            [
                name.to_string(),
                locked,
                latest,
                format!("{result}, {used} crate(s)"),
            ]
        })
        .collect();
    (crates, deps)
}

pub fn majors(dir: &Path, label: &str) -> Result<Part> {
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
    let behind = parse_outdated(&out);
    let packages = std::fs::read_to_string(dir.join("Cargo.lock"))
        .map(|t| lock_packages(&t))
        .unwrap_or_default();
    let (crates, deps) = direct_rows(&packages, &behind);
    let mut lines = vec![format!(
        "{} workspace crates, {} direct dependencies, {} behind their newest stable release, from cargo outdated",
        crates.len(),
        deps.len(),
        behind.len()
    )];
    lines.extend(table(["crate", "direct", "outdated", "result"], &crates));
    lines.push(String::new());
    lines.extend(table(["dependency", "locked", "newest", "result"], &deps));
    let findings = behind
        .into_iter()
        .map(|(krate, name, project, latest)| {
            Finding::new("outdated-dependency", format!("{label} {krate} -> {name}"), WHY_MAJOR)
                .found(project)
                .expected(latest.clone())
                .fix(format!(
                    "Raise {name} to {latest} in Cargo.toml, adapt the code to the new API, and run every check."
                ))
        })
        .collect();
    Ok((
        Section::new(format!("{label} direct dependencies"), lines),
        findings,
    ))
}

pub fn lock_times(lock: &str) -> Result<BTreeMap<String, i64>> {
    Ok(lock_pins(lock)?
        .into_iter()
        .map(|(k, (t, _))| (k, t))
        .collect())
}

pub fn lock_pins(lock: &str) -> Result<BTreeMap<String, (i64, String)>> {
    let v: Value = serde_json::from_str(lock)?;
    let nodes = v["nodes"].as_object().context("flake.lock has no nodes")?;
    Ok(nodes
        .iter()
        .filter_map(|(k, n)| {
            let l = &n["locked"];
            let rev = l["rev"].as_str().unwrap_or("-").to_string();
            Some((k.clone(), (l["lastModified"].as_i64()?, rev)))
        })
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

pub fn flake_rows(
    old: &BTreeMap<String, (i64, String)>,
    new: &BTreeMap<String, (i64, String)>,
    grace_days: i64,
) -> Vec<[String; 5]> {
    old.iter()
        .map(|(k, (t, rev))| {
            let (nt, nrev) = new.get(k).cloned().unwrap_or((*t, rev.clone()));
            let lag = (nt - t) / DAY;
            [
                k.clone(),
                format!("{} {}", short(rev), date(*t)),
                format!("{} {}", short(&nrev), date(nt)),
                format!("{lag} day(s)"),
                verdict(if lag > grace_days { &["outdated"] } else { &[] }),
            ]
        })
        .collect()
}

pub fn flake(dir: &Path, grace_days: i64) -> Result<Part> {
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
    let old_text = std::fs::read_to_string(dir.join("flake.lock"))?;
    let new_text = std::fs::read_to_string(&tmp)?;
    let _ = std::fs::remove_file(&tmp);
    let (old, new) = (lock_pins(&old_text)?, lock_pins(&new_text)?);
    let rows = flake_rows(&old, &new, grace_days);
    let mut lines = vec![format!(
        "{} inputs, each may lag {grace_days} day(s) behind its branch, from nix flake update",
        rows.len()
    )];
    lines.extend(table(
        ["input", "locked", "branch head", "lag", "result"],
        &rows,
    ));
    let findings = flake_lag(&lock_times(&old_text)?, &lock_times(&new_text)?, grace_days)
        .into_iter()
        .map(|(input, lag)| {
            Finding::new("outdated-flake-input", format!("flake.lock {input}"), WHY_FLAKE)
                .found(format!("{lag} days behind its branch"))
                .expected(format!("at most {grace_days} days behind"))
                .fix(format!(
                    "Run nix flake update {input}, run nix flake check and nix build, and commit flake.lock."
                ))
        })
        .collect();
    Ok((Section::new("flake.lock inputs", lines), findings))
}

pub fn parse_uses(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let rest = l
                .trim()
                .trim_start_matches("- ")
                .strip_prefix("uses:")?
                .trim();
            let (path, rev) = rest.split_once('@')?;
            let repo: Vec<&str> = path.splitn(3, '/').take(2).collect();
            (!path.starts_with('.') && repo.len() == 2).then(|| (repo.join("/"), rev.to_string()))
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

pub fn actions(dir: &Path) -> Result<Part> {
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
    let latest: Vec<Result<(String, String, Option<String>)>> = std::thread::scope(|s| {
        let jobs: Vec<_> = pins
            .keys()
            .map(|(repo, _)| {
                s.spawn(move || {
                    let tag = gh(dir, &format!("repos/{repo}/releases/latest"), ".tag_name")?;
                    let sha = gh(dir, &format!("repos/{repo}/commits/{tag}"), ".sha")?;
                    let notes = gh(dir, &format!("repos/{repo}/releases/latest"), ".body")?;
                    Ok((tag, sha, deprecation(&notes)))
                })
            })
            .collect();
        jobs.into_iter()
            .map(|j| {
                j.join()
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("a GitHub API lookup panicked")))
            })
            .collect()
    });
    let mut out = Vec::new();
    let mut rows = Vec::new();
    for (((repo, rev), file), got) in pins.into_iter().zip(latest) {
        let (tag, sha, deprecated) = got?;
        let mut problems = Vec::new();
        if let Some(notice) = deprecated {
            problems.push("deprecated");
            out.push(
                Finding::new("deprecated-action", format!("{file} {repo}"), WHY_DEPRECATED)
                    .found(notice)
                    .expected("an action that its maintainers still support")
                    .fix(format!(
                        "Move to the action that the {tag} release notes of {repo} name as its replacement."
                    )),
            );
        }
        if rev != sha {
            problems.push("outdated");
            out.push(
                Finding::new("outdated-action", format!("{file} {repo}"), WHY_ACTION)
                    .found(rev.clone())
                    .expected(format!("{sha} ({tag})"))
                    .fix(format!("Replace {repo}@{rev} with {repo}@{sha}.")),
            );
        }
        rows.push([
            repo,
            short(&rev),
            format!("{} {tag}", short(&sha)),
            verdict(&problems),
            file,
        ]);
    }
    let mut lines = vec![format!(
        "{} pinned actions, each on the commit of its newest release, from the GitHub API",
        rows.len()
    )];
    lines.extend(table(
        ["action", "pinned", "newest release", "result", "file"],
        &rows,
    ));
    Ok((Section::new("CI actions", lines), out))
}

pub fn deprecation(notes: &str) -> Option<String> {
    notes
        .lines()
        .map(|l| l.trim_start_matches(['>', ' ']).trim())
        .find(|l| l.to_ascii_lowercase().contains("deprecat"))
        .map(str::to_string)
}

pub fn all(
    dir: &Path,
    grace_days: i64,
    with_actions: bool,
) -> Result<(Vec<Section>, Vec<Finding>)> {
    let (workspace, prefix) = if dir.join(WORKSPACE).join("Cargo.lock").is_file() {
        (dir.join(WORKSPACE), format!("{WORKSPACE}/"))
    } else {
        (dir.to_path_buf(), String::new())
    };
    let (lock_label, manifest_label) =
        (format!("{prefix}Cargo.lock"), format!("{prefix}Cargo.toml"));
    std::thread::scope(|s| {
        let jobs = [
            s.spawn(|| lock(&workspace, &lock_label)),
            s.spawn(|| majors(&workspace, &manifest_label)),
            s.spawn(|| flake(dir, grace_days)),
            s.spawn(|| {
                if with_actions {
                    actions(dir)
                } else {
                    Ok((
                        Section::new("CI actions", vec!["skipped, --no-actions".into()]),
                        Vec::new(),
                    ))
                }
            }),
        ];
        let mut sections = Vec::new();
        let mut findings = Vec::new();
        for j in jobs {
            match j.join() {
                Ok(r) => {
                    let (section, found) = r?;
                    sections.push(section);
                    findings.extend(found);
                }
                Err(_) => bail!("an outdated check panicked"),
            }
        }
        Ok((sections, findings))
    })
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
    fn formats_unix_dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_795_234_589), "2026-11-21");
        assert_eq!(date(-DAY), "1969-12-31");
    }

    #[test]
    fn reads_lock_packages_and_direct_dependencies() {
        let lock = concat!(
            "version = 4\n\n",
            "[[package]]\nname = \"anyhow\"\nversion = \"1.0.105\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n",
            "[[package]]\nname = \"base64\"\nversion = \"0.22.1\"\nsource = \"registry+x\"\n\n",
            "[[package]]\nname = \"base64\"\nversion = \"0.23.1\"\nsource = \"registry+x\"\n\n",
            "[[package]]\nname = \"stella-apk\"\nversion = \"0.1.0\"\ndependencies = [\n \"anyhow\",\n \"base64 0.23.1\",\n \"stella-core\",\n]\n\n",
            "[[package]]\nname = \"stella-core\"\nversion = \"0.1.0\"\ndependencies = [\"anyhow\"]\n",
        );
        let packages = lock_packages(lock);
        assert_eq!(packages.len(), 5);
        assert_eq!(packages[3].deps, ["anyhow", "base64", "stella-core"]);
        assert!(packages[3].local && !packages[0].local);
        assert!(packages[4].deps.is_empty());
        let behind = [(
            "stella-apk".to_string(),
            "base64".to_string(),
            "0.23.1".to_string(),
            "1.0.0".to_string(),
        )];
        let (crates, deps) = direct_rows(&packages, &behind);
        assert_eq!(
            crates,
            [
                ["stella-apk", "2", "1", "outdated"].map(String::from),
                ["stella-core", "0", "0", "ok"].map(String::from)
            ]
        );
        assert_eq!(
            deps,
            [
                ["anyhow", "1.0.105", "1.0.105", "ok, 1 crate(s)"].map(String::from),
                ["base64", "0.22.1 0.23.1", "1.0.0", "outdated, 1 crate(s)"].map(String::from)
            ]
        );
    }

    #[test]
    fn lists_every_flake_input() -> Result<()> {
        let old = lock_pins(
            r#"{"nodes":{"nixpkgs":{"locked":{"lastModified":0,"rev":"aaaaaaaaaaaaaaaa"}},"crane":{"locked":{"lastModified":0}},"root":{}}}"#,
        )?;
        let new = lock_pins(&format!(
            r#"{{"nodes":{{"nixpkgs":{{"locked":{{"lastModified":{},"rev":"bbbbbbbbbbbbbbbb"}}}}}}}}"#,
            10 * DAY
        ))?;
        assert_eq!(
            flake_rows(&old, &new, 7),
            [
                ["crane", "- 1970-01-01", "- 1970-01-01", "0 day(s)", "ok"].map(String::from),
                [
                    "nixpkgs",
                    "aaaaaaaaaaaa 1970-01-01",
                    "bbbbbbbbbbbb 1970-01-11",
                    "10 day(s)",
                    "outdated"
                ]
                .map(String::from)
            ]
        );
        Ok(())
    }

    #[test]
    fn finds_deprecation_notices() {
        let notes = "> [!WARNING]\n> As of version 4.0.0 this action is being deprecated in favor of actions/attest.\n";
        assert_eq!(
            deprecation(notes).as_deref(),
            Some("As of version 4.0.0 this action is being deprecated in favor of actions/attest.")
        );
        assert_eq!(deprecation("## What's Changed\n* Bump deps\n"), None);
    }

    #[test]
    fn reads_pinned_actions() {
        let yml = "steps:\n  - uses: actions/checkout@abc\n      - uses: actions/cache/restore@ghi\n      - uses: ./.github/actions/nix\n    uses: cachix/install-nix-action@def\n  - run: echo uses:x@y\n";
        assert_eq!(
            parse_uses(yml),
            [
                ("actions/checkout".to_string(), "abc".to_string()),
                ("actions/cache".to_string(), "ghi".to_string()),
                ("cachix/install-nix-action".to_string(), "def".to_string())
            ]
        );
    }
}
