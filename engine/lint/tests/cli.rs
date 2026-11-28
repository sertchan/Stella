use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_stella-lint");

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("stella-lint-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }

    fn write(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.0.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("parent dir");
        }
        std::fs::write(&p, text).expect("write");
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn isolated(cmd: &mut Command, dir: &Path) {
    cmd.current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .env_remove("GITHUB_ACTIONS");
}

fn git(dir: &Path, args: &[&str]) -> String {
    let mut cmd = Command::new("git");
    cmd.args(args);
    isolated(&mut cmd, dir);
    let out = cmd.output().expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn lint(dir: &Path, args: &[&str], stdin: &str, path: Option<&Path>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolated(&mut cmd, dir);
    if let Some(p) = path {
        let old = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{old}", p.display()));
    }
    let mut child = cmd.spawn().expect("stella-lint runs");
    if let Some(mut s) = child.stdin.take() {
        use std::io::Write;
        s.write_all(stdin.as_bytes()).expect("stdin");
    }
    child.wait_with_output().expect("stella-lint exits")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn sources_reports_and_passes() {
    let s = Scratch::new("sources");
    s.write("ok.rs", "fn main() {}\n");
    let clean = lint(&s.0, &["sources", "."], "", None);
    assert_eq!(clean.status.code(), Some(0), "{}", stderr(&clean));
    assert!(stderr(&clean).contains("source-lint: ok, 1 files"));
    assert!(stderr(&clean).contains(
        "source-lint: files by type\n  type  files  lines  bytes\n  rs        1      1     13\n"
    ));
    s.write("bad.toml", &format!("x = 1 {} why\n", '#'));
    let bad = lint(&s.0, &["sources", "."], "", None);
    assert_eq!(bad.status.code(), Some(1));
    assert!(stderr(&bad).contains("error[comment] bad.toml:1:7"));
    let missing = lint(&s.0, &["sources", "absent"], "", None);
    assert_eq!(missing.status.code(), Some(2));
    assert!(stderr(&missing).contains("could not finish the check"));
}

#[test]
fn commit_messages_and_ranges_are_checked() {
    let s = Scratch::new("commits");
    git(&s.0, &["init", "-q", "-b", "main"]);
    s.write("engine/dns/Cargo.toml", "[package]\n");
    s.write("engine/cli/Cargo.toml", "[package]\n");
    s.write("engine/dns/src/wire.rs", "pub fn a() {}\n");
    git(&s.0, &["add", "."]);
    git(&s.0, &["commit", "-q", "-m", "dns/wire: add parser"]);
    let base = git(&s.0, &["rev-parse", "HEAD"]);
    s.write("engine/cli/src/main.rs", "fn main() {}\n");
    git(&s.0, &["add", "."]);
    let good = s.write("msg-good", "cli: add entry point\n");
    let ok = lint(&s.0, &["commit-msg", "msg-good"], "", None);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
    assert!(good.is_file());
    s.write("msg-scope", "dns: add entry point\n");
    let scope = lint(&s.0, &["commit-msg", "msg-scope"], "", None);
    assert_eq!(scope.status.code(), Some(1));
    assert!(stderr(&scope).contains("error[scope-files]"));
    assert!(stderr(&scope).contains("here cli"));
    git(&s.0, &["commit", "-q", "-m", "Added the entry point."]);
    let head = git(&s.0, &["rev-parse", "HEAD"]);
    let range = lint(&s.0, &["commits", &format!("{base}..{head}")], "", None);
    assert_eq!(range.status.code(), Some(1));
    let text = stderr(&range);
    assert!(text.contains("error[subject-format]"), "{text}");
    assert!(text.contains("error[unsigned]"), "{text}");
    assert!(text.contains("commitlint: rejected"), "{text}");
    assert!(
        text.contains("commit      signature  files  result"),
        "{text}"
    );
    assert!(
        text.contains("none           1  2 problem(s)  Added the entry point."),
        "{text}"
    );
    let all = lint(&s.0, &["commits", "HEAD~1"], "", None);
    assert!(stderr(&all).contains("1 commit(s)"), "{}", stderr(&all));
    let refs = format!("refs/heads/main {head} refs/heads/main {base}\n");
    let push = lint(&s.0, &["pre-push", "origin"], &refs, None);
    assert_eq!(push.status.code(), Some(1));
    assert!(stderr(&push).contains("error[subject-format]"));
    let nothing = lint(&s.0, &["pre-push"], "", None);
    assert_eq!(nothing.status.code(), Some(0), "{}", stderr(&nothing));
    let broken = lint(&s.0, &["commits", "no-such-rev"], "", None);
    assert_eq!(broken.status.code(), Some(2));
    let absent = lint(&s.0, &["commit-msg", "absent"], "", None);
    assert_eq!(absent.status.code(), Some(2));
}

#[test]
fn outdated_reads_every_tool() {
    let s = Scratch::new("outdated");
    let tools = s.0.join("tools");
    s.write(
        "tools/cargo",
        "#!/bin/sh\ncase \"$1\" in\n  update) echo '    Updating zip v9.7.3 -> v9.8.2' >&2 ;;\n  outdated) echo '{\"crate_name\":\"stella\",\"dependencies\":[{\"name\":\"clap\",\"project\":\"4.6.8\",\"latest\":\"5.0.0\"}]}' ;;\nesac\n",
    );
    s.write(
        "tools/nix",
        "#!/bin/sh\nfor a; do last=$a; done\necho '{\"nodes\":{\"nixpkgs\":{\"locked\":{\"lastModified\":2000000}},\"root\":{}}}' > \"$last\"\n",
    );
    s.write(
        "tools/gh",
        "#!/bin/sh\ncase \"$2 $4\" in\n  *\"releases/latest .tag_name\") echo v9 ;;\n  *\"releases/latest .body\") echo '> This action is deprecated in favor of actions/attest.' ;;\n  *) echo newsha ;;\nesac\n",
    );
    for t in ["cargo", "nix", "gh"] {
        let mut perm = std::fs::metadata(tools.join(t))
            .expect("tool")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o755);
        std::fs::set_permissions(tools.join(t), perm).expect("chmod");
    }
    s.write("engine/Cargo.lock", "version = 4\n");
    s.write(
        "flake.lock",
        "{\"nodes\":{\"nixpkgs\":{\"locked\":{\"lastModified\":0}},\"root\":{}}}\n",
    );
    s.write(
        ".github/workflows/ci.yml",
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@oldsha\n",
    );
    let out = lint(&s.0, &["outdated", "."], "", Some(&tools));
    let text = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    for section in [
        "outdated: engine/Cargo.lock\n  0 locked packages, 1 with a newer compatible release",
        "outdated: flake.lock inputs\n",
        "nixpkgs  - 1970-01-01  - 1970-01-24  23 day(s)  outdated",
        "actions/checkout  oldsha  newsha v9       deprecated, outdated  .github/workflows/ci.yml",
    ] {
        assert!(text.contains(section), "{section} missing in {text}");
    }
    for rule in [
        "error[outdated-lockfile] engine/Cargo.lock zip",
        "error[outdated-dependency] engine/Cargo.toml stella -> clap",
        "error[outdated-flake-input] flake.lock nixpkgs",
        "error[outdated-action] .github/workflows/ci.yml actions/checkout",
        "error[deprecated-action] .github/workflows/ci.yml actions/checkout",
    ] {
        assert!(text.contains(rule), "{rule} missing in {text}");
    }
    let quick = lint(
        &s.0,
        &["outdated", ".", "--no-actions", "--grace-days", "30"],
        "",
        Some(&tools),
    );
    let text = stderr(&quick);
    assert!(!text.contains("outdated-action"), "{text}");
    assert!(!text.contains("outdated-flake-input"), "{text}");
    assert!(text.contains("skipped, --no-actions"), "{text}");
}
