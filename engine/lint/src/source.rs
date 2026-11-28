use crate::report::{Finding, Section, table};
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

pub const RULES: [&str; 7] = [
    "comment",
    "lint-suppression",
    "help-text",
    "marker",
    "whitespace",
    "final-newline",
    "large-file",
];

const SKIP_DIRS: &[&str] = &["target", "corpus", "artifacts", "node_modules"];

const PUBLISHED_DIRS: [&str; 1] = ["lists/"];

fn published(rel: &str) -> bool {
    PUBLISHED_DIRS.iter().any(|d| rel.starts_with(d))
}

const WHY_COMMENT: &str = "Stella carries no comments of any kind. Good code explains itself through names, types and structure, and documentation lives outside the code. A comment either repeats what the code already says or hides that a name, a type or a function should say more, and it rots silently when the code changes.";
const FIX_COMMENT: &str = "Delete the comment. If it held a reason, give that reason a home that the compiler or the history keeps honest: a well named binding or constant, a help = \"...\" string, an error message, or the commit message.";
const WHY_HELP: &str = "Help strings are short labels printed by clap. They carry no trailing full stop and no semicolon, so that every line in --help reads the same way.";
const WHY_MARKER: &str = concat!(
    "TO",
    "DO, FIX",
    "ME, X",
    "XX and HA",
    "CK markers are promises without an owner or a date. Open work belongs in the issue tracker or in a commit that does it, never in the tree."
);
const WHY_SPACE: &str = "Trailing whitespace, tabs used for alignment and carriage returns create noisy diffs and hide real changes in review.";
const WHY_NEWLINE: &str = "A text file ends with exactly one newline so that appending a line changes one line in the diff, not two.";
const WHY_SUPPRESS: &str = "Lints are never silenced. A lint attribute hides a real problem from every later reader and from the next Rust release, so the code is restructured until the lint has nothing to say.";
const WHY_LARGE: &str = "Large files bloat every clone forever, because git keeps every version. Fixtures stay small and generated or downloaded data stays out of the tree.";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Rust,
    Script,
    Hash,
    Plain,
}

fn kind(path: &Path) -> Option<Kind> {
    let name = path.file_name()?.to_str()?;
    if name == "Cargo.lock" || name == "flake.lock" {
        return None;
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => Some(Kind::Rust),
        Some("js") => Some(Kind::Script),
        Some("nix" | "toml" | "yml" | "yaml" | "sh") => Some(Kind::Hash),
        Some("md" | "txt" | "json") => Some(Kind::Plain),
        _ if name == ".gitignore" || name == "LICENSE" => Some(Kind::Plain),
        _ => None,
    }
}

fn after_space(line: &str, marker: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = line[from..].find(marker) {
        let at = from + i;
        if at == 0 || line[..at].ends_with([' ', '\t']) {
            return Some(at);
        }
        from = at + marker.len();
    }
    None
}

fn comment_at(kind: Kind, line: &str) -> Option<usize> {
    let marks: &[&str] = match kind {
        Kind::Rust => &["//", "/*", "-- "],
        Kind::Script => &["//", "/*"],
        Kind::Hash => &["#"],
        Kind::Plain => &[],
    };
    marks.iter().filter_map(|m| after_space(line, m)).min()
}

fn help_text(line: &str) -> Option<(usize, &str)> {
    for key in ["help = \"", "about = \""] {
        if let Some(i) = line.find(key) {
            let start = i + key.len();
            let rest = &line[start..];
            let end = rest.find('"')?;
            return Some((start, &rest[..end]));
        }
    }
    None
}

fn suppression_at(line: &str) -> Option<usize> {
    ["allow", "expect"]
        .iter()
        .flat_map(|w| [format!("#[{w}("), format!("#![{w}(")])
        .filter_map(|p| line.find(&p))
        .min()
}

fn marker_at(line: &str) -> Option<(usize, &'static str)> {
    for m in [
        concat!("TO", "DO"),
        concat!("FIX", "ME"),
        concat!("X", "XX"),
        concat!("HA", "CK"),
    ] {
        let mut from = 0;
        while let Some(i) = line[from..].find(m) {
            let at = from + i;
            let before = line[..at].chars().next_back();
            let after = line[at + m.len()..].chars().next();
            let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            if !word(before) && !word(after) {
                return Some((at, m));
            }
            from = at + m.len();
        }
    }
    None
}

pub fn check_text(rel: &str, text: &str, out: &mut Vec<Finding>) {
    let Some(kind) = kind(Path::new(rel)) else {
        return;
    };
    for (n, line) in text.lines().enumerate() {
        let place = |col: usize| format!("{rel}:{}:{}", n + 1, col + 1);
        let trimmed = line.trim_start();
        let shebang = n == 0 && line.starts_with("#!");
        if let Some(col) = comment_at(kind, line).filter(|_| !shebang) {
            out.push(
                Finding::new("comment", place(col), WHY_COMMENT)
                    .found(line[col..].trim_end())
                    .expected("no comment, the code says it")
                    .fix(FIX_COMMENT),
            );
        }
        if kind == Kind::Rust
            && let Some((col, help)) = help_text(line)
            && (help.ends_with('.') || help.contains(';'))
        {
            out.push(
                Finding::new("help-text", place(col), WHY_HELP)
                    .found(format!("\"{help}\""))
                    .expected(format!(
                        "\"{}\"",
                        help.trim_end_matches('.').replace(';', ".")
                    ))
                    .fix("Remove the trailing full stop and split the text at the semicolon."),
            );
        }
        if kind == Kind::Rust
            && let Some(col) = suppression_at(line)
        {
            out.push(
                Finding::new("lint-suppression", place(col), WHY_SUPPRESS)
                    .found(trimmed)
                    .expected("no allow or expect attributes")
                    .fix("Change the code so that the lint passes. Ask on the pull request if a lint looks wrong."),
            );
        }
        if let Some((col, m)) = marker_at(line) {
            out.push(
                Finding::new("marker", place(col), WHY_MARKER)
                    .found(m)
                    .expected("no work markers in the tree")
                    .fix("Do the work now in its own commit, or remove the marker and track the work outside the tree."),
            );
        }
        if line.ends_with([' ', '\t']) || line.contains('\r') {
            out.push(
                Finding::new("whitespace", place(line.trim_end().len()), WHY_SPACE)
                    .found(format!("{:?}", &line[line.trim_end().len()..]))
                    .expected("no trailing spaces, tabs or carriage returns")
                    .fix("Run nix fmt, or strip the line end in your editor."),
            );
        }
    }
    if !text.is_empty() && (!text.ends_with('\n') || text.ends_with("\n\n")) {
        out.push(
            Finding::new("final-newline", rel.to_string(), WHY_NEWLINE)
                .found(if text.ends_with('\n') {
                    "blank lines at the end"
                } else {
                    "no newline at the end"
                })
                .expected("exactly one newline at the end of the file")
                .fix("End the file with a single newline."),
        );
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        let ty = e.file_type()?;
        if ty.is_dir() {
            let hidden = name.starts_with('.') && name != ".github";
            if !hidden && !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with("result") {
                walk(&path, out)?;
            }
        } else if ty.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn git_files(root: &Path) -> Option<Vec<PathBuf>> {
    if !root.join(".git").exists() {
        return None;
    }
    let out = std::process::Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let mut files: Vec<PathBuf> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| root.join(String::from_utf8_lossy(p).as_ref()))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    Some(files)
}

#[derive(Default)]
pub struct Tree {
    pub files: usize,
    pub kinds: BTreeMap<String, (usize, usize, u64)>,
    pub findings: Vec<Finding>,
}

impl Tree {
    pub fn sections(&self) -> Vec<Section> {
        let rows: Vec<[String; 4]> = self
            .kinds
            .iter()
            .map(|(k, (files, lines, bytes))| {
                [
                    k.clone(),
                    files.to_string(),
                    lines.to_string(),
                    bytes.to_string(),
                ]
            })
            .collect();
        vec![
            Section::new("rules", vec![RULES.join(", ")]),
            Section::new(
                "files by type",
                table(["type", "files", "lines", "bytes"], &rows),
            ),
        ]
    }
}

fn type_of(rel: &str) -> String {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => ext.to_string(),
        _ => name.to_string(),
    }
}

pub fn check_tree(root: &Path) -> Result<Tree> {
    let files = if let Some(f) = git_files(root) {
        f
    } else {
        let mut f = Vec::new();
        walk(root, &mut f)?;
        f
    };
    let mut tree = Tree {
        files: files.len(),
        ..Tree::default()
    };
    for path in &files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        let size = std::fs::metadata(path)?.len();
        let entry = tree.kinds.entry(type_of(&rel)).or_default();
        entry.0 += 1;
        entry.2 += size;
        if size > MAX_FILE_BYTES && !published(&rel) {
            tree.findings.push(
                Finding::new("large-file", rel.clone(), WHY_LARGE)
                    .found(format!("{size} bytes"))
                    .expected(format!("at most {MAX_FILE_BYTES} bytes"))
                    .fix(
                        "Remove the file from the commit and generate or download it at run time.",
                    ),
            );
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(path) {
            entry.1 += text.lines().count();
            check_text(&rel, &text, &mut tree.findings);
        }
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(rel: &str, text: &str) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        check_text(rel, text, &mut out);
        out.into_iter().map(|f| (f.rule, f.place)).collect()
    }

    fn slashes() -> String {
        "/".repeat(2)
    }

    #[test]
    fn finds_comments_by_language() {
        let c = slashes();
        assert_eq!(
            rules(
                "a.rs",
                &format!("let x = 1; {c} why\n/* block */\nlet u = \"https:{c}x\";\n")
            ),
            [
                ("comment", "a.rs:1:12".into()),
                ("comment", "a.rs:2:1".into())
            ]
        );
        let sql = format!("const Q: &str = \"SELECT 1 {} note\";\n", "-".repeat(2));
        assert_eq!(rules("q.rs", &sql), [("comment", "q.rs:1:27".into())]);
        let hash = '#';
        assert_eq!(
            rules(
                "n.nix",
                &format!("  x = 1; {hash} note\n  y = \"a{hash}b\";\n")
            ),
            [("comment", "n.nix:1:10".into())]
        );
        assert!(rules("w.yml", "#!/bin/sh\non: push\n").is_empty());
        assert_eq!(
            rules("h.js", &format!("f(); {c} x\n")),
            [("comment", "h.js:1:6".into())]
        );
        assert!(rules("Cargo.lock", "# generated\n").is_empty());
        assert!(rules("image.png", "// x").is_empty());
    }

    #[test]
    fn finds_prose_markers_and_whitespace() {
        assert_eq!(
            rules("a.rs", "#[arg(help = \"Open connections.\")]\n"),
            [("help-text", "a.rs:1:15".into())]
        );
        assert!(rules("a.rs", "#[arg(help = \"Open connections\")]\n").is_empty());
        assert!(rules("r.md", "one \u{2014} two\n").is_empty());
        let todo = ["TO", "DO"].concat();
        assert_eq!(
            rules("a.rs", &format!("let {todo}_X = 1;\nlet y = \"{todo}\";\n")),
            [("marker", "a.rs:2:10".into())]
        );
        assert_eq!(
            rules("a.toml", "x = 1 \n"),
            [("whitespace", "a.toml:1:6".into())]
        );
        assert_eq!(
            rules("a.toml", "x = 1"),
            [("final-newline", "a.toml".into())]
        );
        assert_eq!(
            rules("a.toml", "x = 1\n\n"),
            [("final-newline", "a.toml".into())]
        );
        assert!(rules("a.toml", "").is_empty());
        let attr = format!("{}[allow(dead_code)]\n", '#');
        assert_eq!(
            rules("a.rs", &attr),
            [("lint-suppression", "a.rs:1:1".into())]
        );
        let inner = format!("{}![expect(x)]\n", '#');
        assert_eq!(
            rules("a.rs", &inner),
            [("lint-suppression", "a.rs:1:1".into())]
        );
    }

    #[test]
    fn walks_a_tree_and_skips_build_output() -> Result<()> {
        let root = std::env::temp_dir().join(format!("stella-lint-tree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("target"))?;
        std::fs::create_dir_all(root.join(".github/workflows"))?;
        std::fs::create_dir_all(root.join(".hidden"))?;
        std::fs::write(root.join("target/x.rs"), "// skipped\n")?;
        std::fs::write(root.join(".hidden/x.rs"), "// skipped\n")?;
        std::fs::write(
            root.join(".github/workflows/c.yml"),
            format!("on: push {} x\n", '#'),
        )?;
        std::fs::write(root.join("big.json"), vec![b'a'; 1024 * 1024 + 1])?;
        std::fs::create_dir_all(root.join("lists/ads"))?;
        std::fs::write(root.join("lists/ads/domains.txt"), "a.io\n".repeat(300_000))?;
        std::fs::write(root.join("ok.rs"), "fn main() {}\n")?;
        let tree = check_tree(&root)?;
        assert_eq!(tree.files, 4);
        assert!(published("lists/ads/domains.txt") && !published("listsx/a.txt"));
        let rules: Vec<&str> = tree.findings.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["comment", "large-file"]);
        assert_eq!(tree.findings[0].place, ".github/workflows/c.yml:1:10");
        assert_eq!(tree.kinds["rs"], (1, 1, 13));
        assert_eq!(tree.kinds["json"].0, 1);
        let sections = tree.sections();
        assert_eq!(sections[0].lines, [RULES.join(", ")]);
        assert_eq!(sections[1].lines[2], "rs        1       1       13");
        assert_eq!(type_of("a/.gitignore"), ".gitignore");
        assert_eq!(type_of("LICENSE"), "LICENSE");
        assert_eq!(type_of("a/b.tar.gz"), "gz");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
