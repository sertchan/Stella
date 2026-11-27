use std::fmt::Write as _;
use std::io::Write as _;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub place: String,
    pub found: String,
    pub expected: String,
    pub why: &'static str,
    pub fix: String,
}

impl Finding {
    pub fn new(rule: &'static str, place: impl Into<String>, why: &'static str) -> Self {
        Self {
            rule,
            place: place.into(),
            found: String::new(),
            expected: String::new(),
            why,
            fix: String::new(),
        }
    }

    pub fn found(mut self, v: impl Into<String>) -> Self {
        self.found = v.into();
        self
    }

    pub fn expected(mut self, v: impl Into<String>) -> Self {
        self.expected = v.into();
        self
    }

    pub fn fix(mut self, v: impl Into<String>) -> Self {
        self.fix = v.into();
        self
    }

    pub fn render(&self) -> String {
        let mut s = format!("error[{}] {}\n", self.rule, self.place);
        for (label, value) in [
            ("found", self.found.as_str()),
            ("expected", self.expected.as_str()),
            ("why", self.why),
            ("fix", self.fix.as_str()),
        ] {
            if !value.is_empty() {
                let _ = writeln!(s, "  {label:<9}{value}");
            }
        }
        s
    }
}

fn escape(v: &str) -> String {
    v.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Section {
    pub title: String,
    pub lines: Vec<String>,
}

impl Section {
    pub fn new(title: impl Into<String>, lines: Vec<String>) -> Self {
        Self {
            title: title.into(),
            lines,
        }
    }
}

pub fn table<const N: usize>(header: [&str; N], rows: &[[String; N]]) -> Vec<String> {
    let mut width = header.map(str::len);
    for row in rows {
        for (w, cell) in width.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |cells: [&str; N]| {
        let mut s = String::new();
        for (cell, w) in cells.iter().zip(width) {
            let _ = write!(s, "{cell:<w$}  ");
        }
        s.trim_end().to_string()
    };
    let mut out = vec![line(header)];
    out.extend(rows.iter().map(|r| line(r.each_ref().map(String::as_str))));
    out
}

pub struct Outcome {
    pub tool: &'static str,
    pub checked: String,
    pub sections: Vec<Section>,
    pub findings: Vec<Finding>,
}

impl Outcome {
    pub fn text(&self) -> String {
        let mut s = String::new();
        for section in &self.sections {
            let _ = writeln!(s, "{}: {}", self.tool, section.title);
            for line in &section.lines {
                if line.is_empty() {
                    s.push('\n');
                } else {
                    let _ = writeln!(s, "  {line}");
                }
            }
            s.push('\n');
        }
        for f in &self.findings {
            s.push_str(&f.render());
            s.push('\n');
        }
        if self.findings.is_empty() {
            let _ = writeln!(s, "{}: ok, {}", self.tool, self.checked);
        } else {
            let _ = writeln!(
                s,
                "{}: rejected, {} problem(s) in {}",
                self.tool,
                self.findings.len(),
                self.checked
            );
        }
        s
    }

    pub fn emit(&self) -> bool {
        let text = self.text();
        eprint!("{text}");
        if std::env::var_os("GITHUB_ACTIONS").is_some() {
            let mut out = std::io::stdout().lock();
            for f in &self.findings {
                let _ = writeln!(
                    out,
                    "::error title={} {}::{}",
                    f.rule,
                    escape(&f.place),
                    escape(&f.render())
                );
            }
            if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY")
                && let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path)
            {
                let _ = writeln!(file, "```text\n{text}```");
            }
        }
        self.findings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_filled_field() {
        let f = Finding::new("comment", "a.rs:3:5", "code explains itself")
            .found("note")
            .fix("delete it");
        assert_eq!(
            f.render(),
            "error[comment] a.rs:3:5\n  found    note\n  why      code explains itself\n  fix      delete it\n"
        );
        let ok = Outcome {
            tool: "source-lint",
            checked: "12 files".into(),
            sections: vec![Section::new("files", vec!["rs  12".into(), String::new()])],
            findings: Vec::new(),
        };
        assert_eq!(
            ok.text(),
            "source-lint: files\n  rs  12\n\n\nsource-lint: ok, 12 files\n"
        );
        let bad = Outcome {
            tool: "source-lint",
            checked: "12 files".into(),
            sections: Vec::new(),
            findings: vec![f],
        };
        assert!(bad.text().ends_with("rejected, 1 problem(s) in 12 files\n"));
        assert!(!bad.emit());
        assert_eq!(escape("a%b\nc"), "a%25b%0Ac");
    }

    #[test]
    fn aligns_table_columns() {
        let rows = [
            ["clap".to_string(), "4.6.10".to_string(), "ok".to_string()],
            ["x".to_string(), "1".to_string(), "outdated".to_string()],
        ];
        assert_eq!(
            table(["dependency", "version", "result"], &rows),
            [
                "dependency  version  result",
                "clap        4.6.10   ok",
                "x           1        outdated"
            ]
        );
    }
}
