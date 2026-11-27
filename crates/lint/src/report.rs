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

pub struct Outcome {
    pub tool: &'static str,
    pub checked: String,
    pub findings: Vec<Finding>,
}

impl Outcome {
    pub fn text(&self) -> String {
        let mut s = String::new();
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
            tool: "stella-lint source",
            checked: "12 files".into(),
            findings: Vec::new(),
        };
        assert_eq!(ok.text(), "stella-lint source: ok, 12 files\n");
        let bad = Outcome {
            tool: "stella-lint source",
            checked: "12 files".into(),
            findings: vec![f],
        };
        assert!(bad.text().ends_with("rejected, 1 problem(s) in 12 files\n"));
        assert!(!bad.emit());
        assert_eq!(escape("a%b\nc"), "a%25b%0Ac");
    }
}
