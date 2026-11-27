use anyhow::Result;
use rustc_hash::FxHashSet;
use std::io::{BufRead, BufReader, BufWriter, Stdout, Write};
use std::path::PathBuf;
use stella_core::config::{KNOWN_LISTS, Paths};
use stella_core::known::Known;
use stella_core::public_suffix::Psl;
use stella_core::store::Store;

pub struct Context {
    pub paths: Paths,
    pub input: Option<PathBuf>,
    pub store: Store,
    pub psl: Psl,
    known: std::cell::OnceCell<Known>,
    allow: std::cell::OnceCell<rustc_hash::FxHashMap<String, String>>,
}

impl Context {
    pub fn open(paths: Paths) -> Result<Self> {
        paths.ensure()?;
        let store = Store::open(&paths.db())?;
        let psl = Psl::load(&paths.psl()).unwrap_or_else(|e| {
            eprintln!("psl: {e}");
            Psl::default()
        });
        Ok(Self {
            paths,
            input: None,
            store,
            psl,
            known: std::cell::OnceCell::new(),
            allow: std::cell::OnceCell::new(),
        })
    }

    pub fn known(&self) -> &Known {
        self.known.get_or_init(|| {
            let k = Known::load(&self.paths.known(), KNOWN_LISTS).unwrap_or_default();
            if k.is_empty() {
                eprintln!("known: no reference lists, run stella known sync");
            }
            k
        })
    }

    pub fn regdom(&self, host: &str) -> String {
        self.psl.regdom_or_self(host).to_string()
    }

    pub fn allowed(&self, host: &str) -> Option<&str> {
        let map = self.allow.get_or_init(|| {
            self.store
                .rows("SELECT host, reason FROM allow")
                .unwrap_or_default()
                .into_iter()
                .filter_map(|mut r| {
                    let reason = r.pop()?;
                    let host = r.pop()?;
                    Some((host, reason))
                })
                .collect()
        });
        stella_core::name::suffixes(host).find_map(|s| map.get(s).map(String::as_str))
    }

    fn input_lines(&self) -> Vec<String> {
        let read = |r: &mut dyn BufRead| r.lines().map_while(Result::ok).collect::<Vec<_>>();
        match &self.input {
            Some(p) => match std::fs::File::open(p) {
                Ok(f) => read(&mut BufReader::new(f)),
                Err(e) => {
                    eprintln!("input: {}: {e}", p.display());
                    Vec::new()
                }
            },
            None => read(&mut std::io::stdin().lock()),
        }
    }

    pub fn names(&self) -> Vec<String> {
        names_in(self.input_lines())
    }

    pub fn lines(&self) -> Vec<Vec<String>> {
        rows_in(self.input_lines())
    }
}

pub fn names_in(lines: Vec<String>) -> Vec<String> {
    let mut seen = FxHashSet::default();
    lines
        .into_iter()
        .filter_map(|l| {
            let first = l.split(['\t', ' ', ',']).next()?.to_string();
            stella_core::name::normalize(&first)
        })
        .filter(|n| seen.insert(n.clone()))
        .collect()
}

pub fn rows_in(lines: Vec<String>) -> Vec<Vec<String>> {
    lines
        .into_iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn quiet(on: bool) {
    QUIET.store(on, std::sync::atomic::Ordering::Relaxed);
}

pub struct Out(Option<BufWriter<Stdout>>);

impl Out {
    pub fn new() -> Self {
        let quiet = QUIET.load(std::sync::atomic::Ordering::Relaxed);
        Self((!quiet).then(|| BufWriter::with_capacity(1 << 16, std::io::stdout())))
    }

    pub fn row(&mut self, cols: &[&str]) {
        if let Some(w) = self.0.as_mut() {
            let _ = writeln!(w, "{}", cols.join("\t"));
        }
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        if let Some(w) = self.0.as_mut() {
            let _ = w.flush();
        }
    }
}
