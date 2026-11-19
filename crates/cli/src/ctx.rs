use anyhow::Result;
use rustc_hash::FxHashSet;
use std::io::{BufRead, BufWriter, Stdout, Write};
use stella_core::config::{KNOWN_LISTS, Paths};
use stella_core::known::Known;
use stella_core::psl::Psl;
use stella_core::store::Store;

pub struct Ctx {
    pub paths: Paths,
    pub store: Store,
    pub psl: Psl,
    known: std::cell::OnceCell<Known>,
}

impl Ctx {
    pub fn open(paths: Paths) -> Result<Self> {
        paths.ensure()?;
        let store = Store::open(&paths.db())?;
        let psl = Psl::load(&paths.psl()).unwrap_or_else(|e| {
            eprintln!("psl: {e}");
            Psl::default()
        });
        Ok(Self {
            paths,
            store,
            psl,
            known: std::cell::OnceCell::new(),
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
}

pub fn stdin_names() -> Vec<String> {
    let mut seen = FxHashSet::default();
    std::io::stdin()
        .lock()
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| {
            let first = l.split(['\t', ' ', ',']).next()?.to_string();
            stella_core::name::normalize(&first)
        })
        .filter(|n| seen.insert(n.clone()))
        .collect()
}

pub fn stdin_rows() -> Vec<Vec<String>> {
    std::io::stdin()
        .lock()
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

pub struct Out(BufWriter<Stdout>);

impl Out {
    pub fn new() -> Self {
        Self(BufWriter::with_capacity(1 << 16, std::io::stdout()))
    }

    pub fn row(&mut self, cols: &[&str]) {
        let _ = writeln!(self.0, "{}", cols.join("\t"));
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        let _ = self.0.flush();
    }
}
