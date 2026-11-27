use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static JSON: AtomicBool = AtomicBool::new(false);
pub const EVERY: Duration = Duration::from_secs(30);
pub const SLOWEST: usize = 3;

pub fn set_json(on: bool) {
    JSON.store(on, Ordering::Relaxed);
}

pub struct Snapshot<'a> {
    pub label: &'a str,
    pub done: usize,
    pub total: usize,
    pub inflight: usize,
    pub hits: Option<usize>,
    pub secs: u64,
    pub slowest: &'a [(String, u64)],
}

fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' | '\\' => vec!['\\', c],
            c if c.is_control() => Vec::new(),
            c => vec![c],
        })
        .collect()
}

pub fn render(s: &Snapshot, json: bool) -> String {
    if json {
        let slowest = s
            .slowest
            .iter()
            .map(|(h, t)| format!("{{\"host\":\"{}\",\"secs\":{t}}}", escape(h)))
            .collect::<Vec<_>>()
            .join(",");
        let hits = s.hits.map_or("null".to_string(), |h| h.to_string());
        return format!(
            "{{\"progress\":\"{}\",\"done\":{},\"total\":{},\"inflight\":{},\"hits\":{hits},\"secs\":{},\"slowest\":[{slowest}]}}",
            escape(s.label),
            s.done,
            s.total,
            s.inflight,
            s.secs
        );
    }
    let mut line = format!(
        "{}: progress done={}/{} inflight={}",
        s.label, s.done, s.total, s.inflight
    );
    if let Some(h) = s.hits {
        line.push_str(&format!(" hits={h}"));
    }
    line.push_str(&format!(" secs={}", s.secs));
    if !s.slowest.is_empty() {
        let slow = s
            .slowest
            .iter()
            .map(|(h, t)| format!("{h}({t}s)"))
            .collect::<Vec<_>>()
            .join(",");
        line.push_str(&format!(" slowest={slow}"));
    }
    line
}

pub struct Progress {
    label: &'static str,
    total: usize,
    started: Instant,
    last: Instant,
}

impl Progress {
    pub fn new(label: &'static str, total: usize) -> Self {
        let now = Instant::now();
        Self {
            label,
            total,
            started: now,
            last: now,
        }
    }

    pub fn due(&self) -> bool {
        self.last.elapsed() >= EVERY
    }

    pub fn print(
        &mut self,
        done: usize,
        inflight: usize,
        hits: Option<usize>,
        slowest: &[(String, u64)],
    ) {
        self.last = Instant::now();
        let snap = Snapshot {
            label: self.label,
            done,
            total: self.total,
            inflight,
            hits,
            secs: self.started.elapsed().as_secs(),
            slowest,
        };
        eprintln!("{}", render(&snap, JSON.load(Ordering::Relaxed)));
    }

    pub fn tick(&mut self, done: usize, inflight: usize, hits: Option<usize>) {
        if self.due() {
            self.print(done, inflight, hits, &[]);
        }
    }
}

pub fn slowest<'a>(
    started: impl Iterator<Item = (&'a str, Instant)>,
    n: usize,
) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = started
        .map(|(h, t)| (h.to_string(), t.elapsed().as_secs()))
        .collect();
    v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(slowest: &[(String, u64)]) -> Snapshot<'_> {
        Snapshot {
            label: "probe",
            done: 120,
            total: 400,
            inflight: 30,
            hits: Some(4),
            secs: 61,
            slowest,
        }
    }

    #[test]
    fn renders_text_and_json() {
        let slow = vec![("a.io".to_string(), 19), ("b\"x".to_string(), 7)];
        assert_eq!(
            render(&snap(&slow), false),
            "probe: progress done=120/400 inflight=30 hits=4 secs=61 slowest=a.io(19s),b\"x(7s)"
        );
        assert_eq!(
            render(&snap(&slow), true),
            "{\"progress\":\"probe\",\"done\":120,\"total\":400,\"inflight\":30,\"hits\":4,\"secs\":61,\"slowest\":[{\"host\":\"a.io\",\"secs\":19},{\"host\":\"b\\\"x\",\"secs\":7}]}"
        );
        let mut plain = snap(&[]);
        plain.hits = None;
        assert_eq!(
            render(&plain, false),
            "probe: progress done=120/400 inflight=30 secs=61"
        );
        assert!(render(&plain, true).contains("\"hits\":null"));
    }

    #[test]
    fn picks_the_longest_waiting() {
        let now = Instant::now();
        let ago = |s: u64| now.checked_sub(Duration::from_secs(s)).unwrap_or(now);
        let started = [("a", ago(5)), ("b", ago(50)), ("c", ago(20)), ("d", ago(1))];
        let got = slowest(started.iter().map(|(h, t)| (*h, *t)), 2);
        assert_eq!(
            got.iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>(),
            ["b", "c"]
        );
    }
}
