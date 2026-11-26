use crate::ctx::{Ctx, Out};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use stella_core::shape;
use stella_probe::battery::LITE;

#[derive(clap::Args)]
pub struct Args {
    #[arg(
        long,
        default_value_t = 3,
        help = "Registered domains a cluster needs at least"
    )]
    min_zones: usize,
    #[arg(long, help = "Also list clusters without uncovered hosts")]
    all: bool,
    #[arg(long, help = "Also list clusters whose paths all give the same answer")]
    flat: bool,
    #[arg(
        long,
        value_name = "ID",
        help = "Print the hosts of one cluster instead"
    )]
    show: Option<String>,
    #[arg(long, default_value_t = 5, help = "Uncovered sample hosts per cluster")]
    samples: usize,
}

pub struct ProbeRow {
    pub host: String,
    pub path: String,
    pub status: String,
    pub ctype: String,
    pub length: i64,
    pub head: String,
    pub digest: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Label {
    Candidate,
    New,
    Plain,
}

impl Label {
    fn as_str(self) -> &'static str {
        match self {
            Label::Candidate => "CANDIDATE",
            Label::New => "NEW",
            Label::Plain => "-",
        }
    }
}

pub struct Member {
    pub host: String,
    pub regdom: String,
    pub listed: bool,
    pub picked: bool,
    pub allowed: bool,
}

impl Member {
    fn covered(&self) -> bool {
        self.listed || self.picked
    }

    fn open(&self) -> bool {
        !self.covered() && !self.allowed
    }

    fn state(&self) -> &'static str {
        match (self.listed, self.picked, self.allowed) {
            (_, _, true) => "allowed",
            (true, _, _) => "listed",
            (false, true, _) => "picked",
            _ => "open",
        }
    }
}

pub struct Cluster {
    pub id: String,
    pub shape: String,
    pub flat: bool,
    pub members: Vec<Member>,
}

impl Cluster {
    fn zones(&self, f: impl Fn(&Member) -> bool) -> usize {
        self.members
            .iter()
            .filter(|m| f(m))
            .map(|m| m.regdom.as_str())
            .collect::<FxHashSet<_>>()
            .len()
    }

    pub fn label(&self, min_zones: usize) -> Label {
        if self.flat || self.zones(|_| true) < min_zones {
            return Label::Plain;
        }
        let covered = self.members.iter().filter(|m| m.covered()).count();
        let open = self.members.iter().filter(|m| m.open()).count();
        if covered == 0 && open > 0 {
            Label::New
        } else if open > 0 && covered * 2 >= self.members.len() {
            Label::Candidate
        } else {
            Label::Plain
        }
    }

    fn samples(&self, n: usize) -> Vec<&str> {
        let mut seen = FxHashSet::default();
        let mut out = Vec::new();
        for m in self.members.iter().filter(|m| m.open()) {
            if out.len() >= n {
                break;
            }
            if seen.insert(m.regdom.as_str()) {
                out.push(m.host.as_str());
            }
        }
        out
    }
}

fn token(r: &ProbeRow) -> String {
    let ctype = r
        .ctype
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let body = if !r.digest.is_empty() {
        r.digest.clone()
    } else if r.head.is_empty() {
        String::new()
    } else {
        format!(
            "h{:016x}.{}",
            shape::fnv1a(shape::masked_without_host(r.head.as_bytes(), &r.host).as_bytes()),
            shape::length_bucket(r.length)
        )
    };
    format!("{}:{ctype}:{body}", r.status)
}

pub fn signatures(rows: &[ProbeRow]) -> FxHashMap<&str, Vec<String>> {
    let mut by_host: FxHashMap<&str, Vec<String>> = FxHashMap::default();
    for r in rows {
        let Some(i) = LITE.iter().position(|p| *p == r.path) else {
            continue;
        };
        let slots = by_host
            .entry(r.host.as_str())
            .or_insert_with(|| vec![String::from("-"); LITE.len()]);
        slots[i] = token(r);
    }
    by_host.retain(|_, slots| slots[0] != "-");
    by_host
}

fn describe(slots: &[String]) -> String {
    LITE.iter()
        .zip(slots)
        .map(|(path, t)| {
            let mut parts = t.splitn(3, ':');
            let status = parts.next().unwrap_or("-");
            let ctype = parts.next().unwrap_or("");
            let body = parts.next().unwrap_or("");
            format!("{path}={status}:{ctype}:{}", &body[..body.len().min(8)])
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn cluster(rows: &[ProbeRow], member: impl Fn(&str) -> Member) -> Vec<Cluster> {
    let mut groups: FxHashMap<Vec<String>, Vec<&str>> = FxHashMap::default();
    for (host, slots) in signatures(rows) {
        groups.entry(slots).or_default().push(host);
    }
    let mut out: Vec<Cluster> = groups
        .into_iter()
        .map(|(slots, mut hosts)| {
            hosts.sort_unstable();
            let distinct: FxHashSet<&String> = slots.iter().filter(|t| *t != "-").collect();
            Cluster {
                id: format!("{:08x}", shape::fnv1a(slots.join("|").as_bytes()) as u32),
                shape: describe(&slots),
                flat: distinct.len() <= 1,
                members: hosts.into_iter().map(&member).collect(),
            }
        })
        .collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.zones(|_| true)));
    out
}

fn load(ctx: &Ctx) -> Result<Vec<ProbeRow>> {
    let mut stmt = ctx.store.conn.prepare(
        "SELECT host, path, status, ctype, length, head, digest FROM probe WHERE path IN ('/', '/healthy', '/i', '?random')",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ProbeRow {
            host: r.get(0)?,
            path: r.get(1)?,
            status: r.get::<_, i64>(2)?.to_string(),
            ctype: r.get(3)?,
            length: r.get(4)?,
            head: r.get(5)?,
            digest: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    let rows = load(ctx)?;
    let names: FxHashMap<String, (String, bool)> = ctx
        .store
        .rows("SELECT host, regdom, known FROM name")?
        .into_iter()
        .filter_map(|mut r| {
            let known = r.pop()?;
            let regdom = r.pop()?;
            let host = r.pop()?;
            Some((host, (regdom, !known.is_empty())))
        })
        .collect();
    let picked = ctx
        .store
        .all("SELECT DISTINCT host FROM hit WHERE verdict = 'PICK'")?;
    let clusters = cluster(&rows, |host| {
        let (regdom, listed) = names
            .get(host)
            .cloned()
            .unwrap_or_else(|| (ctx.regdom(host), false));
        Member {
            host: host.to_string(),
            regdom,
            listed,
            picked: picked.contains(host),
            allowed: ctx.allowed(host).is_some(),
        }
    });
    let mut out = Out::new();
    if let Some(id) = args.show {
        let Some(c) = clusters.iter().find(|c| c.id == id) else {
            anyhow::bail!("no cluster with id {id}");
        };
        eprintln!("{}", c.shape);
        for m in &c.members {
            out.row(&[&m.host, &m.regdom, m.state()]);
        }
        return Ok(());
    }
    let mut shown: Vec<(&Cluster, Label)> = clusters
        .iter()
        .filter(|c| args.flat || !c.flat)
        .map(|c| (c, c.label(args.min_zones)))
        .filter(|(c, l)| *l != Label::Plain || (args.all && c.zones(|_| true) >= args.min_zones))
        .collect();
    shown.sort_by_key(|(c, l)| (*l as u8, std::cmp::Reverse(c.zones(Member::open))));
    let mut labels: FxHashMap<&str, usize> = FxHashMap::default();
    for (c, l) in &shown {
        *labels.entry(l.as_str()).or_default() += 1;
        let covered = c.members.iter().filter(|m| m.covered()).count();
        let open = c.members.iter().filter(|m| m.open()).count();
        out.row(&[
            &c.id,
            l.as_str(),
            &c.members.len().to_string(),
            &c.zones(|_| true).to_string(),
            &covered.to_string(),
            &open.to_string(),
            &c.zones(Member::open).to_string(),
            &c.samples(args.samples).join(","),
            &c.shape,
        ]);
    }
    let mut labels: Vec<_> = labels.into_iter().collect();
    labels.sort_unstable();
    eprintln!(
        "hosts={} clusters={} flat={} shown={} {}",
        signatures(&rows).len(),
        clusters.len(),
        clusters.iter().filter(|c| c.flat).count(),
        shown.len(),
        labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(host: &str, path: &str, status: u16, ctype: &str, body: &str) -> ProbeRow {
        ProbeRow {
            host: host.into(),
            path: path.into(),
            status: status.to_string(),
            ctype: ctype.into(),
            length: body.len() as i64,
            head: body.into(),
            digest: shape::digest(body.as_bytes(), host),
        }
    }

    fn sgtm(host: &str) -> Vec<ProbeRow> {
        vec![
            row(host, "/", 400, "text/html; charset=utf-8", ""),
            row(host, "/healthy", 200, "text/plain", "ok"),
            row(host, "/i", 400, "text/html", ""),
            row(host, "?random", 400, "text/html", ""),
        ]
    }

    fn nginx_404(host: &str) -> Vec<ProbeRow> {
        let body = "<html><head><title>404 Not Found</title></head></html>";
        LITE.iter()
            .map(|p| row(host, p, 404, "text/html", body))
            .collect()
    }

    fn member(listed: &[&str]) -> impl Fn(&str) -> Member {
        let listed: Vec<String> = listed.iter().map(|s| s.to_string()).collect();
        move |host: &str| Member {
            host: host.into(),
            regdom: host.split_once('.').map_or(host, |(_, r)| r).into(),
            listed: listed.iter().any(|l| l == host),
            picked: false,
            allowed: false,
        }
    }

    #[test]
    fn groups_same_behaviour_across_zones_and_flags_open_hosts() {
        let rows: Vec<ProbeRow> = ["sst.a.com", "sst.b.com", "sst.c.com", "gtm.d.com"]
            .iter()
            .flat_map(|h| sgtm(h))
            .collect();
        let clusters = cluster(&rows, member(&["sst.a.com", "sst.b.com", "sst.c.com"]));
        assert_eq!(clusters.len(), 1);
        let c = &clusters[0];
        assert!(!c.flat);
        assert_eq!(c.members.len(), 4);
        assert_eq!(c.label(3), Label::Candidate);
        assert_eq!(c.samples(5), vec!["gtm.d.com"]);
    }

    #[test]
    fn same_answer_on_every_path_is_flat() {
        let rows: Vec<ProbeRow> = ["a.x.com", "b.y.com", "c.z.com"]
            .iter()
            .flat_map(|h| nginx_404(h))
            .collect();
        let clusters = cluster(&rows, member(&[]));
        assert_eq!(clusters.len(), 1);
        assert!(clusters[0].flat);
        assert_eq!(clusters[0].label(3), Label::Plain);
    }

    #[test]
    fn unlisted_cluster_is_new_and_small_one_is_plain() {
        let rows: Vec<ProbeRow> = ["t.a.com", "t.b.com", "t.c.com"]
            .iter()
            .flat_map(|h| sgtm(h))
            .collect();
        let clusters = cluster(&rows, member(&[]));
        assert_eq!(clusters[0].label(3), Label::New);
        assert_eq!(clusters[0].label(4), Label::Plain);
    }

    #[test]
    fn host_without_root_answer_is_skipped() {
        let mut rows = sgtm("a.b.com");
        rows.retain(|r| r.path != "/");
        assert!(signatures(&rows).is_empty());
    }
}
