use crate::ctx::{Ctx, Out};
use anyhow::Result;
use rusqlite::params;
use rustc_hash::FxHashMap;
use std::time::{Duration, Instant};
use stella_net::client::{self, Options};
use stella_probe::rules::{DROP, PICK, REVIEW};
use stella_sources::audit::{
    self, CONTENT, DECLINED, DNS, DNS_EXACT, EXCEPTION_LISTS, GRANTED, LABELS, PENDING,
};

#[derive(clap::Args)]
pub struct Args {
    #[arg(
        long,
        help = "Use the issues and exceptions already stored, fetch nothing"
    )]
    no_sync: bool,
    #[arg(
        long,
        default_value_t = 24,
        help = "Fetch an exception list again only when it is older than this many hours"
    )]
    list_age_hours: i64,
}

const LIST_CAP: usize = 64 * 1024 * 1024;
const MAX_PAGES: usize = 400;

pub fn token() -> Option<String> {
    for var in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(t) = std::env::var(var)
            && !t.trim().is_empty()
        {
            return Some(t.trim().to_string());
        }
    }
    let out = std::process::Command::new("gh")
        .args(["auth", "token"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let t = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !t.is_empty()).then_some(t)
}

fn mark(ctx: &Ctx, kind: &str, key: &str) -> Result<()> {
    ctx.store.conn.execute(
        "INSERT OR REPLACE INTO done VALUES(?1, ?2, ?3)",
        params![kind, key, stella_core::now()],
    )?;
    Ok(())
}

async fn sync_issues(ctx: &Ctx, c: &reqwest::Client) -> Result<()> {
    let tok = token();
    if tok.is_none() {
        eprintln!(
            "issues: no GitHub token (GH_TOKEN or gh auth), unauthenticated limit is 60 pages an hour"
        );
    }
    for label in LABELS {
        let kind = format!("issue-sync-{label}");
        let since: Option<String> = ctx
            .store
            .rows(&format!("SELECT max(key) FROM done WHERE kind = '{kind}'"))?
            .into_iter()
            .next()
            .and_then(|mut r| r.pop())
            .filter(|s| !s.is_empty());
        let (mut issues, mut hosts) = (0usize, 0usize);
        for page in 1..=MAX_PAGES {
            let url = audit::issues_url(label, since.as_deref(), page);
            let body = match audit::github_get(c, &url, tok.as_deref()).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("issues {label} page {page}: {e}");
                    break;
                }
            };
            let list = audit::parse_issues(&body, label, |h| {
                ctx.psl.listed_tld(h) && ctx.psl.regdom(h).is_some()
            })?;
            let n = list.len();
            let tx = ctx.store.conn.unchecked_transaction()?;
            {
                let mut del = tx.prepare_cached("DELETE FROM issue WHERE number = ?1")?;
                let mut ins =
                    tx.prepare_cached("INSERT OR REPLACE INTO issue VALUES(?1, ?2, ?3, ?4)")?;
                for i in &list {
                    del.execute([i.number])?;
                    for h in &i.hosts {
                        ins.execute(params![h, i.number, label, i.outcome])?;
                    }
                    hosts += i.hosts.len();
                }
            }
            tx.commit()?;
            issues += n;
            if let Some(last) = list.last() {
                mark(ctx, &kind, &last.updated)?;
            }
            if audit::last_page(n) {
                break;
            }
        }
        eprintln!("issues {label}: {issues} issues, {hosts} host mentions");
    }
    Ok(())
}

async fn sync_exceptions(ctx: &Ctx, c: &reqwest::Client, max_age: i64) -> Result<()> {
    let fresh_after = stella_core::now() - max_age;
    for (name, url, kind) in EXCEPTION_LISTS {
        let fresh = ctx
            .store
            .rows(&format!(
                "SELECT 1 FROM done WHERE kind = 'exception-sync' AND key = '{name}' AND at > {fresh_after}"
            ))?
            .is_empty();
        if !fresh {
            continue;
        }
        let page = match client::fetch(c, url, LIST_CAP).await {
            Ok(p) if p.status == 200 => p,
            Ok(p) => {
                eprintln!("exceptions {name}: http {}", p.status);
                continue;
            }
            Err(e) => {
                eprintln!("exceptions {name}: {e}");
                continue;
            }
        };
        let rows = audit::exceptions(&String::from_utf8_lossy(&page.body), *kind);
        let tx = ctx.store.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM exception WHERE list = ?1", [name])?;
        {
            let mut ins =
                tx.prepare_cached("INSERT OR REPLACE INTO exception VALUES(?1, ?2, ?3)")?;
            for (h, k) in &rows {
                ins.execute(params![h, name, k])?;
            }
        }
        tx.commit()?;
        mark(ctx, "exception-sync", name)?;
        eprintln!("exceptions {name}: {}", rows.len());
    }
    Ok(())
}

pub async fn sync(ctx: &Ctx, list_age_hours: i64) -> Result<()> {
    let c = client::build(&Options {
        timeout: Duration::from_secs(120),
        ..Options::default()
    })?;
    sync_issues(ctx, &c).await?;
    sync_exceptions(ctx, &c, list_age_hours * 3600).await
}

fn rank(v: &str) -> u8 {
    match v {
        PICK => 2,
        REVIEW => 1,
        _ => 0,
    }
}

type Issues = FxHashMap<String, Vec<(i64, String, String)>>;
type Exceptions = FxHashMap<String, Vec<(String, String)>>;

fn judge(host: &str, issues: &Issues, exc: &Exceptions) -> (&'static str, Vec<String>) {
    let mut v = PICK;
    let mut notes = Vec::new();
    let mut lower = |to: &'static str, note: String, notes: &mut Vec<String>| {
        if rank(to) < rank(v) {
            v = to;
        }
        notes.push(note);
    };
    for (n, kind, out) in issues.get(host).into_iter().flatten() {
        match (kind.as_str(), out.as_str()) {
            ("allow", GRANTED) => lower(DROP, format!("unblocked in allow issue #{n}"), &mut notes),
            ("allow", PENDING) => lower(REVIEW, format!("allow request #{n} is open"), &mut notes),
            ("allow", DECLINED) => notes.push(format!("allow request #{n} was declined")),
            ("deny", DECLINED) => lower(
                REVIEW,
                format!("deny request #{n} was declined"),
                &mut notes,
            ),
            ("deny", _) => notes.push(format!("already requested in #{n}")),
            _ => {}
        }
    }
    for p in stella_core::name::suffixes(host)
        .skip(1)
        .filter(|p| p.contains('.'))
    {
        for (n, kind, out) in issues.get(p).into_iter().flatten() {
            if kind == "allow" && out == GRANTED {
                notes.push(format!("{p} unblocked in allow issue #{n}"));
            }
        }
    }
    for s in stella_core::name::suffixes(host) {
        for (list, kind) in exc.get(s).into_iter().flatten() {
            match kind.as_str() {
                DNS if s == host => lower(REVIEW, format!("allowed by {list}"), &mut notes),
                DNS => notes.push(format!("{s} allowed by {list}")),
                DNS_EXACT if s == host => lower(REVIEW, format!("allowed by {list}"), &mut notes),
                CONTENT if s == host => lower(
                    REVIEW,
                    format!("{list} has an exception for this host, check it live"),
                    &mut notes,
                ),
                _ => {}
            }
        }
    }
    (v, notes)
}

fn load<T>(
    ctx: &Ctx,
    sql: &str,
    f: impl Fn(Vec<String>) -> Option<(String, T)>,
) -> Result<FxHashMap<String, Vec<T>>> {
    let mut m: FxHashMap<String, Vec<T>> = FxHashMap::default();
    for r in ctx.store.rows(sql)? {
        if let Some((k, v)) = f(r) {
            m.entry(k).or_default().push(v);
        }
    }
    Ok(m)
}

pub fn apply(ctx: &Ctx) -> Result<(usize, usize)> {
    let issues: Issues = load(
        ctx,
        "SELECT host, number, kind, outcome FROM issue WHERE outcome != 'void'",
        |r| {
            Some((
                r[0].clone(),
                (r[1].parse().ok()?, r[2].clone(), r[3].clone()),
            ))
        },
    )?;
    let exc: Exceptions = load(ctx, "SELECT host, list, kind FROM exception", |r| {
        Some((r[0].clone(), (r[1].clone(), r[2].clone())))
    })?;
    let hits = ctx.store.rows(&format!(
        "SELECT host, product, evidence, verdict FROM hit WHERE verdict IN ('{PICK}', '{REVIEW}') ORDER BY host"
    ))?;
    let mut out = Out::new();
    let (mut lowered, mut noted) = (0usize, 0usize);
    let tx = ctx.store.conn.unchecked_transaction()?;
    {
        let mut upd = tx.prepare_cached(
            "UPDATE hit SET verdict = ?1, evidence = ?2 WHERE host = ?3 AND product = ?4",
        )?;
        for r in &hits {
            let (host, product, evidence, verdict) = (&r[0], &r[1], &r[2], &r[3]);
            let (v, notes) = judge(host, &issues, &exc);
            let new_verdict = if rank(v) < rank(verdict) {
                v
            } else {
                verdict.as_str()
            };
            let fresh: Vec<&String> = notes
                .iter()
                .filter(|n| !evidence.contains(n.as_str()))
                .collect();
            if new_verdict == verdict && fresh.is_empty() {
                continue;
            }
            let mut ev = evidence.clone();
            for n in &fresh {
                ev.push_str("; ");
                ev.push_str(n);
            }
            upd.execute(params![new_verdict, ev, host, product])?;
            if new_verdict == verdict {
                noted += 1;
            } else {
                lowered += 1;
            }
            let joined: Vec<&str> = fresh.iter().map(|s| s.as_str()).collect();
            out.row(&[host, product, verdict, new_verdict, &joined.join("; ")]);
        }
    }
    tx.commit()?;
    Ok((lowered, noted))
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    let started = Instant::now();
    if !args.no_sync {
        sync(ctx, args.list_age_hours).await?;
    }
    let (lowered, noted) = apply(ctx)?;
    eprintln!(
        "audit: lowered={lowered} noted={noted} secs={:.1}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_only_lowers_verdicts() {
        let mut issues = Issues::default();
        issues.insert(
            "a.shop.com".into(),
            vec![(1, "allow".into(), GRANTED.into())],
        );
        issues.insert("shop.com".into(), vec![(2, "allow".into(), GRANTED.into())]);
        issues.insert("d.x.com".into(), vec![(3, "deny".into(), DECLINED.into())]);
        let mut exc = Exceptions::default();
        exc.insert("y.com".into(), vec![("adguard-dns".into(), DNS.into())]);
        exc.insert("p.z.com".into(), vec![("easylist".into(), CONTENT.into())]);
        exc.insert("z.com".into(), vec![("easylist".into(), CONTENT.into())]);
        assert_eq!(judge("a.shop.com", &issues, &exc).0, DROP);
        assert_eq!(judge("b.shop.com", &issues, &exc).0, PICK);
        assert_eq!(judge("d.x.com", &issues, &exc).0, REVIEW);
        assert_eq!(judge("t.y.com", &issues, &exc).0, PICK);
        assert_eq!(judge("y.com", &issues, &exc).0, REVIEW);
        assert_eq!(judge("p.z.com", &issues, &exc).0, REVIEW);
        assert_eq!(judge("q.z.com", &issues, &exc).0, PICK);
        assert!(judge("free.com", &issues, &exc).1.is_empty());
    }
}
