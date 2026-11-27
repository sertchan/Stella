use crate::context::{Context, Out};
use anyhow::Result;
use rusqlite::params;
use rustc_hash::FxHashMap;
use std::time::Duration;
use stella_crawl::breakage::{self, Case, Options, Outcome, Snapshot};
use stella_probe::rules::{PICK, REVIEW};

#[derive(clap::Args)]
pub struct Args {
    #[arg(long, help = "Test the newest picks instead of the hosts on stdin")]
    picks: bool,
    #[arg(long, default_value_t = 50, help = "Picks tested at most")]
    limit: usize,
    #[arg(long, default_value_t = 2, help = "Pages tested per host")]
    pages: usize,
    #[arg(long, default_value_t = 15, help = "Seconds each page is watched")]
    dwell: u64,
    #[arg(
        long,
        default_value_t = 2,
        help = "Browsers with a blocked host at once"
    )]
    par: usize,
    #[arg(
        long,
        help = "Run Chromium with a window on a headless Wayland compositor"
    )]
    headful: bool,
    #[arg(long, help = "Leave cookie banners alone")]
    no_consent: bool,
}

fn pages_for(ctx: &Context, host: &str, n: usize) -> Result<Vec<String>> {
    let mut sites: Vec<String> = ctx
        .store
        .set(
            "SELECT DISTINCT site FROM request WHERE url LIKE 'http%://' || ?1 || '/%' LIMIT 50",
            host,
        )?
        .into_iter()
        .filter(|s| s != host)
        .collect();
    sites.sort_unstable();
    let mut pages: Vec<String> = sites
        .into_iter()
        .take(n)
        .map(|s| format!("https://{s}/"))
        .collect();
    let zone = ctx.psl.icann_regdom_or_self(host);
    if pages.is_empty() && zone != host {
        pages.push(format!("https://{zone}/"));
    }
    Ok(pages)
}

fn range(base: &[Snapshot], field: fn(&Snapshot) -> usize) -> String {
    let v: Vec<usize> = base
        .iter()
        .filter(|s| s.error.is_none())
        .map(field)
        .collect();
    match (v.iter().min(), v.iter().max()) {
        (Some(a), Some(b)) if a == b => a.to_string(),
        (Some(a), Some(b)) => format!("{a}-{b}"),
        _ => "-".into(),
    }
}

fn metrics(o: &Outcome) -> String {
    let b = &o.blocked;
    format!(
        "text {} -> {}, controls {} -> {}, frames {} -> {}, errors {} -> {}, failed {} -> {}",
        range(&o.base, |s| s.text),
        b.text,
        range(&o.base, |s| s.controls),
        b.controls,
        range(&o.base, |s| s.frames),
        b.frames,
        range(&o.base, |s| s.errors),
        b.errors,
        range(&o.base, |s| s.failed),
        b.failed
    )
}

pub async fn run(ctx: &mut Context, args: Args) -> Result<()> {
    let hosts: Vec<String> = if args.picks {
        ctx.store
            .rows(&format!(
                "SELECT host FROM hit WHERE verdict = '{PICK}' GROUP BY host ORDER BY max(at) DESC LIMIT {}",
                args.limit
            ))?
            .into_iter()
            .filter_map(|mut r| r.pop())
            .collect()
    } else {
        ctx.names()
    };
    let mut cases = Vec::new();
    for host in hosts {
        let pages = pages_for(ctx, &host, args.pages)?;
        if pages.is_empty() {
            eprintln!("breakage {host}: no page to test, crawl a site that loads it first");
            continue;
        }
        cases.push(Case { host, pages });
    }
    let total = cases.len();
    let opts = Options {
        dwell: Duration::from_secs(args.dwell),
        consent: !args.no_consent,
        headful: args.headful,
        par: args.par,
        width: 412,
        height: 915,
    };
    let work = ctx.paths.cache().join("breakage");
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let runner = tokio::spawn(async move { breakage::run(cases, opts, &work, tx).await });
    let mut out = Out::new();
    let mut found: FxHashMap<String, Vec<String>> = FxHashMap::default();
    let (mut breaks, mut fine, mut unknown) = (0usize, 0usize, 0usize);
    while let Some(o) = rx.recv().await {
        let j = &o.judgement;
        let verdict = if !j.known {
            unknown += 1;
            "UNKNOWN"
        } else if j.breaks {
            breaks += 1;
            "BREAKS"
        } else {
            fine += 1;
            "OK"
        };
        let mut why: Vec<String> = j.reasons.clone();
        why.extend(j.notes.iter().cloned());
        out.row(&[&o.host, &o.page, verdict, &why.join("; "), &metrics(&o)]);
        let note = match verdict {
            "BREAKS" => format!("blocking it changes {}: {}", o.page, j.reasons.join(", ")),
            "OK" => format!("no visible change on {} when blocked", o.page),
            _ => continue,
        };
        found.entry(o.host.clone()).or_default().push(note);
    }
    runner.await??;
    drop(out);
    let tx = ctx.store.conn.unchecked_transaction()?;
    let mut lowered = 0usize;
    {
        let mut add = tx.prepare_cached(
            "UPDATE hit SET evidence = evidence || '; ' || ?2 WHERE host = ?1 AND verdict != 'DROP' AND instr(evidence, ?2) = 0",
        )?;
        let mut lower = tx.prepare_cached(&format!(
            "UPDATE hit SET verdict = '{REVIEW}' WHERE host = ?1 AND verdict = '{PICK}'"
        ))?;
        for (host, notes) in &found {
            for n in notes {
                add.execute(params![host, n])?;
            }
            if notes.iter().any(|n| n.starts_with("blocking it changes")) {
                lowered += lower.execute([host])?;
            }
        }
    }
    tx.commit()?;
    eprintln!(
        "breakage: hosts={total} pages ok={fine} breaks={breaks} unknown={unknown} picks moved to review={lowered}"
    );
    Ok(())
}
