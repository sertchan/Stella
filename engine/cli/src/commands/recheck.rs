use crate::context::Context;
use crate::pipeline::{self, DnsArgs, ProbeArgs};
use anyhow::Result;
use rusqlite::params;
use std::net::IpAddr;
use std::time::Instant;
use stella_dns::resolver;

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    dns: DnsArgs,
    #[command(flatten)]
    probe: ProbeArgs,
    #[arg(
        long,
        default_value_t = 7,
        help = "Recheck picks last confirmed this many days ago or earlier, 0 rechecks all"
    )]
    older_than_days: i64,
}

const DAY: i64 = 86_400;
const STRIKE: &str = "recheck-miss";
const MAX_MISSED_PERCENT: usize = 30;

pub async fn run(ctx: &mut Context, args: Args) -> Result<()> {
    recheck(ctx, &args.dns, &args.probe, args.older_than_days)
        .await
        .map(|_| ())
}

pub async fn recheck(
    ctx: &mut Context,
    dns: &DnsArgs,
    probe: &ProbeArgs,
    older_than_days: i64,
) -> Result<usize> {
    let started = Instant::now();
    let start_at = stella_core::now();
    let cutoff = start_at - older_than_days * DAY;
    let hosts: Vec<String> = ctx
        .store
        .rows(&format!(
            "SELECT DISTINCT host FROM hit WHERE verdict = 'PICK' AND at <= {cutoff} ORDER BY host"
        ))?
        .into_iter()
        .filter_map(|mut r| r.pop())
        .collect();
    let total = hosts.len();
    let w = ctx.store.writer()?;
    let res = pipeline::resolve(ctx, &w, &dns.config(), hosts.clone(), false).await?;
    let items: Vec<_> = res
        .into_iter()
        .filter_map(|r| {
            let a = r.res.addrs.iter().find(|a| resolver::public(a))?;
            let b = pipeline::battery_for(ctx, &r.res.host, "auto");
            Some((r.res.host, IpAddr::V4(*a), b))
        })
        .collect();
    let alive = items.len();
    let prober = probe.prober();
    let st = pipeline::probe(ctx, &w, &prober, items, probe.conc, |_, _| {}).await;
    tokio::task::block_in_place(|| w.flush());
    let confirmed = ctx.store.all(&format!(
        "SELECT DISTINCT host FROM hit WHERE verdict = 'PICK' AND at >= {start_at}"
    ))?;
    let missed: Vec<&String> = hosts.iter().filter(|h| !confirmed.contains(*h)).collect();
    let healthy = total == 0 || missed.len() * 100 <= total * MAX_MISSED_PERCENT;
    let (mut stale, mut first) = (0usize, 0usize);
    if healthy {
        let strikes = ctx.store.done(STRIKE)?;
        let tx = ctx.store.conn.unchecked_transaction()?;
        {
            let mut mark = tx.prepare(
                "UPDATE hit SET verdict = 'STALE', evidence = evidence || '; not confirmed at two rechecks'
                 WHERE verdict = 'PICK' AND host = ?1 AND at < ?2",
            )?;
            let mut strike = tx.prepare("INSERT OR REPLACE INTO done VALUES(?1, ?2, ?3)")?;
            let mut clear = tx.prepare("DELETE FROM done WHERE kind = ?1 AND key = ?2")?;
            for h in &hosts {
                if confirmed.contains(h) {
                    clear.execute(params![STRIKE, h])?;
                } else if strikes.contains(h) {
                    stale += mark.execute(params![h, start_at])?;
                    clear.execute(params![STRIKE, h])?;
                } else {
                    first += 1;
                    strike.execute(params![STRIKE, h, start_at])?;
                }
            }
        }
        tx.commit()?;
    } else {
        eprintln!(
            "recheck: {} of {total} picks unconfirmed, more than {MAX_MISSED_PERCENT}%, so this run marks nothing",
            missed.len()
        );
    }
    w.finish()?;
    eprintln!(
        "picks={total} resolving={alive} first-miss={first} stale={stale} secs={:.1} {}",
        started.elapsed().as_secs_f64(),
        st.line()
    );
    Ok(stale)
}
