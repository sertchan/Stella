use crate::ctx::Ctx;
use crate::pipeline::{self, DnsArgs, ProbeArgs};
use anyhow::Result;
use rusqlite::params;
use std::net::IpAddr;
use std::time::Instant;
use stella_dns::chase;

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

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    recheck(ctx, &args.dns, &args.probe, args.older_than_days)
        .await
        .map(|_| ())
}

pub async fn recheck(
    ctx: &mut Ctx,
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
            let a = r.res.addrs.iter().find(|a| chase::public(a))?;
            let b = pipeline::battery_for(ctx, &r.res.host, "auto");
            Some((r.res.host, IpAddr::V4(*a), b))
        })
        .collect();
    let alive = items.len();
    let prober = probe.prober();
    let st = pipeline::probe(ctx, &w, &prober, items, probe.conc, |_, _| {}).await;
    tokio::task::block_in_place(|| w.flush());
    let mut stale = 0usize;
    {
        let tx = ctx.store.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "UPDATE hit SET verdict = 'STALE', evidence = evidence || '; not confirmed at recheck'
                 WHERE verdict = 'PICK' AND host = ?1 AND at < ?2",
            )?;
            for h in &hosts {
                stale += stmt.execute(params![h, start_at])?;
            }
        }
        tx.commit()?;
    }
    w.finish()?;
    eprintln!(
        "picks={total} resolving={alive} stale={stale} secs={:.1} {}",
        started.elapsed().as_secs_f64(),
        st.line()
    );
    Ok(stale)
}
