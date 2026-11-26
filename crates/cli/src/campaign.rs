use crate::ctx::{self, Ctx, Out};
use crate::{audit, cname, feeds, hunt, known, recheck, source, stats, twins};
use anyhow::Result;
use rustc_hash::FxHashSet;
use std::time::Instant;
use stella_core::psl::Psl;

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    hunt: hunt::Args,
    #[arg(
        long,
        help = "Download nothing: no reference lists, issues, exceptions, vendor seeds, crt.sh or passive DNS"
    )]
    offline: bool,
    #[arg(
        long,
        default_value_t = 24,
        help = "Download the reference lists again when they are older than this many hours"
    )]
    list_age_hours: u64,
    #[arg(
        long,
        default_value_t = 7,
        help = "Learn vendor CNAME targets again when that is older than this many days"
    )]
    vendor_age_days: i64,
    #[arg(
        long,
        default_value_t = 200,
        help = "Zones of new picks asked at subdomain.center"
    )]
    passive_zones: usize,
    #[arg(
        long,
        default_value_t = 20,
        help = "Zones of new picks searched in crt.sh"
    )]
    ct_zones: usize,
    #[arg(
        long,
        default_value_t = 300,
        help = "New picks whose region, shard and country domain twins are tried"
    )]
    twin_seeds: usize,
    #[arg(
        long,
        default_value_t = 7,
        help = "Recheck picks last confirmed this many days ago or earlier, 0 skips the recheck"
    )]
    recheck_days: i64,
    #[arg(long, help = "Print the rows of every stage, not only the final hits")]
    verbose: bool,
}

const TWIN_MAX_NUM: u32 = 40;

fn last_run(ctx: &Ctx) -> i64 {
    ctx.store
        .rows("SELECT max(at) FROM done WHERE kind = 'campaign'")
        .ok()
        .and_then(|r| r.into_iter().next())
        .and_then(|mut r| r.pop())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn picks_since(ctx: &Ctx, since: i64, limit: usize) -> Result<Vec<(String, String)>> {
    Ok(ctx
        .store
        .rows(&format!(
            "SELECT host, min(product) FROM hit WHERE verdict = 'PICK' AND at > {since}
             GROUP BY host ORDER BY max(at) DESC LIMIT {limit}"
        ))?
        .into_iter()
        .filter_map(|mut r| {
            let product = r.pop()?;
            let host = r.pop()?;
            Some((host, product))
        })
        .collect())
}

static STAGES: std::sync::Mutex<Vec<(&'static str, f64)>> = std::sync::Mutex::new(Vec::new());

struct Stage(&'static str, Instant);

impl Stage {
    fn start(name: &'static str) -> Self {
        eprintln!("campaign: {name}");
        Self(name, Instant::now())
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let secs = self.1.elapsed().as_secs_f64();
        if let Ok(mut s) = STAGES.lock() {
            s.push((self.0, secs));
        }
        eprintln!(
            "campaign: {} done in {:.1}s",
            self.0,
            self.1.elapsed().as_secs_f64()
        );
    }
}

async fn sync(ctx: &mut Ctx, args: &Args) -> Result<()> {
    let _s = Stage::start("sync");
    let stale = known::age(ctx).is_none_or(|a| a.as_secs() > args.list_age_hours * 3600);
    if stale {
        known::sync(ctx).await?;
        ctx.psl = Psl::load(&ctx.paths.psl())?;
    }
    audit::sync(ctx, 24).await?;
    if cname::learned_age(ctx).is_none_or(|a| a > args.vendor_age_days * 86_400) {
        let learn = cname::Learn {
            sample: 120_000,
            top: 50_000,
            list: "tranco".into(),
            min_zones: 8,
            min_lift: 5.0,
        };
        cname::learn(ctx, &args.hunt.dns.config(), &learn).await?;
    }
    Ok(())
}

async fn expand(ctx: &mut Ctx, args: &Args, since: i64) -> Result<()> {
    let _s = Stage::start("zones of new picks");
    let picks = picks_since(ctx, since, usize::MAX >> 1)?;
    let known = ctx.known();
    let mut seen = FxHashSet::default();
    let zones: Vec<String> = picks
        .iter()
        .map(|(h, _)| ctx.psl.icann_regdom_or_self(h).to_string())
        .filter(|z| !known.contains(z) && seen.insert(z.clone()))
        .collect();
    eprintln!(
        "campaign: {} new picks in {} zones",
        picks.len(),
        zones.len()
    );
    let mut passive: Vec<String> = zones.clone();
    let mates = crate::mates::zones(ctx)?;
    eprintln!(
        "campaign: {} zones share dns, tags or certificates with pick zones",
        mates.len()
    );
    passive.extend(
        mates
            .into_iter()
            .filter(|z| !known.contains(z) && seen.insert(z.clone())),
    );
    passive.truncate(args.passive_zones);
    let ct: Vec<String> = zones.iter().take(args.ct_zones).cloned().collect();
    feeds::passive_zones(ctx, passive, 4).await?;
    source::ct_zones(ctx, ct, 4, false, true).await
}

async fn hunt_pending(ctx: &mut Ctx, args: &Args) -> Result<usize> {
    let _s = Stage::start("hunt");
    let known = ctx.known();
    let mut names: Vec<String> = ctx
        .store
        .all("SELECT DISTINCT host FROM origin WHERE host NOT IN (SELECT host FROM resolution)")?
        .into_iter()
        .filter(|n| !known.contains(n))
        .collect();
    names.sort_unstable();
    eprintln!("campaign: {} names waiting", names.len());
    hunt::hunt(ctx, &args.hunt, names).await
}

async fn twins_of_picks(ctx: &mut Ctx, args: &Args, since: i64) -> Result<usize> {
    let _s = Stage::start("twins");
    let seeds = picks_since(ctx, since, args.twin_seeds)?;
    let mut rows: Vec<Vec<String>> = Vec::new();
    for (host, product) in &seeds {
        stella_sources::variants::variants(host, TWIN_MAX_NUM, &mut |c| {
            rows.push(vec![c, host.clone()]);
        });
        if product == "sgtm" {
            for c in stella_sources::variants::cctld_twins(host) {
                rows.push(vec![c, host.clone()]);
            }
        }
    }
    eprintln!("campaign: {} seeds, {} candidates", seeds.len(), rows.len());
    if rows.is_empty() {
        return Ok(0);
    }
    twins::verify(ctx, &args.hunt.dns, &args.hunt.probe, rows).await
}

fn log_run(ctx: &Ctx, start_at: i64, secs: f64, outcome: &str) -> Result<()> {
    let stages = STAGES
        .lock()
        .map(|mut s| std::mem::take(&mut *s))
        .unwrap_or_default();
    let tx = ctx.store.conn.unchecked_transaction()?;
    for (seq, (stage, secs)) in stages.iter().enumerate() {
        tx.execute(
            "INSERT OR REPLACE INTO run VALUES(?1, ?2, ?3, ?4, '')",
            rusqlite::params![start_at, seq as i64, stage, secs],
        )?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO run VALUES(?1, ?2, 'total', ?3, ?4)",
        rusqlite::params![start_at, stages.len() as i64, secs, outcome],
    )?;
    tx.commit()?;
    Ok(())
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    let started = Instant::now();
    let start_at = stella_core::now();
    let result = campaign(ctx, args, started, start_at).await;
    let outcome = match &result {
        Ok(summary) => summary.clone(),
        Err(e) => format!("error: {e}"),
    };
    log_run(ctx, start_at, started.elapsed().as_secs_f64(), &outcome)?;
    result.map(|_| ())
}

async fn campaign(
    ctx: &mut Ctx,
    mut args: Args,
    started: Instant,
    start_at: i64,
) -> Result<String> {
    args.hunt.tag.clear();
    let since = last_run(ctx);
    ctx::quiet(!args.verbose);
    if !args.offline {
        sync(ctx, &args).await?;
    }
    let mut picks = hunt_pending(ctx, &args).await?;
    if !args.offline {
        expand(ctx, &args, since).await?;
        picks += hunt_pending(ctx, &args).await?;
    }
    let twins = twins_of_picks(ctx, &args, since).await?;
    {
        let _s = Stage::start("cname vendors");
        cname::matches(ctx)?;
    }
    if args.recheck_days > 0 {
        let _s = Stage::start("recheck");
        recheck::recheck(ctx, &args.hunt.dns, &args.hunt.probe, args.recheck_days).await?;
    }
    {
        let _s = Stage::start("fuse");
        crate::fuse::apply(
            ctx,
            2,
            usize::try_from(args.hunt.max_ip).unwrap_or(0),
            false,
        )?;
    }
    let (lowered, _) = {
        let _s = Stage::start("audit");
        audit::apply(ctx)?
    };
    {
        let _s = Stage::start("clusters");
        eprintln!(
            "campaign: clusters {}",
            crate::clusters::summary(ctx, 3, 2)?
        );
    }
    ctx.store.conn.execute(
        "INSERT OR REPLACE INTO done VALUES('campaign', ?1, ?2)",
        rusqlite::params![start_at.to_string(), start_at],
    )?;
    ctx::quiet(false);
    let mut out = Out::new();
    let fresh = ctx.store.rows(&format!(
        "SELECT host, product, verdict, evidence FROM hit
         WHERE at >= {start_at} AND verdict IN ('PICK', 'REVIEW') ORDER BY verdict, host"
    ))?;
    for r in &fresh {
        let cols: Vec<&str> = r.iter().map(String::as_str).collect();
        out.row(&cols);
    }
    drop(out);
    for r in stats::table(ctx)? {
        eprintln!("{}", r.join("\t"));
    }
    let summary = format!(
        "hunt picks={picks} twin picks={twins} lowered by audit={lowered} new hits={}",
        fresh.len()
    );
    eprintln!(
        "campaign: {summary} secs={:.1}",
        started.elapsed().as_secs_f64()
    );
    Ok(summary)
}
