use crate::ctx::{Ctx, Out};
use anyhow::Result;

const YIELD: &str = "
WITH o AS (SELECT DISTINCT host, source FROM origin),
     p AS (SELECT DISTINCT host FROM probe),
     h AS (SELECT host, max(verdict = 'PICK') AS pick, max(verdict = 'REVIEW') AS review FROM hit GROUP BY host)
SELECT o.source,
       count(*),
       sum(r.addrs IS NOT NULL AND r.addrs != ''),
       sum(p.host IS NOT NULL),
       coalesce(sum(h.pick), 0),
       coalesce(sum(h.review), 0)
FROM o
LEFT JOIN resolution r ON r.host = o.host
LEFT JOIN p ON p.host = o.host
LEFT JOIN h ON h.host = o.host
GROUP BY o.source";

pub fn table(ctx: &Ctx) -> Result<Vec<Vec<String>>> {
    let mut rows: Vec<(String, [i64; 5])> = ctx
        .store
        .rows(YIELD)?
        .into_iter()
        .filter_map(|r| {
            let n = |i: usize| r.get(i).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
            Some((r.first()?.clone(), [n(1), n(2), n(3), n(4), n(5)]))
        })
        .collect();
    rows.sort_unstable_by(|a, b| b.1[3].cmp(&a.1[3]).then_with(|| b.1[0].cmp(&a.1[0])));
    let mut out: Vec<Vec<String>> = Vec::with_capacity(rows.len() + 1);
    out.push(
        vec![
            "source",
            "names",
            "resolved",
            "probed",
            "picks",
            "reviews",
            "picks_per_1k_probed",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    );
    for (source, [names, resolved, probed, picks, reviews]) in &rows {
        let rate = if *probed > 0 {
            format!("{:.1}", *picks as f64 * 1000.0 / *probed as f64)
        } else {
            "-".to_string()
        };
        out.push(vec![
            source.clone(),
            names.to_string(),
            resolved.to_string(),
            probed.to_string(),
            picks.to_string(),
            reviews.to_string(),
            rate,
        ]);
    }
    Ok(out)
}

#[derive(clap::Args)]
pub struct Args {
    #[arg(
        long,
        help = "List past campaign runs with the time of each stage instead"
    )]
    runs: bool,
    #[arg(long, default_value_t = 10, help = "Campaign runs to list with --runs")]
    last: usize,
}

pub fn runs(ctx: &Ctx, last: usize) -> Result<Vec<Vec<String>>> {
    ctx.store.rows(&format!(
        "SELECT datetime(started, 'unixepoch'), seq, stage, printf('%.1f', secs), detail FROM run
         WHERE started IN (SELECT DISTINCT started FROM run ORDER BY started DESC LIMIT {last})
         ORDER BY started DESC, seq"
    ))
}

pub fn run(ctx: &Ctx, args: Args) -> Result<()> {
    let mut out = Out::new();
    let rows = if args.runs {
        runs(ctx, args.last)?
    } else {
        table(ctx)?
    };
    for r in rows {
        let cols: Vec<&str> = r.iter().map(String::as_str).collect();
        out.row(&cols);
    }
    Ok(())
}
