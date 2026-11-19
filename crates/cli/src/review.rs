use crate::ctx::{Ctx, Out};
use anyhow::Result;

#[derive(clap::Args)]
pub struct ReviewArgs {
    #[arg(
        long,
        default_value = "PICK,REVIEW",
        help = "Verdicts to list, comma separated"
    )]
    verdict: String,
}

#[derive(clap::Args)]
pub struct ExportArgs {
    #[arg(long, help = "Also export hosts that a reference list already covers")]
    with_known: bool,
}

fn verdicts(v: &str) -> String {
    v.split(',')
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| s.chars().all(|c| c.is_ascii_uppercase()))
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn review(ctx: &Ctx, args: ReviewArgs) -> Result<()> {
    let rows = ctx.store.rows(&format!(
        "SELECT hit.host, hit.product, hit.verdict, hit.evidence, coalesce(name.known, ''),
                coalesce((SELECT group_concat(source || ':' || detail, ' ') FROM (SELECT source, detail FROM origin WHERE origin.host = hit.host LIMIT 3)), '')
         FROM hit LEFT JOIN name USING(host) WHERE hit.verdict IN ({}) ORDER BY hit.verdict, hit.product, hit.host",
        verdicts(&args.verdict)
    ))?;
    let mut out = Out::new();
    for r in &rows {
        out.row(&r.iter().map(String::as_str).collect::<Vec<_>>());
    }
    eprintln!("rows={}", rows.len());
    Ok(())
}

pub fn export(ctx: &Ctx, args: ExportArgs) -> Result<()> {
    let filter = if args.with_known {
        ""
    } else {
        "AND coalesce(name.known, '') = ''"
    };
    let rows = ctx.store.rows(&format!(
        "SELECT DISTINCT hit.host FROM hit LEFT JOIN name USING(host) WHERE hit.verdict = 'PICK' {filter} ORDER BY hit.host"
    ))?;
    let mut out = Out::new();
    let mut n = 0usize;
    for r in rows.iter().filter(|r| ctx.allowed(&r[0]).is_none()) {
        n += 1;
        out.row(&[&r[0]]);
    }
    eprintln!("hosts={n} allowlisted={}", rows.len() - n);
    Ok(())
}
