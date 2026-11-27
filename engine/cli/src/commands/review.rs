use crate::context::{Context, Out};
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

fn verdicts(v: &str) -> String {
    v.split(',')
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| s.chars().all(|c| c.is_ascii_uppercase()))
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn run(ctx: &Context, args: &ReviewArgs) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_plain_verdicts() {
        assert_eq!(verdicts("pick, review,x'y"), "'PICK','REVIEW'");
    }
}
