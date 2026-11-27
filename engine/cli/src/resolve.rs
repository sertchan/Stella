use crate::ctx::{Ctx, Out};
use crate::pipeline::{self, DnsArgs};
use anyhow::Result;
use std::time::Instant;
use stella_dns::wild::Verdict;

#[derive(clap::Args)]
pub struct Args {
    #[command(flatten)]
    dns: DnsArgs,
    #[arg(long, help = "Compare each host with random names in its zones")]
    wild: bool,
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    let names = ctx.names();
    let started = Instant::now();
    let w = ctx.store.writer()?;
    let n = names.len();
    let res = pipeline::resolve(ctx, &w, &args.dns.config(), names, args.wild).await?;
    let mut out = Out::new();
    let mut answered = 0usize;
    let mut timeouts = 0usize;
    for r in &res {
        answered += usize::from(r.res.answered());
        timeouts += usize::from(r.res.rcode == stella_dns::chase::TIMEOUT);
        out.row(&[
            &r.res.host,
            &r.res.rcode.to_string(),
            &r.res.chain.join(">"),
            &pipeline::join_addrs(&r.res.addrs),
            r.wild.map_or("", Verdict::as_str),
            &r.known,
        ]);
    }
    drop(out);
    let rows = w.finish()?;
    eprintln!(
        "names={n} answered={answered} timeouts={timeouts} rows={rows} secs={:.1}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
