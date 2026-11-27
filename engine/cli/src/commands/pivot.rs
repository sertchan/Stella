use crate::context::{Context, Out};
use anyhow::Result;
use stella_core::store::Row;

#[derive(clap::Args)]
pub struct Args {
    #[arg(
        long,
        default_value_t = 40,
        help = "Skip addresses shared by more hosts than this"
    )]
    max_ip: i64,
    #[arg(
        long,
        help = "Pivot from REVIEW hits too, so certificates and addresses of behaviour hits are followed"
    )]
    with_review: bool,
}

pub fn run(ctx: &mut Context, args: &Args) -> Result<()> {
    let p =
        stella_sources::pivot::collect(&ctx.store.conn, &ctx.psl, args.max_ip, args.with_review)?;
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    for (host, addr, via) in &p.neighbours {
        out.row(&[host, "ip", addr, via]);
        w.send(Row::Origin {
            host: host.clone(),
            source: "pivot-ip".into(),
            detail: via.clone(),
        });
    }
    for (san, host) in &p.sans {
        out.row(&[san, "san", host]);
        w.send(Row::Origin {
            host: san.clone(),
            source: "pivot-san".into(),
            detail: host.clone(),
        });
    }
    for z in &p.zones {
        out.row(&[z, "zone"]);
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "ip-neighbours={} sans={} zones={}",
        p.neighbours.len(),
        p.sans.len(),
        p.zones.len()
    );
    Ok(())
}
