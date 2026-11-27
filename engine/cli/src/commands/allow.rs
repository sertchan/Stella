use crate::context::{Context, Out};
use anyhow::{Result, bail};
use rusqlite::params;
use stella_core::store::Row;

#[derive(clap::Args)]
pub struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    #[command(
        about = "Never pick a host or its subdomains, for example because blocking it breaks a site"
    )]
    Add {
        host: String,
        #[arg(long, help = "Why the host must stay unblocked")]
        reason: String,
    },
    #[command(about = "Remove a host from the allowlist")]
    Remove { host: String },
    #[command(about = "Print the allowlist")]
    List,
}

pub fn run(ctx: &mut Context, args: Args) -> Result<()> {
    match args.cmd {
        Cmd::Add { host, reason } => {
            let Some(host) = stella_core::name::normalize(&host) else {
                bail!("not a host name: {host}");
            };
            let w = ctx.store.writer()?;
            w.send(Row::Allow {
                host: host.clone(),
                reason: reason.clone(),
            });
            w.finish()?;
            let changed = ctx.store.conn.execute(
                "UPDATE hit SET verdict = 'DROP', evidence = evidence || '; allowlisted: ' || ?2
                 WHERE verdict != 'DROP' AND (host = ?1 OR host LIKE '%.' || ?1)",
                params![host, reason],
            )?;
            eprintln!("allowed {host}, {changed} hits dropped");
        }
        Cmd::Remove { host } => {
            let n = ctx
                .store
                .conn
                .execute("DELETE FROM allow WHERE host = ?1", [&host])?;
            eprintln!("removed {n}");
        }
        Cmd::List => {
            let mut out = Out::new();
            for r in ctx
                .store
                .rows("SELECT host, reason FROM allow ORDER BY host")?
            {
                out.row(&[&r[0], &r[1]]);
            }
        }
    }
    Ok(())
}
