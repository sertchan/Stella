use crate::ctx::{Ctx, Out, stdin_names};
use anyhow::Result;
use stella_core::config::{KNOWN_LIST_URL, KNOWN_LISTS, PSL_URL};
use stella_net::client::{self, Options};

#[derive(clap::Args)]
pub struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    #[command(about = "Download the reference lists and the public suffix list")]
    Sync,
    #[command(about = "Print the reference lists that cover each host on stdin")]
    Check,
}

const LIST_CAP: u64 = 512 * 1024 * 1024;

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    match args.cmd {
        Cmd::Sync => sync(ctx).await?,
        Cmd::Check => {
            let names = stdin_names();
            let known = ctx.known();
            let mut out = Out::new();
            for n in names {
                let labels = known.labels(known.mask(&n));
                out.row(&[&n, &labels]);
            }
        }
    }
    Ok(())
}

pub async fn sync(ctx: &Ctx) -> Result<()> {
    let client = client::build(&Options::default())?;
    let n = client::download(&client, PSL_URL, &ctx.paths.psl(), LIST_CAP).await?;
    eprintln!("psl {n} bytes");
    for name in KNOWN_LISTS {
        let url = format!("{KNOWN_LIST_URL}{name}-onlydomains.txt");
        let path = ctx.paths.known().join(format!("{name}-onlydomains.txt"));
        match client::download(&client, &url, &path, LIST_CAP).await {
            Ok(n) => eprintln!("{name} {n} bytes"),
            Err(e) => eprintln!("{name}: {e}"),
        }
    }
    Ok(())
}
