use anyhow::Result;
use std::io::Write;
use std::time::Duration;
use stella_net::client::{self, Options};

#[derive(clap::Args)]
pub struct Args {
    url: String,
    #[arg(long, help = "Print the body to stdout")]
    body: bool,
    #[arg(long, help = "Accept certificates that do not verify")]
    insecure: bool,
    #[arg(long, help = "Use HTTP/1.1 only")]
    http1: bool,
}

const BODY_CAP: usize = 4 * 1024 * 1024;

pub async fn run(args: Args) -> Result<()> {
    let c = client::build(&Options {
        timeout: Duration::from_secs(12),
        redirects: 3,
        insecure: args.insecure,
        http1_only: args.http1,
    })?;
    let p = client::fetch(&c, &args.url, BODY_CAP).await?;
    let header = |name: &str| {
        p.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    eprintln!(
        "status={} url={} type={} server={} bytes={}",
        p.status,
        p.url,
        header("content-type"),
        header("server"),
        p.body.len()
    );
    if args.body {
        std::io::stdout().write_all(&p.body)?;
    }
    Ok(())
}
