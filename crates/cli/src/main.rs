mod allow;
mod apk;
mod crawl;
mod ctx;
mod get;
mod hunt;
mod known;
mod pipeline;
mod pivot;
mod probe;
mod resolve;
mod review;
mod source;
mod zone;

use anyhow::Result;
use clap::{Parser, Subcommand};
use stella_core::config::Paths;

#[derive(Parser)]
#[command(
    name = "stella",
    version,
    about = "Active discovery of ad, tracker and telemetry hosts"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "State directory with the database, lists and downloads"
    )]
    state: Option<std::path::PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = "Reference lists and the public suffix list")]
    Known(known::Args),
    #[command(about = "Fetch one URL through Stella's resolver and print status, type and size")]
    Get(get::Args),
    #[command(about = "Name sources")]
    Source(source::Args),
    #[command(about = "Resolve names with CNAME chains, wildcard check and reference labels")]
    Resolve(resolve::Args),
    #[command(about = "Find zone transfers and NSEC walks for zones on their own name servers")]
    Zone(zone::Args),
    #[command(about = "Run the fingerprint battery on hosts")]
    Probe(probe::Args),
    #[command(about = "Android app download, URL scan, path filter and code context")]
    Apk(apk::Args),
    #[command(about = "Load pages in Chromium and record every request")]
    Crawl(crawl::CrawlArgs),
    #[command(about = "Score request hosts by prevalence, POST share, id keys and collector paths")]
    Score(crawl::ScoreArgs),
    #[command(about = "Address neighbours, certificate names and zones of the picks")]
    Pivot(pivot::Args),
    #[command(about = "Filter, resolve, cap, probe and pivot the names on stdin in one pass")]
    Hunt(hunt::Args),
    #[command(about = "Hosts that must never be picked, with the reason")]
    Allow(allow::Args),
    #[command(about = "List hits with their evidence")]
    Review(review::ReviewArgs),
    #[command(about = "Print picked hosts that no reference list covers")]
    Export(review::ExportArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut paths = Paths::from_env();
    if let Some(s) = cli.state {
        paths.state = s;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let mut ctx = ctx::Ctx::open(paths)?;
        match cli.cmd {
            Cmd::Known(a) => known::run(&mut ctx, a).await,
            Cmd::Get(a) => get::run(a).await,
            Cmd::Source(a) => source::run(&mut ctx, a).await,
            Cmd::Resolve(a) => resolve::run(&mut ctx, a).await,
            Cmd::Zone(a) => zone::run(&mut ctx, a).await,
            Cmd::Probe(a) => probe::run(&mut ctx, a).await,
            Cmd::Apk(a) => apk::run(&mut ctx, a).await,
            Cmd::Crawl(a) => crawl::crawl(&mut ctx, a).await,
            Cmd::Score(a) => crawl::score(&mut ctx, a),
            Cmd::Pivot(a) => pivot::run(&mut ctx, a),
            Cmd::Hunt(a) => hunt::run(&mut ctx, a).await,
            Cmd::Allow(a) => allow::run(&mut ctx, a),
            Cmd::Review(a) => review::review(&ctx, a),
            Cmd::Export(a) => review::export(&ctx, a),
        }
    })
}
