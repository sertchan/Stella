mod allow;
mod apk;
mod audit;
mod breakage;
mod campaign;
mod clusters;
mod cname;
mod crawl;
mod ctx;
mod feeds;
mod fuse;
mod geo;
mod get;
mod hunt;
mod known;
mod mates;
mod pipeline;
mod pivot;
mod probe;
mod recheck;
mod records;
mod resolve;
mod review;
mod source;
mod stats;
mod sweep;
mod twins;
mod zone;

#[cfg(test)]
mod e2e;

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
    #[arg(long, global = true, help = "Print progress lines as JSON")]
    progress_json: bool,
    #[arg(
        long,
        global = true,
        help = "Read names or rows from this file instead of stdin"
    )]
    input: Option<std::path::PathBuf>,
    #[arg(
        long = "endpoint",
        global = true,
        value_name = "HOST=URL",
        help = "Send requests for HOST to URL instead, for a mirror or a local test server, repeatable"
    )]
    endpoints: Vec<String>,
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
    #[command(about = "Probe old picks again and mark the ones that no longer answer as STALE")]
    Recheck(recheck::Args),
    #[command(
        about = "IPv6 addresses and HTTPS targets of hosts, and NS, SOA and TXT verification records of their zones"
    )]
    Records(records::Args),
    #[command(
        about = "Zones that share a private name server, SOA mailbox or TXT token with a pick zone"
    )]
    Mates(mates::Args),
    #[command(
        about = "Raise REVIEW hits with two independent signal kinds to PICK and list unhit hosts that have two"
    )]
    Fuse(fuse::Args),
    #[command(
        about = "Certificate names from TLS handshakes without SNI to every address of /24 blocks dense with picks"
    )]
    Sweep(sweep::Args),
    #[command(
        about = "Probe the addresses that EU, US and Asia client subnets get for each host when they differ from ours"
    )]
    Geo(geo::Args),
    #[command(about = "Address neighbours, certificate names and zones of the picks")]
    Pivot(pivot::Args),
    #[command(about = "Filter, resolve, cap, probe and pivot the names on stdin in one pass")]
    Hunt(hunt::Args),
    #[command(about = "Hosts that must never be picked, with the reason")]
    Allow(allow::Args),
    #[command(
        about = "Lower hits named in HaGeZi allow or deny issues or excepted by other lists, after syncing them"
    )]
    Audit(audit::Args),
    #[command(
        about = "Load pages with and without a host blocked by DNS and report visible breakage"
    )]
    Breakage(breakage::Args),
    #[command(
        about = "Run one full discovery round: sync, expand new picks, hunt, twins, vendor CNAMEs, recheck and audit"
    )]
    Campaign(campaign::Args),
    #[command(about = "Names, resolutions, probes and hits per source")]
    Stats(stats::Args),
    #[command(about = "Group probed hosts that answer the same way and show the uncovered ones")]
    Clusters(clusters::Args),
    #[command(about = "Keep candidates that answer exactly like their listed seed or sibling")]
    Twins(twins::Args),
    #[command(about = "List hits with their evidence")]
    Review(review::ReviewArgs),
    #[command(about = "Print picked hosts that no reference list covers")]
    Export(review::ExportArgs),
    #[command(
        about = "Write every list format with metadata and counts for the picks no reference list covers"
    )]
    Publish(review::PublishArgs),
}

fn main() -> Result<()> {
    run(Cli::parse())
}

fn run(cli: Cli) -> Result<()> {
    for e in &cli.endpoints {
        let (host, url) = e
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--endpoint {e}: expected HOST=URL"))?;
        stella_net::client::redirect(host, url);
    }
    stella_core::progress::set_json(cli.progress_json);
    let mut paths = Paths::from_env();
    if let Some(s) = cli.state {
        paths.state = s;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let mut ctx = ctx::Ctx::open(paths)?;
        ctx.input = cli.input;
        match cli.cmd {
            Cmd::Known(a) => known::run(&mut ctx, a).await,
            Cmd::Get(a) => get::run(a).await,
            Cmd::Source(a) => source::run(&mut ctx, a).await,
            Cmd::Resolve(a) => resolve::run(&mut ctx, a).await,
            Cmd::Zone(a) => zone::run(&mut ctx, a).await,
            Cmd::Probe(a) => probe::run(&mut ctx, a).await,
            Cmd::Apk(a) => apk::run(&mut ctx, a).await,
            Cmd::Crawl(a) => crawl::crawl(&mut ctx, a).await,
            Cmd::Score(a) => crawl::score(&mut ctx, &a),
            Cmd::Recheck(a) => recheck::run(&mut ctx, a).await,
            Cmd::Records(a) => records::run(&mut ctx, a).await,
            Cmd::Mates(a) => mates::run(&ctx, &a),
            Cmd::Fuse(a) => fuse::run(&ctx, &a),
            Cmd::Sweep(a) => sweep::run(&mut ctx, a).await,
            Cmd::Geo(a) => geo::run(&mut ctx, a).await,
            Cmd::Pivot(a) => pivot::run(&mut ctx, &a),
            Cmd::Hunt(a) => hunt::run(&mut ctx, a).await,
            Cmd::Allow(a) => allow::run(&mut ctx, a),
            Cmd::Audit(a) => audit::run(&mut ctx, a).await,
            Cmd::Breakage(a) => breakage::run(&mut ctx, a).await,
            Cmd::Campaign(a) => campaign::run(&mut ctx, a).await,
            Cmd::Stats(a) => stats::run(&ctx, &a),
            Cmd::Clusters(a) => clusters::run(&ctx, a),
            Cmd::Twins(a) => twins::run(&mut ctx, a).await,
            Cmd::Review(a) => review::review(&ctx, &a),
            Cmd::Export(a) => review::export(&ctx, &a),
            Cmd::Publish(a) => review::publish(&ctx, &a),
        }
    })
}
