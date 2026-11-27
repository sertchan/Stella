use crate::context::{Context, Out};
use crate::pipeline::{self, DnsArgs};
use anyhow::{Result, bail};
use rustc_hash::FxHashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use stella_core::category::Category;
use stella_core::list::Format;

pub const NXDOMAIN: i64 = 3;

#[derive(clap::Args)]
pub struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    #[command(
        about = "Resolve every published entry with Stella's resolver and report the ones that no longer exist, so the next publish removes them with the reason"
    )]
    Check {
        #[arg(
            long,
            default_value = crate::commands::publish::LISTS_DIR,
            help = "Directory with one folder per list"
        )]
        dir: PathBuf,
        #[command(flatten)]
        dns: DnsArgs,
    },
}

pub fn entries(dir: &Path) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for c in Category::ALL {
        let path = dir.join(c.slug()).join(Format::Domains.file_name());
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        out.extend(
            text.lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| (l.trim().to_string(), c.slug())),
        );
    }
    out
}

pub fn state(rcode: i64, addrs: usize) -> &'static str {
    match rcode {
        NXDOMAIN => "dead",
        stella_dns::resolver::TIMEOUT => "no answer",
        0 if addrs > 0 => "alive",
        0 => "alive, no address",
        _ => "error",
    }
}

pub async fn run(ctx: &mut Context, args: Args) -> Result<()> {
    let Cmd::Check { dir, dns } = args.cmd;
    let started = Instant::now();
    let listed = entries(&dir);
    if listed.is_empty() {
        eprintln!("lists check: no entries under {}", dir.display());
        return Ok(());
    }
    let list_of: FxHashMap<&str, &str> = listed.iter().map(|(n, l)| (n.as_str(), *l)).collect();
    let w = ctx.store.writer()?;
    let cfg = dns.config();
    let names: Vec<String> = listed.iter().map(|(n, _)| n.clone()).collect();
    let first = pipeline::resolve(ctx, &w, &cfg, names, false).await?;
    let suspects: Vec<String> = first
        .iter()
        .filter(|n| n.res.rcode == NXDOMAIN)
        .map(|n| n.res.host.clone())
        .collect();
    let confirmed: FxHashMap<String, i64> = pipeline::resolve(ctx, &w, &cfg, suspects, false)
        .await?
        .into_iter()
        .map(|n| (n.res.host, n.res.rcode))
        .collect();
    w.finish()?;
    let mut counts: FxHashMap<&'static str, usize> = FxHashMap::default();
    let mut dead = Vec::new();
    let mut out = Out::new();
    for n in &first {
        let rcode = if n.res.rcode == NXDOMAIN {
            confirmed.get(&n.res.host).copied().unwrap_or(n.res.rcode)
        } else {
            n.res.rcode
        };
        let s = state(rcode, n.res.addrs.len());
        *counts.entry(s).or_default() += 1;
        let list = list_of.get(n.res.host.as_str()).copied().unwrap_or("-");
        out.row(&[&n.res.host, list, s, &n.res.chain.join(" > ")]);
        if s == "dead" {
            dead.push((n.res.host.clone(), list));
        }
    }
    drop(out);
    let mut summary: Vec<String> = counts.iter().map(|(k, v)| format!("{k}={v}")).collect();
    summary.sort_unstable();
    eprintln!(
        "lists check: entries={} {} secs={:.2}",
        first.len(),
        summary.join(" "),
        started.elapsed().as_secs_f64()
    );
    if dead.is_empty() {
        return Ok(());
    }
    for (host, list) in &dead {
        eprintln!("error[dead-entry] lists/{list}/domains.txt {host}");
        eprintln!("  found    NXDOMAIN from Stella's resolver, twice in a row");
        eprintln!("  expected a name that still exists");
        eprintln!(
            "  why      A dead name blocks nothing and costs every blocker memory and lookup time. HaGeZi removes dead names too."
        );
        eprintln!(
            "  fix      Run stella lists check and then stella publish with the release build from nix run .#stella. Publish removes the name and logs the reason in lists/changelog.tsv. Commit the lists folder with the lists scope."
        );
    }
    bail!("{} dead entr(ies) in the published lists", dead.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_entries_and_names_states() {
        let dir = std::env::temp_dir().join(format!("stella-lists-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tracker")).expect("dir");
        std::fs::write(
            dir.join("tracker/domains.txt"),
            "# Title: t\n#\na.io\nb.io\n",
        )
        .expect("write");
        assert_eq!(
            entries(&dir),
            [
                ("a.io".to_string(), "tracker"),
                ("b.io".to_string(), "tracker")
            ]
        );
        assert_eq!(state(NXDOMAIN, 0), "dead");
        assert_eq!(state(0, 1), "alive");
        assert_eq!(state(0, 0), "alive, no address");
        assert_eq!(state(stella_dns::resolver::TIMEOUT, 0), "no answer");
        assert_eq!(state(2, 0), "error");
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
