use crate::context::{Context, Out};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use std::time::Instant;
use stella_apk::scan::Outcome;
use stella_apk::{context, fetch, filter, scan};
use stella_core::store::Row;
use stella_net::client::{self, Options};
use tokio::task::JoinSet;

#[derive(clap::Args)]
pub struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    #[command(about = "Download the Android packages named on stdin (Aptoide, then APKPure)")]
    Fetch {
        #[arg(long, default_value_t = 3, help = "Downloads in parallel")]
        par: usize,
    },
    #[command(about = "Pull URL literals and decoded URLs out of every downloaded package")]
    Scan {
        #[arg(long, default_value_t = 2, help = "Packages scanned in parallel")]
        par: usize,
    },
    #[command(
        about = "Hosts behind telemetry or ad paths in app URLs that no reference list covers"
    )]
    Filter,
    #[command(about = "Decompile the apps behind filter hits and keep the code around each host")]
    Context {
        #[arg(long, default_value_t = 1, help = "Decompiles in parallel")]
        par: usize,
    },
    #[command(about = "Delete downloaded packages that need no more work")]
    Clean,
}

pub async fn run(ctx: &mut Context, args: Args) -> Result<()> {
    let started = Instant::now();
    let root = ctx.paths.apk();
    match args.cmd {
        Cmd::Fetch { par } => {
            let done = ctx.store.done("apk-fetch")?;
            let pkgs: Vec<String> = ctx
                .lines()
                .into_iter()
                .filter_map(|r| r.first().map(|p| p.trim().to_string()))
                .filter(|p| fetch::valid_package(p) && !done.contains(p))
                .collect();
            let c = client::build(&Options {
                timeout: std::time::Duration::from_secs(900),
                ..Options::default()
            })?;
            let w = ctx.store.writer()?;
            let mut out = Out::new();
            let (mut ok, mut failed) = (0usize, 0usize);
            let mut set = JoinSet::new();
            let mut it = pkgs.into_iter();
            loop {
                while set.len() < par.max(1) {
                    let Some(p) = it.next() else { break };
                    let (c, root) = (c.clone(), root.clone());
                    set.spawn(async move {
                        let r = fetch::fetch(&c, &root, &p).await;
                        (p, r)
                    });
                }
                let Some(Ok((p, r))) = set.join_next().await else {
                    break;
                };
                match r {
                    Ok((path, how)) => {
                        ok += 1;
                        let size = std::fs::metadata(&path).map_or(0, |m| m.len());
                        out.row(&[&p, "OK", how, &size.to_string()]);
                        w.send(Row::Done {
                            kind: "apk-fetch".into(),
                            key: p,
                        });
                    }
                    Err(e) => {
                        failed += 1;
                        out.row(&[&p, "FAIL", &e.to_string()]);
                    }
                }
            }
            drop(out);
            w.finish()?;
            eprintln!(
                "ok={ok} failed={failed} secs={:.2}",
                started.elapsed().as_secs_f64()
            );
        }
        Cmd::Scan { par } => {
            let done = ctx.store.done("apk-scan")?;
            let mut todo = Vec::new();
            for e in std::fs::read_dir(&root)?.flatten() {
                let pkg = e.file_name().to_string_lossy().to_string();
                let file = fetch::file(&root, &pkg);
                if !done.contains(&pkg) && file.exists() {
                    todo.push((pkg, file));
                }
            }
            let w = ctx.store.writer()?;
            let mut out = Out::new();
            let (mut scanned, mut games, mut urls) = (0usize, 0usize, 0usize);
            let mut set = JoinSet::new();
            let mut it = todo.into_iter();
            loop {
                while set.len() < par.max(1) {
                    let Some((pkg, file)) = it.next() else { break };
                    set.spawn_blocking(move || {
                        let r = scan::scan(&file);
                        (pkg, file, r)
                    });
                }
                let Some(Ok((pkg, file, r))) = set.join_next().await else {
                    break;
                };
                match r {
                    Ok(Outcome::Scanned(found)) => {
                        scanned += 1;
                        urls += found.len();
                        out.row(&[&pkg, "scanned", &found.len().to_string()]);
                        for f in found {
                            w.send(Row::ApkUrl {
                                pkg: pkg.clone(),
                                method: f.method,
                                url: f.url,
                                member: f.member,
                            });
                        }
                    }
                    Ok(Outcome::Game(engine)) => {
                        games += 1;
                        out.row(&[&pkg, "game", &engine]);
                        let _ = std::fs::remove_file(&file);
                    }
                    Err(e) => {
                        out.row(&[&pkg, "error", &e.to_string()]);
                        continue;
                    }
                }
                w.send(Row::Done {
                    kind: "apk-scan".into(),
                    key: pkg,
                });
            }
            drop(out);
            w.finish()?;
            eprintln!(
                "scanned={scanned} games={games} urls={urls} secs={:.2}",
                started.elapsed().as_secs_f64()
            );
        }
        Cmd::Filter => {
            let rows = ctx.store.rows("SELECT pkg, method, url FROM apk_url")?;
            let mut config: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();
            for r in rows.iter().filter(|r| r[1] == stella_apk::scan::AXML_HOST) {
                if let Some((host, _)) = filter::split(&r[2]) {
                    config.entry(host).or_default().insert(r[0].clone());
                }
            }
            let mut per_host: FxHashMap<String, Vec<(String, String, String)>> =
                FxHashMap::default();
            for r in &rows {
                if let Some((host, path)) = filter::endpoint(&r[2]) {
                    per_host
                        .entry(host)
                        .or_default()
                        .push((r[0].clone(), r[1].clone(), path));
                }
            }
            let known = ctx.known();
            let psl = &ctx.psl;
            per_host.retain(|h, _| {
                let sub = stella_core::name::subdomain(h, psl.regdom_or_self(h));
                !known.contains(h) && !stella_core::token::skipped(sub)
            });
            let w = ctx.store.writer()?;
            let mut config_hosts = 0usize;
            for (host, apps) in &config {
                if known.contains(host) {
                    continue;
                }
                config_hosts += 1;
                for a in apps {
                    w.send(Row::Origin {
                        host: host.clone(),
                        source: "apk-config".into(),
                        detail: a.clone(),
                    });
                }
            }
            eprintln!("apk filter: {config_hosts} hosts from network security config files");
            let mut out = Out::new();
            let mut hosts: Vec<_> = per_host.into_iter().collect();
            hosts.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            for (host, ev) in &hosts {
                let apps: FxHashSet<&str> = ev.iter().map(|(p, _, _)| p.as_str()).collect();
                let (pkg, method, path) = &ev[0];
                out.row(&[host, path, pkg, method, &apps.len().to_string()]);
                for a in &apps {
                    w.send(Row::Origin {
                        host: host.clone(),
                        source: "apk".into(),
                        detail: (*a).to_string(),
                    });
                }
                w.send(Row::Hit {
                    host: host.clone(),
                    product: "apk-endpoint".into(),
                    evidence: format!("{pkg} {method} {path}"),
                    verdict: stella_probe::rules::REVIEW.into(),
                });
            }
            drop(out);
            w.finish()?;
            eprintln!("urls={} hosts={}", rows.len(), hosts.len());
        }
        Cmd::Context { par } => {
            let done = ctx.store.done("apk-context")?;
            let rows = ctx.store.rows(
                "SELECT origin.detail, origin.host FROM origin JOIN hit USING(host) WHERE origin.source = 'apk' AND hit.product = 'apk-endpoint'",
            )?;
            let mut per_pkg: FxHashMap<String, Vec<String>> = FxHashMap::default();
            for r in rows {
                if !done.contains(&r[0]) {
                    per_pkg.entry(r[0].clone()).or_default().push(r[1].clone());
                }
            }
            let ctx_dir = root.join("ctx");
            std::fs::create_dir_all(&ctx_dir)?;
            let w = ctx.store.writer()?;
            let mut out = Out::new();
            let mut set = JoinSet::new();
            let mut it = per_pkg.into_iter();
            loop {
                while set.len() < par.max(1) {
                    let Some((pkg, hosts)) = it.next() else { break };
                    let root = root.clone();
                    set.spawn(async move {
                        let file = fetch::file(&root, &pkg);
                        if !file.exists() {
                            return (pkg, Err(anyhow::anyhow!("package file missing")));
                        }
                        let work = fetch::dir(&root, &pkg).join("work");
                        let r = match context::decompile(&file, &work).await {
                            Ok(tree) => {
                                let hs = hosts.clone();
                                let snippets = tokio::task::spawn_blocking(move || {
                                    context::snippets(&tree, &hs)
                                })
                                .await;
                                let _ = tokio::fs::remove_dir_all(&work).await;
                                snippets.map_err(anyhow::Error::from)
                            }
                            Err(e) => Err(e),
                        };
                        (pkg, r)
                    });
                }
                let Some(Ok((pkg, r))) = set.join_next().await else {
                    break;
                };
                match r {
                    Ok(snippets) => {
                        for (host, text) in snippets {
                            let lines = text.lines().count();
                            if lines > 0 {
                                std::fs::write(
                                    ctx_dir.join(format!("{host}.ctx")),
                                    format!("{pkg}\n{text}\n"),
                                )?;
                            }
                            out.row(&[&pkg, &host, &lines.to_string()]);
                        }
                        w.send(Row::Done {
                            kind: "apk-context".into(),
                            key: pkg,
                        });
                    }
                    Err(e) => out.row(&[&pkg, "error", &e.to_string()]),
                }
            }
            drop(out);
            w.finish()?;
            eprintln!(
                "context in {} secs={:.2}",
                ctx_dir.display(),
                started.elapsed().as_secs_f64()
            );
        }
        Cmd::Clean => {
            let scanned = ctx.store.done("apk-scan")?;
            let contexted = ctx.store.done("apk-context")?;
            let pending: FxHashSet<String> = ctx
                .store
                .all("SELECT DISTINCT origin.detail FROM origin JOIN hit USING(host) WHERE origin.source = 'apk' AND hit.product = 'apk-endpoint'")?
                .into_iter()
                .filter(|p| !contexted.contains(p))
                .collect();
            let mut freed = 0u64;
            for pkg in scanned.iter().filter(|p| !pending.contains(*p)) {
                let file = fetch::file(&root, pkg);
                if let Ok(m) = std::fs::metadata(&file) {
                    freed += m.len();
                    std::fs::remove_file(&file)?;
                }
            }
            eprintln!("freed={} MB", freed / (1024 * 1024));
        }
    }
    Ok(())
}
