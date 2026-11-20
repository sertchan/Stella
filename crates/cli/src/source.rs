use crate::ctx::{Ctx, Out, stdin_names};
use anyhow::Result;
use std::time::Instant;
use stella_core::store::Row;
use stella_net::client::{self, Options};
use stella_sources::{container, ct, labels, site, toplist};
use tokio::task::JoinSet;

#[derive(clap::Args)]
pub struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    #[command(about = "Print a top site list (umbrella or tranco), downloaded at most once a day")]
    Toplist {
        list: String,
        #[arg(long, default_value_t = 1_000_000, help = "Highest rank to print")]
        top: usize,
    },
    #[command(about = "Names under each zone on stdin from certificate transparency (crt.sh)")]
    Ct {
        #[arg(long, default_value_t = 4, help = "Parallel crt.sh sessions")]
        par: usize,
        #[arg(
            long,
            help = "Treat each input as a subzone of a zone too big for one query"
        )]
        subzone: bool,
    },
    #[command(
        about = "Tag ids, server container hints and security header hosts from each site's homepage"
    )]
    Site {
        #[arg(long, default_value_t = 200, help = "Sites fetched in parallel")]
        par: usize,
    },
    #[command(about = "Hosts named in every GTM and GA4 container found by the site source")]
    Container {
        #[arg(long, default_value_t = 24, help = "Containers fetched in parallel")]
        par: usize,
    },
    #[command(about = "Labels shared by picks in several zones, combined with top sites")]
    Labels {
        #[arg(long, default_value_t = 20_000, help = "Top sites to combine with")]
        top: usize,
        #[arg(
            long,
            default_value_t = 2,
            help = "Zones a label needs among the picks"
        )]
        min: usize,
        #[arg(long, default_value = "tranco", help = "Top site list")]
        list: String,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Use these labels instead of learning them, comma separated"
        )]
        labels: Vec<String>,
        #[arg(
            long,
            help = "Learn labels from the reference lists instead of the picks"
        )]
        from_known: bool,
        #[arg(long, help = "Read zones from stdin instead of the top site list")]
        stdin_zones: bool,
    },
    #[command(
        about = "Region, country, cloud region and shard number variants of hosts, as candidate and seed"
    )]
    Variants {
        #[arg(
            long,
            help = "Seed with every reference list host instead of the hosts on stdin"
        )]
        from_known: bool,
        #[arg(
            long,
            help = "Try label and brand on country domains instead (sgtm.brand.de to sgtm.brand.fr)"
        )]
        cctld: bool,
        #[arg(long, default_value_t = 40, help = "Highest shard number to try")]
        max_num: u32,
    },
    #[command(about = "Zones where reference lists include subdomains but not the zone itself")]
    PartialZones,
    #[command(
        about = "Tracking labels from the reference lists tried on partly listed zones, as candidate and seed"
    )]
    Siblings {
        #[arg(long, default_value_t = 60, help = "Most frequent labels to use")]
        top: usize,
    },
}

pub async fn run(ctx: &mut Ctx, args: Args) -> Result<()> {
    let started = Instant::now();
    match args.cmd {
        Cmd::Toplist { list, top } => {
            let c = client::build(&Options::default())?;
            let path = toplist::fetch(&c, &list, &ctx.paths.cache()).await?;
            let mut out = Out::new();
            let names = toplist::read(&path, top)?;
            for (rank, name) in &names {
                out.row(&[name, &rank.to_string()]);
            }
            eprintln!("{list}: {} names", names.len());
        }
        Cmd::Ct { par, subzone } => {
            let done = ctx.store.done("ct")?;
            let zones: Vec<String> = stdin_names()
                .into_iter()
                .filter(|z| !done.contains(z))
                .collect();
            let total = zones.len();
            let (tx, mut rx) = tokio::sync::mpsc::channel(256);
            let runner = tokio::spawn(ct::run(zones, par, subzone, tx));
            let w = ctx.store.writer()?;
            let mut out = Out::new();
            let (mut ok, mut failed, mut names) = (0usize, 0usize, 0usize);
            while let Some((zone, result)) = rx.recv().await {
                match result {
                    Ok(list) => {
                        ok += 1;
                        names += list.len();
                        for n in list {
                            out.row(&[&n, "ct", &zone]);
                            w.send(Row::Origin {
                                host: n,
                                source: "ct".into(),
                                detail: zone.clone(),
                            });
                        }
                        w.send(Row::Done {
                            kind: "ct".into(),
                            key: zone,
                        });
                    }
                    Err(e) => {
                        failed += 1;
                        eprintln!("ct {zone}: {e}");
                    }
                }
            }
            let _ = runner.await;
            drop(out);
            w.finish()?;
            eprintln!(
                "zones={total} ok={ok} failed={failed} names={names} secs={:.1}",
                started.elapsed().as_secs_f64()
            );
        }
        Cmd::Site { par } => {
            let done = ctx.store.done("site")?;
            let sites: Vec<String> = stdin_names()
                .into_iter()
                .filter(|s| !done.contains(s))
                .collect();
            let total = sites.len();
            let c = client::build(&Options {
                timeout: std::time::Duration::from_secs(12),
                redirects: 3,
                insecure: true,
                http1_only: true,
            })?;
            let w = ctx.store.writer()?;
            let mut out = Out::new();
            let (mut fetched, mut ids, mut hosts) = (0usize, 0usize, 0usize);
            let mut set = JoinSet::new();
            let mut it = sites.into_iter();
            loop {
                while set.len() < par.max(1) {
                    let Some(s) = it.next() else { break };
                    let c = c.clone();
                    set.spawn(async move {
                        let f = site::mine(&c, &s).await;
                        (s, f)
                    });
                }
                let Some(Ok((s, f))) = set.join_next().await else {
                    break;
                };
                if let Some(f) = f {
                    fetched += 1;
                    for id in f.ids {
                        ids += 1;
                        w.send(Row::Tag {
                            site: s.clone(),
                            id,
                        });
                    }
                    for h in f.inline {
                        hosts += 1;
                        out.row(&[&h, "inline", &s]);
                        w.send(Row::Origin {
                            host: h,
                            source: "inline".into(),
                            detail: s.clone(),
                        });
                    }
                    for (header, h) in f.headers {
                        hosts += 1;
                        out.row(&[&h, header, &s]);
                        w.send(Row::Origin {
                            host: h,
                            source: header.into(),
                            detail: s.clone(),
                        });
                    }
                }
                w.send(Row::Done {
                    kind: "site".into(),
                    key: s,
                });
            }
            drop(out);
            w.finish()?;
            eprintln!(
                "sites={total} fetched={fetched} ids={ids} hosts={hosts} secs={:.1}",
                started.elapsed().as_secs_f64()
            );
        }
        Cmd::Container { par } => {
            let done = ctx.store.done("container")?;
            let mut todo: Vec<String> = ctx
                .store
                .all("SELECT DISTINCT id FROM tag")?
                .into_iter()
                .filter(|id| !done.contains(id))
                .collect();
            todo.sort_unstable();
            let total = todo.len();
            let c = client::build(&Options {
                timeout: std::time::Duration::from_secs(20),
                ..Options::default()
            })?;
            let w = ctx.store.writer()?;
            let mut out = Out::new();
            let (mut fetched, mut sgtm, mut failed) = (0usize, 0usize, 0usize);
            let mut set = JoinSet::new();
            let mut it = todo.into_iter();
            loop {
                while set.len() < par.max(1) {
                    let Some(id) = it.next() else { break };
                    let c = c.clone();
                    set.spawn(async move {
                        let r = container::fetch(&c, &id).await;
                        (id, r)
                    });
                }
                let Some(Ok((id, r))) = set.join_next().await else {
                    break;
                };
                let r = match r {
                    container::Fetched::Found(r) => r,
                    container::Fetched::Missing => {
                        w.send(Row::Done {
                            kind: "container".into(),
                            key: id,
                        });
                        continue;
                    }
                    container::Fetched::Failed => {
                        failed += 1;
                        continue;
                    }
                };
                fetched += 1;
                for h in &r.sgtm {
                    sgtm += 1;
                    out.row(&[h, "sgtm", &id]);
                    w.send(Row::Origin {
                        host: h.clone(),
                        source: "sgtm".into(),
                        detail: id.clone(),
                    });
                }
                for h in r.hosts.into_iter().filter(|h| !r.sgtm.contains(h)) {
                    out.row(&[&h, "gtm", &id]);
                    w.send(Row::Origin {
                        host: h,
                        source: "gtm".into(),
                        detail: id.clone(),
                    });
                }
                w.send(Row::Done {
                    kind: "container".into(),
                    key: id,
                });
            }
            drop(out);
            w.finish()?;
            eprintln!(
                "ids={total} fetched={fetched} failed={failed} sgtm-hosts={sgtm} secs={:.1}",
                started.elapsed().as_secs_f64()
            );
        }
        Cmd::Labels {
            top,
            min,
            list,
            labels: fixed,
            from_known,
            stdin_zones,
        } => {
            let learned: Vec<(String, usize)> = if !fixed.is_empty() {
                fixed.into_iter().map(|l| (l, 0)).collect()
            } else if from_known {
                stella_sources::variants::learned_labels(ctx.known(), &ctx.psl, 60)
            } else {
                labels::learn(&ctx.store.conn, &ctx.psl, min)?
            };
            let mut sites: Vec<String> = if stdin_zones {
                stdin_names()
            } else {
                let c = client::build(&Options::default())?;
                let path = toplist::fetch(&c, &list, &ctx.paths.cache()).await?;
                toplist::read(&path, top)?
                    .into_iter()
                    .map(|(_, n)| ctx.psl.regdom_or_self(&n).to_string())
                    .collect()
            };
            sites.sort_unstable();
            sites.dedup();
            let known = ctx.known();
            let mut out = Out::new();
            let cands: Vec<String> = labels::candidates(&learned, &sites)
                .into_iter()
                .filter(|n| !known.contains(n))
                .collect();
            for n in &cands {
                out.row(&[n]);
            }
            eprintln!(
                "labels={} sites={} names={}",
                learned.len(),
                sites.len(),
                cands.len()
            );
        }
        Cmd::Variants {
            from_known,
            cctld,
            max_num,
        } => {
            let seeds: Vec<String> = if from_known {
                ctx.known().domains().map(str::to_string).collect()
            } else {
                stdin_names()
            };
            let known = ctx.known();
            let mut out = Out::new();
            let mut n = 0usize;
            for seed in &seeds {
                let mut emit = |c: String| {
                    if stella_core::name::normalize(&c).is_some() && !known.contains(&c) {
                        n += 1;
                        out.row(&[&c, seed]);
                    }
                };
                if cctld {
                    stella_sources::variants::cctld_twins(seed)
                        .into_iter()
                        .for_each(&mut emit);
                } else {
                    stella_sources::variants::variants(seed, max_num, &mut emit);
                }
            }
            eprintln!("seeds={} candidates={n}", seeds.len());
        }
        Cmd::PartialZones => {
            let zones = stella_sources::variants::partial_zones(ctx.known(), &ctx.psl);
            let mut out = Out::new();
            for z in &zones {
                out.row(&[&z.zone, &z.listed.len().to_string(), &z.listed[0]]);
            }
            eprintln!("zones={}", zones.len());
        }
        Cmd::Siblings { top } => {
            let known = ctx.known();
            let learned = stella_sources::variants::learned_labels(known, &ctx.psl, top);
            let zones = stella_sources::variants::partial_zones(known, &ctx.psl);
            let mut out = Out::new();
            let mut n = 0usize;
            for z in &zones {
                let Some(seed) = stella_sources::variants::sibling_seed(&z.listed) else {
                    continue;
                };
                for (l, _) in &learned {
                    let c = format!("{l}.{}", z.zone);
                    if !known.contains(&c) {
                        n += 1;
                        out.row(&[&c, seed]);
                    }
                }
            }
            eprintln!(
                "labels={} zones={} candidates={n}",
                learned.len(),
                zones.len()
            );
        }
    }
    Ok(())
}
