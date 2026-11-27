use crate::ctx::{Ctx, Out};
use anyhow::Result;
use std::time::{Duration, Instant};
use stella_core::store::Row;
use stella_crawl::crawl::{self, Options};
use stella_crawl::score::Scorer;

#[derive(clap::Args)]
pub struct CrawlArgs {
    #[arg(long, default_value_t = 8, help = "Pages open at the same time")]
    par: usize,
    #[arg(long, default_value_t = 20, help = "Seconds each page stays open")]
    dwell: u64,
    #[arg(long, help = "Do not click cookie banner accept buttons")]
    no_consent: bool,
    #[arg(
        long,
        default_value_t = 10,
        help = "Seconds to wait after the consent clicks"
    )]
    after: u64,
    #[arg(
        long,
        help = "Run a normal windowed Chromium on an Xvfb display instead of headless mode"
    )]
    headful: bool,
    #[arg(
        long,
        default_value_t = 200,
        help = "Pages per browser process before a restart"
    )]
    restart_every: usize,
    #[arg(long, value_enum, default_value_t = ProfileArg::Android, help = "Browser profile: user agent and screen size")]
    profile: ProfileArg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ProfileArg {
    Android,
    Ios,
    Desktop,
}

impl ProfileArg {
    fn profile(self) -> stella_crawl::cdp::Profile {
        match self {
            Self::Android => stella_crawl::cdp::Profile::Android,
            Self::Ios => stella_crawl::cdp::Profile::Ios,
            Self::Desktop => stella_crawl::cdp::Profile::Desktop,
        }
    }
}

pub fn done_key(profile: stella_crawl::cdp::Profile, url: &str) -> String {
    match profile {
        stella_crawl::cdp::Profile::Android => url.to_string(),
        p => format!("{} {url}", p.name()),
    }
}

#[derive(clap::Args)]
pub struct ScoreArgs {
    #[arg(
        long,
        default_value_t = 3,
        help = "Score that turns an unlisted host into a review hit"
    )]
    review_at: u8,
}

fn url_of(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Some(raw.to_string());
    }
    stella_core::name::normalize(raw).map(|d| format!("https://{d}/"))
}

pub async fn crawl(ctx: &mut Ctx, args: CrawlArgs) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("crawl")?;
    let urls: Vec<String> = ctx
        .lines()
        .into_iter()
        .filter_map(|r| r.first().and_then(|u| url_of(u)))
        .filter(|u| !done.contains(&done_key(args.profile.profile(), u)))
        .collect();
    let total = urls.len();
    let profile = args.profile.profile();
    let (width, height) = profile.size();
    let opts = Options {
        par: args.par,
        dwell: Duration::from_secs(args.dwell),
        consent: !args.no_consent,
        after: Duration::from_secs(args.after),
        headful: args.headful,
        restart_every: args.restart_every,
        width,
        height,
        profile,
    };
    let work = ctx.paths.cache().join("crawl");
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let runner = tokio::spawn(async move { crawl::run(urls, opts, &work, tx).await });
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    let mut progress = stella_core::progress::Progress::new("crawl", total);
    let (mut pages, mut requests, mut errors) = (0usize, 0usize, 0usize);
    while let Some(p) = rx.recv().await {
        pages += 1;
        progress.tick(pages, args.par.min(total.saturating_sub(pages)), None);
        requests += p.requests.len();
        let site = stella_core::name::host_of_url(&p.url)
            .unwrap_or("")
            .to_ascii_lowercase();
        out.row(&[
            &p.url,
            &p.requests.len().to_string(),
            &p.consent,
            p.error.as_deref().unwrap_or(""),
        ]);
        if p.error.is_some() && p.requests.is_empty() {
            errors += 1;
            continue;
        }
        for ((api, target, script), calls) in p.hooks {
            w.send(Row::Hook {
                site: site.clone(),
                api,
                target,
                script,
                calls: calls as i64,
            });
        }
        for (method, url) in p.requests {
            w.send(Row::Request {
                site: site.clone(),
                method,
                url,
            });
        }
        w.send(Row::Done {
            kind: "crawl".into(),
            key: done_key(profile, &p.url),
        });
    }
    runner.await??;
    drop(out);
    w.finish()?;
    eprintln!(
        "urls={total} pages={pages} requests={requests} errors={errors} secs={:.1}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub fn score(ctx: &mut Ctx, args: ScoreArgs) -> Result<()> {
    let mut scorer = Scorer::default();
    {
        let mut stmt = ctx
            .store
            .conn
            .prepare("SELECT site, method, url FROM request")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let (site, method, url): (String, String, String) = (r.get(0)?, r.get(1)?, r.get(2)?);
            scorer.add(&site, &method, &url);
        }
    }
    let scores = scorer.finish();
    let known = ctx.known();
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    let mut review = 0usize;
    let mut by_level = [(0usize, 0usize); 5];
    for s in &scores {
        let labels = known.labels(known.mask(&s.host));
        let level = &mut by_level[usize::from(s.score.min(4))];
        if labels.is_empty() {
            level.1 += 1;
        } else {
            level.0 += 1;
        }
        w.send(Row::Score {
            host: s.host.clone(),
            sites: s.sites as i64,
            requests: s.requests as i64,
            post: s.post,
            id: s.id,
            path: s.path,
            score: i64::from(s.score),
            known: labels.clone(),
        });
        if !labels.is_empty() || s.score < 2 {
            continue;
        }
        out.row(&[
            &s.host,
            &s.score.to_string(),
            &s.sites.to_string(),
            &s.requests.to_string(),
            &format!("{:.2}", s.post),
            &format!("{:.2}", s.id),
            &format!("{:.2}", s.path),
        ]);
        let rd = ctx.psl.regdom_or_self(&s.host);
        let main = s.host == rd || s.host.strip_prefix("www.") == Some(rd);
        if s.score >= args.review_at && !main {
            review += 1;
            w.send(Row::Hit {
                host: s.host.clone(),
                product: "behaviour".into(),
                evidence: format!(
                    "sites={} post={:.2} id={:.2} path={:.2}",
                    s.sites, s.post, s.id, s.path
                ),
                verdict: stella_probe::rules::REVIEW.into(),
            });
        }
    }
    drop(out);
    w.finish()?;
    for (score, (known, free)) in by_level.iter().enumerate() {
        let n = known + free;
        if n > 0 {
            eprintln!(
                "score={score} hosts={n} known={known} share={:.0}%",
                *known as f64 * 100.0 / n as f64
            );
        }
    }
    eprintln!("hosts={} review={review}", scores.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stella_crawl::cdp::Profile;

    #[test]
    fn keys_other_profiles_apart() {
        assert_eq!(done_key(Profile::Android, "https://a.io/"), "https://a.io/");
        assert_eq!(done_key(Profile::Ios, "https://a.io/"), "ios https://a.io/");
        assert_eq!(Profile::Ios.size(), (390, 844));
        assert!(Profile::Desktop.user_agent().contains("Windows NT"));
    }
}
