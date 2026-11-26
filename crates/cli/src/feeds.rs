use crate::ctx::{Ctx, Out, stdin_names, stdin_rows};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use std::time::{Duration, Instant};
use stella_core::store::Row;
use stella_net::client::{self, Options};
use stella_sources::{adtech, code, extension, httparchive, nrd, scripts, sdk, vendors};
use tokio::task::JoinSet;

const PREBID_CAP: u64 = 400 * 1024 * 1024;
const GVL_CAP: usize = 64 * 1024 * 1024;
const DISCLOSURE_CAP: usize = 4 * 1024 * 1024;
const SCRIPT_CAP: usize = 6 * 1024 * 1024;
const REPORT_CAP: usize = 20 * 1024 * 1024;
const PASSIVE_CAP: usize = 64 * 1024 * 1024;
const PASSIVE_TRIES: u64 = 3;

fn web(timeout: u64) -> Result<reqwest::Client> {
    client::build(&Options {
        timeout: Duration::from_secs(timeout),
        redirects: 3,
        insecure: true,
        http1_only: true,
    })
}

async fn each<T: Send + 'static, F, Fut>(
    items: Vec<String>,
    par: usize,
    f: F,
    mut sink: impl FnMut(String, T),
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = T> + Send + 'static,
{
    let mut set = JoinSet::new();
    let mut it = items.into_iter();
    loop {
        while set.len() < par.max(1) {
            let Some(item) = it.next() else { break };
            let fut = f(item.clone());
            set.spawn(async move { (item, fut.await) });
        }
        match set.join_next().await {
            Some(Ok((item, r))) => sink(item, r),
            Some(Err(_)) => {}
            None => break,
        }
    }
}

pub async fn adtech(ctx: &mut Ctx, par: usize, min_intermediary: usize) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("adstxt")?;
    let sites: Vec<String> = stdin_names()
        .into_iter()
        .filter(|s| !done.contains(s))
        .collect();
    let c = web(20)?;
    let w = ctx.store.writer()?;
    let mut systems: FxHashMap<String, usize> = FxHashMap::default();
    let (mut with_ads, mut with_app_ads, total) = (0usize, 0usize, sites.len());
    let cc = c.clone();
    each(
        sites,
        par,
        move |s| {
            let c = cc.clone();
            async move {
                (
                    adtech::well_known(&c, &s, "ads.txt").await,
                    adtech::well_known(&c, &s, "app-ads.txt").await,
                )
            }
        },
        |site, (web, app)| {
            for (body, count) in [(web, &mut with_ads), (app, &mut with_app_ads)] {
                let Some(b) = body else { continue };
                let list = adtech::parse_ads_txt(&String::from_utf8_lossy(&b));
                *count += usize::from(!list.is_empty());
                for d in list {
                    *systems.entry(d).or_default() += 1;
                }
            }
            w.send(Row::Done {
                kind: "adstxt".into(),
                key: site,
            });
        },
    )
    .await;
    let names: Vec<String> = systems.keys().cloned().collect();
    let mut sellers: FxHashSet<String> = FxHashSet::default();
    let mut inter: FxHashMap<String, usize> = FxHashMap::default();
    let cc = c.clone();
    each(
        names,
        par,
        move |s| {
            let c = cc.clone();
            async move { adtech::well_known(&c, &s, "sellers.json").await }
        },
        |sys, body| {
            if let Some(list) = body.as_deref().and_then(adtech::parse_sellers) {
                sellers.insert(sys);
                for d in list {
                    *inter.entry(d).or_default() += 1;
                }
            }
        },
    )
    .await;
    let known = ctx.known();
    let mut companies: FxHashMap<String, (String, usize)> = FxHashMap::default();
    for s in &sellers {
        companies.insert(
            ctx.psl.icann_regdom_or_self(s).to_string(),
            ("sellers.json".into(), systems[s]),
        );
    }
    for (d, n) in inter.iter().filter(|(_, n)| **n >= min_intermediary) {
        companies
            .entry(ctx.psl.icann_regdom_or_self(d).to_string())
            .or_insert(("intermediary".into(), *n));
    }
    let mut rows: Vec<_> = companies
        .into_iter()
        .filter(|(z, _)| !known.contains(z))
        .collect();
    rows.sort_unstable_by(|a, b| b.1.1.cmp(&a.1.1).then_with(|| a.0.cmp(&b.0)));
    let mut attested: FxHashSet<String> = FxHashSet::default();
    let cc = c.clone();
    each(
        rows.iter().map(|(z, _)| z.clone()).collect(),
        par,
        move |z| {
            let c = cc.clone();
            async move { adtech::well_known(&c, &z, adtech::ATTESTATIONS).await }
        },
        |zone, body| {
            if body.as_deref().is_some_and(adtech::is_attestation) {
                attested.insert(zone);
            }
        },
    )
    .await;
    let mut out = Out::new();
    for (zone, (kind, n)) in &rows {
        let mark = if attested.contains(zone) {
            "attested"
        } else {
            ""
        };
        out.row(&[zone, kind, &n.to_string(), mark]);
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "sites={total} ads.txt={with_ads} app-ads.txt={with_app_ads} ad-systems={} with-sellers.json={} zones={} attested={} secs={:.1}",
        systems.len(),
        sellers.len(),
        rows.len(),
        attested.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub async fn prebid(ctx: &mut Ctx) -> Result<()> {
    let c = client::build(&Options {
        timeout: Duration::from_secs(600),
        ..Options::default()
    })?;
    let mut found: Vec<(String, String)> = Vec::new();
    for (url, file) in [
        (adtech::PREBID_JS, "prebid-js.tar.gz"),
        (adtech::PREBID_SERVER, "prebid-server.tar.gz"),
    ] {
        let path = ctx.paths.cache().join(file);
        client::download(&c, url, &path, PREBID_CAP).await?;
        let p = path.clone();
        found.extend(
            tokio::task::spawn_blocking(move || {
                adtech::hosts_in_tarball(&p, adtech::prebid_member)
            })
            .await??,
        );
    }
    found.sort_unstable();
    found.dedup_by(|a, b| a.0 == b.0);
    let known = ctx.known();
    let mut out = Out::new();
    let mut n = 0usize;
    for (h, file) in found.iter().filter(|(h, _)| !known.contains(h)) {
        n += 1;
        out.row(&[h, file]);
    }
    eprintln!("hosts={} unlisted={n}", found.len());
    Ok(())
}

pub async fn cmp(ctx: &mut Ctx, par: usize) -> Result<()> {
    let started = Instant::now();
    let c = web(20)?;
    let gvl = client::fetch(&c, vendors::GVL, GVL_CAP).await?;
    let list = vendors::gvl_vendors(&gvl.body);
    let names: FxHashMap<String, String> = list
        .iter()
        .map(|v| (v.disclosure.clone(), v.name.clone()))
        .collect();
    let urls: Vec<String> = names.keys().cloned().collect();
    let mut hosts: FxHashMap<String, String> = FxHashMap::default();
    let cc = c.clone();
    each(
        urls,
        par,
        move |u| {
            let c = cc.clone();
            async move {
                client::fetch(&c, &u, DISCLOSURE_CAP)
                    .await
                    .ok()
                    .map(|p| p.body)
            }
        },
        |u, body| {
            if let Some(b) = body {
                for h in vendors::disclosure_hosts(&b) {
                    hosts.entry(h).or_insert_with(|| names[&u].clone());
                }
            }
        },
    )
    .await;
    let known = ctx.known();
    let mut rows: Vec<_> = hosts
        .into_iter()
        .filter(|(h, _)| !known.contains(h))
        .collect();
    rows.sort_unstable();
    let mut out = Out::new();
    for (h, vendor) in &rows {
        out.row(&[h, vendor]);
    }
    eprintln!(
        "vendors={} hosts-unlisted={} secs={:.1}",
        list.len(),
        rows.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub async fn scripts(ctx: &mut Ctx, par: usize) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("script")?;
    let urls: Vec<String> = ctx
        .store
        .all("SELECT DISTINCT url FROM request WHERE method = 'GET'")?
        .into_iter()
        .filter(|u| scripts::script_url(u) && !done.contains(u))
        .collect();
    let total = urls.len();
    let c = web(20)?;
    let w = ctx.store.writer()?;
    let mut links: FxHashMap<String, (scripts::Linked, String)> = FxHashMap::default();
    let mut seen: FxHashMap<String, (usize, String)> = FxHashMap::default();
    let cc = c.clone();
    each(
        urls,
        par,
        move |u| {
            let c = cc.clone();
            async move { client::fetch(&c, &u, SCRIPT_CAP).await.ok().map(|p| p.body) }
        },
        |u, body| {
            if let Some(b) = body {
                for (kind, l) in scripts::linked(&b, &u) {
                    links.entry(l).or_insert((kind, u.clone()));
                }
                for h in scripts::hosts_in_script(&b) {
                    let e = seen.entry(h).or_insert_with(|| (0, u.clone()));
                    e.0 += 1;
                }
            }
            w.send(Row::Done {
                kind: "script".into(),
                key: u,
            });
        },
    )
    .await;
    let linked_total = links.len();
    let mut via: FxHashMap<String, (&'static str, String)> = FxHashMap::default();
    let (inline, remote): (Vec<_>, Vec<_>) =
        links.into_iter().partition(|(l, _)| l.starts_with("data:"));
    let mut found_linked = |kind: scripts::Linked, from: &str, body: &[u8]| {
        let hosts = match kind {
            scripts::Linked::SourceMap => scripts::hosts_in_map(body),
            scripts::Linked::ServiceWorker => scripts::hosts_in_script(body),
        };
        for h in hosts {
            via.entry(h).or_insert((kind.source(), from.to_string()));
        }
    };
    for (l, (kind, from)) in &inline {
        if let Some(b) = scripts::inline_map(l) {
            found_linked(*kind, from, &b);
        }
    }
    let kinds: FxHashMap<String, (scripts::Linked, String)> = remote.into_iter().collect();
    let cc = c.clone();
    each(
        kinds.keys().cloned().collect(),
        par,
        move |u| {
            let c = cc.clone();
            async move {
                client::fetch(&c, &u, SCRIPT_CAP)
                    .await
                    .ok()
                    .filter(|p| p.status == 200)
                    .map(|p| p.body)
            }
        },
        |u, body| {
            if let (Some(b), Some((kind, from))) = (body, kinds.get(&u)) {
                found_linked(*kind, from, &b);
            }
        },
    )
    .await;
    let known = ctx.known();
    let mut linked_rows: Vec<_> = via
        .into_iter()
        .filter(|(h, _)| !known.contains(h) && !seen.contains_key(h))
        .collect();
    linked_rows.sort_unstable();
    let mut rows: Vec<_> = seen
        .into_iter()
        .filter(|(h, _)| !known.contains(h))
        .collect();
    rows.sort_unstable_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
    let mut out = Out::new();
    for (h, (n, example)) in &rows {
        out.row(&[h, &n.to_string(), example]);
        w.send(Row::Origin {
            host: h.clone(),
            source: "script".into(),
            detail: example.clone(),
        });
    }
    for (h, (source, from)) in &linked_rows {
        out.row(&[h, source, from]);
        w.send(Row::Origin {
            host: h.clone(),
            source: (*source).into(),
            detail: from.clone(),
        });
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "scripts={total} hosts-unlisted={} linked-files={linked_total} linked-hosts-unlisted={} secs={:.1}",
        rows.len(),
        linked_rows.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub async fn extract(ctx: &mut Ctx) -> Result<()> {
    let c = web(30)?;
    let known = ctx.known();
    let mut out = Out::new();
    for row in stdin_rows() {
        let Some(src) = row.first().map(|s| s.trim().to_string()) else {
            continue;
        };
        let body = if src.starts_with("http://") || src.starts_with("https://") {
            match client::fetch(&c, &src, REPORT_CAP).await {
                Ok(p) => p.body,
                Err(e) => {
                    eprintln!("{src}: {e}");
                    continue;
                }
            }
        } else {
            match std::fs::read(&src) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{src}: {e}");
                    continue;
                }
            }
        };
        let text = String::from_utf8_lossy(&body);
        let mut hosts: FxHashMap<String, bool> =
            scripts::hosts_in_report(&text, |h| ctx.psl.listed_tld(h))
                .into_iter()
                .collect();
        for h in scripts::hosts_in_script(&body) {
            hosts.entry(h).or_insert(false);
        }
        let mut hosts: Vec<(String, bool)> = hosts.into_iter().collect();
        hosts.sort_unstable();
        for (h, defanged) in &hosts {
            let form = if *defanged { "defanged" } else { "plain" };
            out.row(&[h, &src, form, &known.labels(known.mask(h))]);
        }
    }
    Ok(())
}

pub async fn passive(ctx: &mut Ctx, par: usize) -> Result<()> {
    passive_zones(ctx, stdin_names(), par).await
}

pub async fn passive_zones(ctx: &mut Ctx, input: Vec<String>, par: usize) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("passive")?;
    let zones: Vec<String> = input.into_iter().filter(|z| !done.contains(z)).collect();
    let total = zones.len();
    let c = web(60)?;
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    let (mut ok, mut names) = (0usize, 0usize);
    let cc = c.clone();
    each(
        zones,
        par,
        move |z| {
            let c = cc.clone();
            async move {
                for t in 0..PASSIVE_TRIES {
                    if t > 0 {
                        tokio::time::sleep(Duration::from_secs(5 * t)).await;
                    }
                    if let Ok(p) = client::fetch(
                        &c,
                        &format!("{}{z}", vendors::SUBDOMAIN_CENTER),
                        PASSIVE_CAP,
                    )
                    .await
                        && let Some(list) = vendors::passive_names(&p.body, &z)
                    {
                        return Some(list);
                    }
                }
                None
            }
        },
        |zone, list| {
            let Some(list) = list else {
                eprintln!("passive {zone}: no answer");
                return;
            };
            ok += 1;
            names += list.len();
            for n in list {
                out.row(&[&n, "passive", &zone]);
                w.send(Row::Origin {
                    host: n,
                    source: "passive".into(),
                    detail: zone.clone(),
                });
            }
            w.send(Row::Done {
                kind: "passive".into(),
                key: zone,
            });
        },
    )
    .await;
    drop(out);
    w.finish()?;
    eprintln!(
        "zones={total} ok={ok} names={names} secs={:.1}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn real_host(ctx: &Ctx, h: &str) -> bool {
    ctx.psl.listed_tld(h) && ctx.psl.regdom(h).is_some()
}

const EXTENSION_CAP: usize = 64 * 1024 * 1024;

async fn extension_file(c: &reqwest::Client, store: &extension::Store) -> Option<Vec<u8>> {
    let url = match store {
        extension::Store::Chrome(id) => extension::chrome_url(id),
        extension::Store::Firefox(slug) => {
            let api = client::fetch(c, &extension::firefox_api(slug), 1024 * 1024)
                .await
                .ok()?;
            extension::firefox_file(&api.body)?
        }
    };
    let p = client::fetch(c, &url, EXTENSION_CAP).await.ok()?;
    (p.status == 200 && !p.body.is_empty()).then_some(p.body)
}

pub async fn extensions(ctx: &mut Ctx, par: usize) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("extension")?;
    let keys: Vec<String> = stdin_rows()
        .into_iter()
        .filter_map(|r| r.first().and_then(|l| extension::Store::parse(l)))
        .map(|s| s.key())
        .filter(|k| !done.contains(k))
        .collect();
    let total = keys.len();
    let root = ctx.paths.cache().join("ext");
    let c = web(120)?;
    let w = ctx.store.writer()?;
    let mut by_host: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();
    let mut fetched = 0usize;
    let cc = c.clone();
    each(
        keys,
        par,
        move |k| {
            let c = cc.clone();
            async move {
                let store = extension::Store::parse(&k)?;
                extension_file(&c, &store)
                    .await
                    .map(|b| (store.file_name(), b))
            }
        },
        |key, got| {
            if let Some((name, body)) = got {
                fetched += 1;
                let dir = root.join(key.replace(':', "-"));
                if std::fs::create_dir_all(&dir).is_ok() {
                    let _ = std::fs::write(dir.join(name), &body);
                }
                for h in extension::hosts(&body).unwrap_or_default() {
                    by_host.entry(h).or_default().insert(key.clone());
                }
            }
            w.send(Row::Done {
                kind: "extension".into(),
                key,
            });
        },
    )
    .await;
    let known = ctx.known();
    let mut rows: Vec<(String, FxHashSet<String>)> = by_host
        .into_iter()
        .filter(|(h, _)| !known.contains(h) && real_host(ctx, h))
        .collect();
    rows.sort_unstable_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    let mut out = Out::new();
    for (h, exts) in &rows {
        let mut list: Vec<&String> = exts.iter().collect();
        list.sort_unstable();
        out.row(&[h, &exts.len().to_string(), list[0]]);
        for e in list {
            w.send(Row::Origin {
                host: h.clone(),
                source: "extension".into(),
                detail: e.clone(),
            });
        }
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "extensions={total} fetched={fetched} hosts-unlisted={} secs={:.1}",
        rows.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

const SDK_INDEX_CAP: usize = 16 * 1024 * 1024;

async fn sdk_hosts(
    c: &reqwest::Client,
    pkg: &sdk::Package,
    dir: std::path::PathBuf,
) -> Option<Vec<String>> {
    if let sdk::Package::File(p) = pkg {
        let p = p.clone();
        return tokio::task::spawn_blocking(move || sdk::hosts_in_file(&p))
            .await
            .ok()
            .flatten();
    }
    let urls = match pkg {
        sdk::Package::Github { .. } => vec![pkg.index_url()],
        _ => {
            let index = client::fetch(c, &pkg.index_url(), SDK_INDEX_CAP)
                .await
                .ok()?;
            if index.status != 200 {
                return None;
            }
            let urls = pkg.archive_urls(&index.body);
            if !matches!(pkg, sdk::Package::Pod(_)) {
                urls
            } else {
                let spec = client::fetch(c, urls.first()?, SDK_INDEX_CAP).await.ok()?;
                if spec.status != 200 {
                    return None;
                }
                sdk::pod_archive_urls(&spec.body)
            }
        }
    };
    for url in urls {
        let Ok(p) = client::fetch(c, &url, sdk::ARCHIVE_CAP).await else {
            continue;
        };
        if p.status != 200 || p.body.is_empty() {
            continue;
        }
        if std::fs::create_dir_all(&dir).is_ok() {
            let _ = std::fs::write(dir.join("archive"), &p.body);
        }
        return tokio::task::spawn_blocking(move || sdk::hosts_in_archive(&p.body))
            .await
            .ok()
            .flatten();
    }
    None
}

pub async fn sdks(ctx: &mut Ctx, par: usize) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("sdk")?;
    let keys: Vec<String> = stdin_rows()
        .into_iter()
        .filter_map(|r| r.first().and_then(|l| sdk::Package::parse(l)))
        .map(|p| p.key())
        .filter(|k| !done.contains(k))
        .collect();
    let total = keys.len();
    let root = ctx.paths.cache().join("sdk");
    let c = web(300)?;
    let w = ctx.store.writer()?;
    let mut by_host: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();
    let mut scanned = 0usize;
    let cc = c.clone();
    each(
        keys,
        par,
        move |k| {
            let c = cc.clone();
            let dir = root.join(k.replace([':', '/', '@'], "-"));
            async move {
                let pkg = sdk::Package::parse(&k)?;
                sdk_hosts(&c, &pkg, dir).await
            }
        },
        |key, got| {
            if let Some(hosts) = got {
                scanned += 1;
                for h in hosts {
                    by_host.entry(h).or_default().insert(key.clone());
                }
            }
            w.send(Row::Done {
                kind: "sdk".into(),
                key,
            });
        },
    )
    .await;
    let known = ctx.known();
    let mut rows: Vec<(String, FxHashSet<String>)> = by_host
        .into_iter()
        .filter(|(h, _)| !known.contains(h) && real_host(ctx, h))
        .collect();
    rows.sort_unstable_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    let mut out = Out::new();
    for (h, pkgs) in &rows {
        let mut list: Vec<&String> = pkgs.iter().collect();
        list.sort_unstable();
        out.row(&[h, &pkgs.len().to_string(), list[0]]);
        for p in list {
            w.send(Row::Origin {
                host: h.clone(),
                source: "sdk".into(),
                detail: p.clone(),
            });
        }
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "packages={total} scanned={scanned} hosts-unlisted={} secs={:.1}",
        rows.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

const CODE_FILE_CAP: usize = 2 * 1024 * 1024;
const SEARCH_SPACING: Duration = Duration::from_secs(7);

pub async fn github_code(ctx: &mut Ctx, par: usize) -> Result<()> {
    let started = Instant::now();
    let done = ctx.store.done("github-code")?;
    let tok = crate::audit::token();
    if tok.is_none() {
        anyhow::bail!("code search needs a GitHub token from GH_TOKEN or gh auth");
    }
    let c = web(60)?;
    let w = ctx.store.writer()?;
    let mut files: FxHashMap<String, String> = FxHashMap::default();
    let queries: Vec<&str> = code::QUERIES
        .iter()
        .copied()
        .filter(|q| !done.contains(*q))
        .collect();
    for (i, q) in queries.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(SEARCH_SPACING).await;
        }
        match stella_sources::audit::github_get(&c, &code::search_url(q), tok.as_deref()).await {
            Ok(body) => {
                for u in code::raw_urls(&body) {
                    files.entry(u).or_insert_with(|| (*q).to_string());
                }
                w.send(Row::Done {
                    kind: "github-code".into(),
                    key: (*q).to_string(),
                });
            }
            Err(e) => eprintln!("github code {q}: {e}"),
        }
    }
    let total = files.len();
    let mut by_host: FxHashMap<String, String> = FxHashMap::default();
    let cc = c.clone();
    each(
        files.keys().cloned().collect(),
        par,
        move |u| {
            let c = cc.clone();
            async move {
                client::fetch(&c, &u, CODE_FILE_CAP)
                    .await
                    .ok()
                    .filter(|p| p.status == 200)
                    .map(|p| p.body)
            }
        },
        |u, body| {
            if let Some(b) = body {
                for h in scripts::hosts_in_script(&b) {
                    by_host.entry(h).or_insert_with(|| u.clone());
                }
            }
        },
    )
    .await;
    let known = ctx.known();
    let mut rows: Vec<(String, String)> = by_host
        .into_iter()
        .filter(|(h, _)| !known.contains(h) && real_host(ctx, h))
        .collect();
    rows.sort_unstable();
    let mut out = Out::new();
    for (h, u) in &rows {
        out.row(&[h, u]);
        w.send(Row::Origin {
            host: h.clone(),
            source: "github-code".into(),
            detail: u.clone(),
        });
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "queries={} files={total} hosts-unlisted={} secs={:.1}",
        queries.len(),
        rows.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

const SDK_INDEX: &str = "https://play.google.com/sdks";
const SDK_INDEX_WAIT: Duration = Duration::from_secs(8);
const SDK_LINKS_JS: &str = r#"JSON.stringify(Array.from(document.querySelectorAll("a[href]")).map(a => a.href).filter(h => h.includes("/sdks/")))"#;
const SDK_TEXT_JS: &str = "(document.body && document.body.innerText) || \"\"";

async fn links(b: &stella_crawl::cdp::Browser, url: &str, part: &str) -> Vec<String> {
    let Ok(v) = stella_crawl::crawl::render(b, url, SDK_INDEX_WAIT, SDK_LINKS_JS).await else {
        return Vec::new();
    };
    sdk::index_links(&v, SDK_INDEX, part)
}

pub async fn sdk_index(ctx: &mut Ctx, limit: usize) -> Result<()> {
    let started = Instant::now();
    let launch = stella_crawl::cdp::Launch {
        headful: false,
        user_agent: stella_crawl::cdp::DESKTOP_UA,
        display: None,
        width: 1280,
        height: 900,
        extra: Vec::new(),
    };
    let b =
        stella_crawl::cdp::Browser::launch(&launch, &ctx.paths.cache().join("sdk-index")).await?;
    let root = links(&b, SDK_INDEX, "/sdks/").await;
    let mut categories: Vec<String> = root
        .iter()
        .filter(|h| h.contains("/categories/"))
        .cloned()
        .collect();
    let mut details: FxHashSet<String> = root
        .iter()
        .filter(|h| h.contains("/details/"))
        .cloned()
        .collect();
    eprintln!(
        "sdk index: {} links, {} categories, {} sdks on the first page",
        root.len(),
        categories.len(),
        details.len()
    );
    categories.sort_unstable();
    for c in &categories {
        let all = links(&b, c, "/sdks/").await;
        let found: Vec<String> = all
            .iter()
            .filter(|h| h.contains("/details/"))
            .cloned()
            .collect();
        eprintln!("sdk index: {c} links={} sdks={}", all.len(), found.len());
        if found.is_empty() {
            for l in all.iter().take(5) {
                eprintln!("sdk index:   {l}");
            }
        }
        details.extend(found);
    }
    let mut coords: FxHashSet<String> = FxHashSet::default();
    let mut details: Vec<String> = details.into_iter().collect();
    details.sort_unstable();
    if limit > 0 {
        details.truncate(limit);
    }
    for d in &details {
        if let Ok(text) = stella_crawl::crawl::render(&b, d, SDK_INDEX_WAIT, SDK_TEXT_JS).await {
            coords.extend(sdk::maven_coords(&text));
        }
    }
    b.close().await;
    let mut coords: Vec<String> = coords.into_iter().collect();
    coords.sort_unstable();
    let mut out = Out::new();
    for c in &coords {
        out.row(&[c]);
    }
    drop(out);
    eprintln!(
        "sdk index: categories={} sdks={} maven={} secs={:.1}",
        categories.len(),
        details.len(),
        coords.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

const HTTPARCHIVE_CAP: usize = 64 * 1024 * 1024;

pub async fn http_archive(ctx: &mut Ctx) -> Result<()> {
    let started = Instant::now();
    let c = web(120)?;
    let latest = client::fetch(&c, httparchive::LATEST, 1024 * 1024).await?;
    let url = httparchive::tarball_url(&latest.body)
        .ok_or_else(|| anyhow::anyhow!("third-party-web: no tarball in the npm record"))?;
    let tgz = client::fetch(&c, &url, HTTPARCHIVE_CAP).await?;
    let json = httparchive::entities_json(&tgz.body)
        .ok_or_else(|| anyhow::anyhow!("third-party-web: no entities.json in {url}"))?;
    let all = httparchive::entries(&json);
    let known = ctx.known();
    let fresh: Vec<&httparchive::Entry> = all
        .iter()
        .filter(|e| !known.contains(&e.domain) && real_host(ctx, &e.domain))
        .collect();
    let w = ctx.store.writer()?;
    let mut out = Out::new();
    for e in &fresh {
        let shape = if e.zone { "zone" } else { "host" };
        out.row(&[&e.domain, shape, &e.category, &e.entity]);
        w.send(Row::Origin {
            host: e.domain.clone(),
            source: "httparchive".into(),
            detail: format!("{} {}", e.category, e.entity),
        });
    }
    drop(out);
    w.finish()?;
    eprintln!(
        "third-party-web: domains={} unlisted={} zones={} secs={:.1}",
        all.len(),
        fresh.len(),
        fresh.iter().filter(|e| e.zone).count(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

const NRD_CAP: usize = 64 * 1024 * 1024;

pub async fn nrd(ctx: &mut Ctx, date: Option<String>) -> Result<()> {
    let started = Instant::now();
    let date = date.unwrap_or_else(|| nrd::day_before(stella_core::now()));
    if !nrd::valid_date(&date) {
        anyhow::bail!("date must look like 2026-11-25, got {date}");
    }
    let c = web(120)?;
    let p = client::fetch(&c, &nrd::url(&date), NRD_CAP).await?;
    if p.status != 200 {
        anyhow::bail!("newly registered domains for {date}: http {}", p.status);
    }
    let list = nrd::domains(&p.body).ok_or_else(|| {
        anyhow::anyhow!("newly registered domains for {date}: no domain list in the archive")
    })?;
    let known = ctx.known();
    let mut out = Out::new();
    let mut fresh = 0usize;
    for d in list.iter().filter(|d| !known.contains(d)) {
        fresh += 1;
        out.row(&[d]);
    }
    drop(out);
    eprintln!(
        "newly registered {date}: domains={} unlisted={fresh} secs={:.1}",
        list.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
