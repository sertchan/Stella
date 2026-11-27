use crate::{Cli, run};
use clap::Parser;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;
use stella_core::store::{Row, Store};
use stella_testkit::dns::{self as fake, Answer, Dns, Zone, a, cname, ns, rr, soa};
use stella_testkit::http::{Http, Reply, Site};

struct State {
    dir: PathBuf,
}

impl State {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("stella-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("known")).expect("state dir");
        std::fs::write(
            dir.join("public_suffix_list.dat"),
            "// ===BEGIN ICANN DOMAINS===\ntest\nco.test\n",
        )
        .expect("psl");
        std::fs::write(
            dir.join("known/pro-onlydomains.txt"),
            "listed.test\ncdn-listed.test\n",
        )
        .expect("known");
        crate::context::quiet(true);
        Self { dir }
    }

    fn file(&self, name: &str, lines: &[&str]) -> String {
        let p = self.dir.join(name);
        std::fs::write(&p, lines.join("\n")).expect("input");
        p.display().to_string()
    }

    fn stella(&self, args: &[&str]) {
        let state = self.dir.display().to_string();
        let mut argv = vec!["stella", "--state", &state];
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(&argv).expect("arguments");
        run(cli).unwrap_or_else(|e| panic!("{argv:?}: {e:#}"));
    }

    fn store(&self) -> Store {
        Store::open(&self.dir.join("stella.db")).expect("store")
    }

    fn rows(&self, sql: &str) -> Vec<Vec<String>> {
        self.store().rows(sql).expect("rows")
    }

    fn count(&self, sql: &str) -> usize {
        self.rows(sql)[0][0].parse().expect("count")
    }

    fn seed(&self, rows: Vec<Row>) {
        let store = self.store();
        let w = store.writer().expect("writer");
        for r in rows {
            w.send(r);
        }
        w.finish().expect("finish");
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn s(v: &str) -> String {
    v.to_string()
}

fn hit(host: &str, product: &str, verdict: &str, evidence: &str) -> Row {
    Row::Hit {
        host: s(host),
        product: s(product),
        evidence: s(evidence),
        verdict: s(verdict),
    }
}

fn probe_row(host: &str, path: &str, addr: &str, status: i64, head: &str) -> Row {
    Row::Probe {
        host: s(host),
        path: s(path),
        addr: s(addr),
        status,
        ctype: s("text/plain"),
        server: s(""),
        cookies: s(""),
        length: head.len() as i64,
        head: s(head),
        digest: stella_core::digest::digest(head.as_bytes(), host),
    }
}

fn local_zone() -> Zone {
    Zone::new()
        .record(a("a.shop.test", [127, 0, 0, 2]))
        .answer(
            "b.shop.test",
            fake::A,
            Answer::records(vec![
                cname("b.shop.test", "x.cdn-listed.test"),
                a("x.cdn-listed.test", [127, 0, 0, 3]),
            ]),
        )
        .record(a("*.wild.test", [127, 0, 0, 4]))
        .record(ns("shop.test", "ns1.shop.test"))
        .record(a("ns1.shop.test", [127, 0, 0, 5]))
        .record(soa("shop.test", "ns1.shop.test", "hostmaster.shop.test"))
        .record(rr(
            "shop.test",
            fake::Data::Txt(vec!["google-site-verification=abc123".into()]),
        ))
        .record(rr(
            "a.shop.test",
            fake::Data::Aaaa("2a00:1450::1".parse().expect("v6")),
        ))
        .record(rr(
            "a.shop.test",
            fake::Data::Https(1, "svc.edge.test".into(), vec!["h2".into()]),
        ))
}

#[test]
fn dns_commands_use_the_given_resolver() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let dns = rt.block_on(Dns::start(local_zone())).expect("dns");
    let resolver = dns.addr.to_string();
    let st = State::new("dns");
    let names = st.file(
        "names.txt",
        &[
            "a.shop.test",
            "b.shop.test\tfrom ct",
            "w.wild.test",
            "a.shop.test",
            "",
        ],
    );
    st.stella(&[
        "--input",
        &names,
        "resolve",
        "--resolver",
        &resolver,
        "--wild",
    ]);
    assert_eq!(st.count("SELECT count(*) FROM resolution"), 3);
    let b = st.rows("SELECT chain, known FROM resolution WHERE host = 'b.shop.test'");
    assert_eq!(b[0][0], "x.cdn-listed.test");
    assert!(!b[0][1].is_empty());
    let w = st.rows("SELECT wild FROM resolution WHERE host = 'w.wild.test'");
    assert_eq!(w[0][0], "WILD");
    let hosts = st.file("hosts.txt", &["a.shop.test"]);
    st.stella(&["--input", &hosts, "records", "--resolver", &resolver]);
    assert!(st.count("SELECT count(*) FROM zonedns WHERE zone = 'shop.test'") >= 2);
    st.stella(&[
        "--input",
        &names,
        "hunt",
        "--resolver",
        &resolver,
        "--rounds",
        "2",
        "--again",
    ]);
    assert_eq!(st.count("SELECT count(*) FROM probe"), 0);
    let zones = st.file("zones.txt", &["shop.test"]);
    st.stella(&["--input", &zones, "zone", "--resolver", &resolver]);
    st.stella(&["--input", &hosts, "geo", "--resolver", &resolver]);
    st.seed(vec![hit("a.shop.test", "sgtm", "PICK", "healthy ok")]);
    st.stella(&["records", "--picks", "--no-zones", "--resolver", &resolver]);
    st.stella(&["recheck", "--resolver", &resolver, "--older-than-days", "0"]);
    assert!(!dns.asked().is_empty());
    drop(rt);
}

#[test]
fn probe_command_handles_pinned_and_resolved_rows() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let dns = rt.block_on(Dns::start(local_zone())).expect("dns");
    let resolver = dns.addr.to_string();
    let st = State::new("probe");
    let rows = st.file(
        "rows.txt",
        &["p.shop.test\t127.0.0.9", "a.shop.test", "bad name"],
    );
    st.stella(&[
        "--input",
        &rows,
        "probe",
        "--resolver",
        &resolver,
        "--timeout",
        "1",
        "--budget",
        "2",
        "--battery",
        "lite",
    ]);
    assert_eq!(st.count("SELECT count(*) FROM resolution"), 1);
    drop(rt);
}

#[test]
fn get_fetches_through_the_client() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let srv = rt
        .block_on(Http::plain(Site::new().route("/x", Reply::ok("hello"))))
        .expect("http");
    let st = State::new("get");
    st.stella(&["get", &srv.url("/x"), "--insecure", "--http1"]);
    assert_eq!(srv.seen()[0].path, "/x");
    drop(rt);
}

fn seeded(name: &str) -> State {
    let st = State::new(name);
    let mut rows = vec![
        hit("t1.shop.test", "sgtm", "PICK", "healthy ok, random 400"),
        hit("t2.shop.test", "sgtm", "PICK", "healthy ok, random 400"),
        hit("t3.shop.test", "sgtm", "PICK", "healthy ok, random 400"),
        hit("c.blog.test", "collector", "REVIEW", "/ empty 204"),
        hit("n.blog.test", "collector", "REVIEW", "/ empty 204"),
        hit("gone.shop.test", "pixel", "DROP", "image cdn"),
        Row::Allow {
            host: s("safe.shop.test"),
            reason: s("checkout"),
        },
    ];
    for (i, zone) in ["shop.test", "blog.test", "news.test", "mail.test"]
        .iter()
        .enumerate()
    {
        for j in 0..2 {
            let host = format!("e{j}.{zone}");
            let ip = format!("198.51.100.{}", i * 2 + j);
            rows.push(Row::Name {
                host: host.clone(),
                regdom: s(zone),
                known: s(""),
            });
            rows.push(Row::Origin {
                host: host.clone(),
                source: s(if i % 2 == 0 { "ct" } else { "site" }),
                detail: s(zone),
            });
            rows.push(Row::Resolution {
                host: host.clone(),
                rcode: 0,
                chain: s(""),
                addrs: ip.clone(),
                wild: s("REAL"),
                known: s(""),
            });
            rows.push(Row::Addr {
                addr: ip.clone(),
                host: host.clone(),
            });
            rows.push(probe_row(&host, "/", &ip, 204, ""));
            rows.push(probe_row(&host, "/healthy", &ip, 200, "ok"));
            rows.push(probe_row(&host, "?random", &ip, 400, ""));
            rows.push(probe_row(&host, "/i", &ip, 404, "nope"));
            rows.push(Row::TlsPrint {
                host: host.clone(),
                print: s("TLSv1_3|TLS13_AES_128_GCM_SHA256|http/1.1|2"),
            });
        }
    }
    for host in ["t1.shop.test", "c.blog.test"] {
        rows.push(Row::Addr {
            addr: s("203.0.113.7"),
            host: s(host),
        });
        rows.push(Row::Cert {
            host: s(host),
            san: s("san.blog.test"),
        });
    }
    rows.push(Row::Addr {
        addr: s("203.0.113.7"),
        host: s("n.blog.test"),
    });
    for (pkg, url) in [
        ("com.a", "https://c.blog.test/v1/track"),
        ("com.b", "https://c.blog.test/v1/track"),
    ] {
        rows.push(Row::ApkUrl {
            pkg: s(pkg),
            method: s("literal"),
            url: s(url),
            member: s("classes.dex"),
        });
    }
    for site in ["news.test", "mail.test", "shop.test", "blog.test"] {
        rows.push(Row::Request {
            site: s(site),
            method: s("POST"),
            url: s("https://beacon.metrics.test/collect?uid=1234567890abcdef"),
        });
        rows.push(Row::Hook {
            site: s(site),
            api: s("canvas"),
            target: s("toDataURL"),
            script: s("fp.blog.test"),
            calls: 3,
        });
    }
    for (zone, kind, value) in [
        ("shop.test", "ns", "ns1.private-dns.test"),
        ("blog.test", "ns", "ns1.private-dns.test"),
        ("news.test", "soa", "hostmaster.private-dns.test"),
        ("shop.test", "soa", "hostmaster.private-dns.test"),
    ] {
        rows.push(Row::ZoneDns {
            zone: s(zone),
            kind,
            value: s(value),
        });
    }
    st.seed(rows);
    st
}

#[test]
fn store_commands_read_and_update_the_database() {
    let st = seeded("store");
    st.stella(&["stats"]);
    st.stella(&["stats", "--runs"]);
    st.stella(&["review"]);
    st.stella(&["review", "--verdict", "DROP"]);
    let meta = st.dir.join("meta.tsv").display().to_string();
    st.stella(&["export", "--metadata", &meta]);
    assert!(
        std::fs::read_to_string(&meta)
            .expect("meta")
            .contains("t1.shop.test")
    );
    for f in ["hosts", "adblock", "rpz"] {
        st.stella(&["export", "--format", f, "--zones", "2", "--with-known"]);
    }
    st.stella(&["export", "--unfiled"]);
    let out = st.dir.join("pub").display().to_string();
    st.stella(&["publish", "--dir", &out]);
    for list in stella_core::category::Category::ALL {
        for format in stella_core::list::Format::ALL {
            let p = st
                .dir
                .join("pub")
                .join(list.slug())
                .join(format.file_name());
            let text = std::fs::read_to_string(&p).expect("published list");
            assert!(text.contains(list.title()), "{}", p.display());
        }
    }
    let counts = std::fs::read_to_string(st.dir.join("pub/counts.tsv")).expect("counts");
    assert!(
        counts.starts_with("list\tzones\thosts\tentries\nads\t"),
        "{counts}"
    );
    st.stella(&["export", "--category", "tracker", "--format", "rpz"]);
    st.stella(&["pivot"]);
    st.stella(&["pivot", "--with-review", "--max-ip", "2"]);
    st.stella(&["mates"]);
    st.stella(&["clusters"]);
    st.stella(&["clusters", "--all", "--flat", "--min-zones", "2"]);
    st.stella(&["clusters", "--loose", "--tls", "--min-zones", "2", "--all"]);
    let ctx = crate::context::Context::open(stella_core::config::Paths {
        state: st.dir.clone(),
    })
    .expect("ctx");
    let id = crate::commands::clusters::build(&ctx, false, false).expect("clusters")[0]
        .id
        .clone();
    drop(ctx);
    st.stella(&["clusters", "--show", &id, "--min-zones", "2", "--all"]);
    st.stella(&["score", "--review-at", "1"]);
    assert!(st.count("SELECT count(*) FROM score") >= 1);
    st.stella(&["fuse", "--dry-run"]);
    st.stella(&["fuse"]);
    assert!(
        st.count("SELECT count(*) FROM hit WHERE evidence LIKE '%fused:%'") >= 1,
        "{:?}",
        st.rows("SELECT host, product, verdict, evidence FROM hit")
    );
    st.stella(&[
        "allow",
        "add",
        "t2.shop.test",
        "--reason",
        "breaks checkout",
    ]);
    st.stella(&["allow", "list"]);
    assert_eq!(st.count("SELECT count(*) FROM allow"), 2);
    st.stella(&["allow", "remove", "t2.shop.test"]);
    assert_eq!(st.count("SELECT count(*) FROM allow"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn pipeline_probes_writes_rows_and_drops_covered_hosts() {
    let tls = Http::tls(
        Site::new()
            .route(
                "/healthy",
                Reply::ok("ok").header("Content-Type", "text/plain"),
            )
            .fallback(Reply::new(400)),
        &["t.shop.test", "alt.shop.test"],
    )
    .await
    .expect("tls");
    let dns = Dns::start(Zone::new().record(a("t.shop.test", [127, 0, 0, 1])).subnet(
        "t.shop.test",
        fake::A,
        stella_dns::ecs::REGIONS[0].1,
        Answer::records(vec![cname("t.shop.test", "edge.cdn-listed.test")]),
    ))
    .await
    .expect("dns");
    let st = State::new("pipeline");
    let mut ctx = crate::context::Context::open(stella_core::config::Paths {
        state: st.dir.clone(),
    })
    .expect("ctx");
    let w = ctx.store.writer().expect("writer");
    let cfg = stella_dns::transport::Config {
        servers: vec![dns.addr],
        ecs_server: dns.addr,
        timeout: Duration::from_millis(300),
        ..stella_dns::transport::Config::default()
    };
    let named = crate::pipeline::resolve(&mut ctx, &w, &cfg, vec![s("t.shop.test")], true)
        .await
        .expect("resolve");
    assert_eq!(named[0].res.addrs, [Ipv4Addr::LOCALHOST]);
    let mut prober = stella_probe::battery::Prober::new(stella_net::limiter::Limiter::new(8, 100));
    prober.tls_port = tls.addr.port();
    prober.timeout = Duration::from_secs(2);
    let b = crate::pipeline::battery_for(&ctx, "t.shop.test", "auto");
    let items = vec![(s("t.shop.test"), IpAddr::V4(Ipv4Addr::LOCALHOST), b)];
    let mut found = Vec::new();
    let stats = crate::pipeline::probe(&ctx, &w, &prober, items, 4, |p, h| {
        found.push(crate::pipeline::Found::new(p, h));
    })
    .await;
    assert_eq!((stats.total, stats.answered), (1, 1));
    assert!(!stats.line().is_empty());
    assert!(found.iter().any(|f| f.product == "sgtm"));
    let covered = crate::pipeline::drop_covered(&ctx, &w, &cfg, &mut found)
        .await
        .expect("covered");
    assert_eq!(covered, found.len());
    assert!(
        found[0]
            .evidence
            .contains("CNAME to included edge.cdn-listed.test")
    );
    w.finish().expect("finish");
    assert!(st.count("SELECT count(*) FROM probe WHERE host = 't.shop.test'") >= 4);
    assert_eq!(st.count("SELECT count(*) FROM tlsprint"), 1);
    assert_eq!(st.count("SELECT count(*) FROM cert"), 2);
    assert_eq!(
        st.rows("SELECT verdict FROM hit WHERE host = 't.shop.test'")[0][0],
        "DROP"
    );
}

#[test]
fn offline_sources_read_files_lists_and_local_scripts() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let site = Site::new()
        .route(
            "/app.js",
            Reply::ok(
                "fetch(\"https://collect.vendor.test/v1\");\n//# sourceMappingURL=app.js.map\n",
            )
            .header("Content-Type", "application/javascript"),
        )
        .route(
            "/app.js.map",
            Reply::ok("{\"sourcesContent\":[\"const u = 'https://map.vendor.test/e'\"]}"),
        );
    let srv = rt.block_on(Http::tls(site, &["localhost"])).expect("https");
    let st = State::new("sources");
    std::fs::write(
        st.dir.join("known/pro-onlydomains.txt"),
        "listed.test\na.shop.test\nb.shop.test\nmetrics.news.test\n",
    )
    .expect("known");
    let js = st.file(
        "bundle.js",
        &["var u = \"https://beacon.vendor.test/collect\";"],
    );
    let files = st.file("files.txt", &[&js]);
    st.stella(&["--input", &files, "source", "extract"]);
    let sdk = st.file("sdk.txt", &[&format!("file:{js}")]);
    st.stella(&["--input", &sdk, "source", "sdk"]);
    let hosts = st.file("hosts.txt", &["eu-west.collector.shop.test"]);
    st.stella(&["--input", &hosts, "source", "variants"]);
    st.stella(&["source", "partial-zones"]);
    st.stella(&["source", "siblings"]);
    st.seed(vec![Row::Request {
        site: s("shop.test"),
        method: s("GET"),
        url: format!("https://{}/app.js", srv.addr),
    }]);
    st.stella(&["source", "scripts", "--par", "2"]);
    let origins = st.rows("SELECT host, source FROM origin ORDER BY host, source");
    let has = |h: &str| origins.iter().any(|r| r[0] == h);
    assert!(has("beacon.vendor.test"), "{origins:?}");
    assert!(has("collect.vendor.test"), "{origins:?}");
    assert!(has("map.vendor.test"), "{origins:?}");
    assert!(srv.seen().iter().any(|s| s.path == "/app.js"));
    drop(rt);
}

#[test]
fn crawl_score_and_breakage_run_with_a_real_browser() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let page = "<html><head><title>Shop</title></head><body><h1>Shop</h1><script>fetch(\"/collect?uid=1234567890abcdef\", { method: \"POST\", body: \"x\" });</script></body></html>";
    let srv = rt
        .block_on(Http::plain(
            Site::new()
                .route("/", Reply::ok(page).header("Content-Type", "text/html"))
                .fallback(Reply::new(204)),
        ))
        .expect("http");
    let st = State::new("crawl");
    let urls = st.file("urls.txt", &[&srv.url("/")]);
    st.stella(&[
        "--input",
        &urls,
        "crawl",
        "--par",
        "1",
        "--dwell",
        "2",
        "--after",
        "0",
        "--no-consent",
    ]);
    let posts =
        st.count("SELECT count(*) FROM request WHERE method = 'POST' AND url LIKE '%/collect%'");
    assert!(
        posts >= 1,
        "{:?}",
        st.rows("SELECT method, url FROM request")
    );
    st.stella(&["--input", &urls, "crawl", "--par", "1"]);
    st.stella(&["score", "--review-at", "1"]);
    let hosts = st.file("hosts.txt", &["nothing.unseen.test"]);
    st.stella(&["--input", &hosts, "breakage", "--dwell", "1"]);
    st.stella(&["breakage", "--picks", "--dwell", "1"]);
    drop(rt);
}

fn apk_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in entries {
        w.start_file(*name, zip::write::SimpleFileOptions::default())
            .expect("zip entry");
        w.write_all(data).expect("zip data");
    }
    w.finish().expect("zip finish").into_inner()
}

#[test]
fn offline_campaign_and_local_tools_run() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let dns = rt.block_on(Dns::start(local_zone())).expect("dns");
    let resolver = dns.addr.to_string();
    let st = seeded("campaign");
    st.seed(vec![
        Row::Origin {
            host: s("a.shop.test"),
            source: s("ct"),
            detail: s("shop.test"),
        },
        Row::Origin {
            host: s("b.shop.test"),
            source: s("site"),
            detail: s("shop.test"),
        },
    ]);
    st.stella(&[
        "campaign",
        "--offline",
        "--resolver",
        &resolver,
        "--recheck-days",
        "0",
    ]);
    assert!(
        st.count("SELECT count(*) FROM run") >= 1,
        "{:?}",
        st.rows("SELECT * FROM run")
    );
    assert!(st.count("SELECT count(*) FROM resolution WHERE host = 'a.shop.test'") >= 1);
    st.stella(&["stats", "--runs", "--last", "3"]);
    let twins = st.file(
        "twins.txt",
        &["eu.collect.shop.test\tcollect.shop.test", "w.wild.test"],
    );
    st.stella(&["--input", &twins, "twins", "--resolver", &resolver]);
    st.stella(&["audit", "--no-sync"]);
    let hosts = st.file("known.txt", &["listed.test", "x.listed.test", "free.test"]);
    st.stella(&["--input", &hosts, "known", "check"]);
    let mut addrs = Vec::new();
    for (i, h) in ["t1.shop.test", "t2.shop.test", "t3.shop.test"]
        .iter()
        .enumerate()
    {
        addrs.push(Row::Addr {
            addr: format!("127.0.0.{}", i + 2),
            host: s(h),
        });
    }
    st.seed(addrs);
    st.stella(&[
        "sweep",
        "--min-picks",
        "1",
        "--min-share",
        "0",
        "--max-blocks",
        "1",
    ]);
    let pkg_dir = st.dir.join("apk/com.vendor.app");
    std::fs::create_dir_all(&pkg_dir).expect("apk dir");
    let inner = apk_with(&[(
        "classes.dex",
        b"\x00https://telemetry.vendor.test/v1/events?app=1\x00https://cdn.vendor.test/img/logo.png\x00",
    )]);
    std::fs::write(
        pkg_dir.join("com.vendor.app.pkg"),
        apk_with(&[("base.apk", &inner), ("manifest.json", b"{}")]),
    )
    .expect("apk file");
    st.stella(&["apk", "scan"]);
    assert!(
        st.count("SELECT count(*) FROM apk_url WHERE url LIKE '%telemetry.vendor.test%'") >= 1,
        "{:?}",
        st.rows("SELECT pkg, url FROM apk_url")
    );
    st.stella(&["apk", "filter"]);
    st.stella(&["apk", "clean"]);
    drop(rt);
}

#[test]
fn every_command_definition_is_valid() {
    use clap::CommandFactory;
    Cli::command().debug_assert();
}

fn tgz_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    for (name, body) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, name, *body).expect("tar entry");
    }
    tar.into_inner()
        .expect("tar finish")
        .finish()
        .expect("gzip finish")
}

const MIRRORED: &[&str] = &[
    "raw.githubusercontent.com",
    "publicsuffix.org",
    "api.github.com",
    "adguardteam.github.io",
    "filters.adtidy.org",
    "easylist.to",
    "api.subdomain.center",
    "vendor-list.consensu.org",
    "disclosures.vendor.test",
    "registry.npmjs.org",
    "www.whoisds.com",
    "codeload.github.com",
    "tranco-list.eu",
    "addons.mozilla.org",
    "shop.test",
    "www.shop.test",
    "adsys.test",
    "www.googletagmanager.com",
];

fn mirror() -> Site {
    let list = "listed.test\nx.tracker.listed.test\n";
    let gvl = r#"{"vendors":{"1":{"name":"Vendor","deviceStorageDisclosureUrl":"https://disclosures.vendor.test/d.json"}}}"#;
    let disclosure = r#"{"disclosures":[{"identifier":"uid","domains":["*.sync.vendor.test"]}],"domains":[{"domain":".pixel.vendor.test","use":"x"}]}"#;
    let entities = r#"[{"name":"Ad Co","category":"ad","domains":["*.adco.test","px.adco.test"]}]"#;
    let nrd_path = stella_sources::newly_registered::url("2026-11-20")
        .split_once("whoisds.com")
        .map(|(_, p)| p.to_string())
        .expect("nrd path");
    Site::new()
        .route(
            "/list/public_suffix_list.dat",
            Reply::ok("// ===BEGIN ICANN DOMAINS===\ntest\nco.test\n"),
        )
        .route("/repos/hagezi/dns-blocklists/issues", Reply::ok("[]"))
        .route(
            "/",
            Reply::ok("[\"a.shop.test\",\"b.shop.test\",\"x.other.test\"]")
                .header("Content-Type", "application/json"),
        )
        .route("/v3/vendor-list.json", Reply::ok(gvl))
        .route("/d.json", Reply::ok(disclosure))
        .route(
            "/third-party-web/latest",
            Reply::ok(r#"{"dist":{"tarball":"https://registry.npmjs.org/third-party-web/-/third-party-web-1.0.0.tgz"}}"#),
        )
        .route(
            "/third-party-web/-/third-party-web-1.0.0.tgz",
            Reply::new(200).body(tgz_with(&[("package/dist/entities.json", entities.as_bytes())])),
        )
        .route(
            "/vendor-sdk/latest",
            Reply::ok(r#"{"dist":{"tarball":"https://registry.npmjs.org/vendor-sdk/-/vendor-sdk-1.0.0.tgz"}}"#),
        )
        .route(
            "/vendor-sdk/-/vendor-sdk-1.0.0.tgz",
            Reply::new(200).body(tgz_with(&[(
                "package/index.js",
                b"export const api = \"https://events.sdk-vendor.test/v2/track\";",
            )])),
        )
        .route(
            &nrd_path,
            Reply::new(200).body(apk_with(&[(
                "domain-names.txt",
                b"fresh-ads.test\nnew-trk.test\n",
            )])),
        )
        .route(
            "/prebid/Prebid.js/tar.gz/refs/heads/master",
            Reply::new(200).body(tgz_with(&[(
                "Prebid.js-master/modules/fooBidAdapter.js",
                b"const URL = 'https://hb.foo-ads.test/bid';",
            )])),
        )
        .route(
            "/prebid/prebid-server/tar.gz/refs/heads/master",
            Reply::new(200).body(tgz_with(&[(
                "prebid-server-master/static/bidder-info/bar.yaml",
                b"endpoint: \"https://rtb.bar-ads.test/openrtb\"",
            )])),
        )
        .route(
            "/top-1m.csv.zip",
            Reply::new(200).body(apk_with(&[(
                "top-1m.csv",
                b"1,shop.test\n2,news.test\n3,blog.test\n",
            )])),
        )
        .route(
            "/api/v5/addons/addon/tracker-ext/",
            Reply::ok(r#"{"current_version":{"file":{"url":"https://addons.mozilla.org/firefox/downloads/file/1/x.xpi"}}}"#),
        )
        .route(
            "/firefox/downloads/file/1/x.xpi",
            Reply::new(200).body(apk_with(&[
                (
                    "manifest.json",
                    br#"{"name":"Tracker","permissions":["https://api.ext-tracker.test/"]}"#,
                ),
                ("bg.js", b"fetch('https://collect.ext-tracker.test/e');"),
            ])),
        )
        .route(
            "/ads.txt",
            Reply::ok("adsys.test, pub-1, DIRECT, f08c47fec0942fa0\n"),
        )
        .route(
            "/sellers.json",
            Reply::ok(r#"{"sellers":[{"seller_id":"1","domain":"seller.shop.test","seller_type":"PUBLISHER"}]}"#),
        )
        .route(
            "/gtm.js",
            Reply::ok("var data = {\"vtp_serverContainerUrl\":\"https://sgtm.shop.test\",\"x\":\"https://collect.tags.test/g\"};"),
        )
        .fallback(Reply::ok(list))
}

#[test]
fn remote_sources_run_against_a_local_mirror() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let srv = rt.block_on(Http::plain(mirror())).expect("mirror");
    let base = format!("http://{}", srv.addr);
    let st = State::new("mirror");
    let mut prefix: Vec<String> = Vec::new();
    for host in MIRRORED {
        prefix.push("--endpoint".into());
        prefix.push(format!("{host}={base}"));
    }
    let run = |args: &[&str]| {
        let mut all: Vec<&str> = prefix.iter().map(String::as_str).collect();
        all.extend_from_slice(args);
        st.stella(&all);
    };
    run(&["known", "sync"]);
    let pro = std::fs::read_to_string(st.dir.join("known/pro-onlydomains.txt")).expect("pro list");
    assert!(pro.contains("x.tracker.listed.test"));
    run(&["audit", "--list-age-hours", "0"]);
    let zones = st.file("zones.txt", &["shop.test"]);
    run(&["--input", &zones, "source", "passive"]);
    assert!(st.count("SELECT count(*) FROM origin WHERE host = 'a.shop.test'") >= 1);
    run(&["source", "cmp"]);
    run(&["source", "http-archive"]);
    run(&["source", "nrd", "--date", "2026-11-20"]);
    run(&["source", "prebid"]);
    run(&["source", "toplist", "tranco", "--top", "2"]);
    let sdks = st.file("sdks.txt", &["npm:vendor-sdk"]);
    run(&["--input", &sdks, "source", "sdk"]);
    let exts = st.file("exts.txt", &["firefox:tracker-ext"]);
    run(&["--input", &exts, "source", "extension"]);
    let sites = st.file("sites.txt", &["shop.test"]);
    run(&["--input", &sites, "source", "adtech"]);
    run(&["--input", &sites, "source", "site"]);
    st.seed(vec![Row::Tag {
        site: s("shop.test"),
        id: s("GTM-ABC123"),
    }]);
    run(&["source", "container"]);
    let seen: Vec<String> = srv.seen().into_iter().map(|s| s.path).collect();
    for path in [
        "/list/public_suffix_list.dat",
        "/v3/vendor-list.json",
        "/d.json",
        "/third-party-web/-/third-party-web-1.0.0.tgz",
        "/top-1m.csv.zip",
        "/firefox/downloads/file/1/x.xpi",
        "/ads.txt",
    ] {
        assert!(
            seen.iter().any(|p| p.starts_with(path)),
            "{path} not requested: {seen:?}"
        );
    }
    drop(rt);
}
