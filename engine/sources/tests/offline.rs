use std::io::Write;
use std::path::PathBuf;
use stella_core::public_suffix::Psl;
use stella_core::store::{Row, Store};
use stella_sources::{adtech, audit, container, pivot, toplist};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stella-sources-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    dir
}

#[test]
fn parses_github_issue_pages() {
    let page = br#"[
      {"number": 7, "updated_at": "2026-11-01T00:00:00Z", "state": "closed",
       "state_reason": "completed", "labels": [{"name": "added"}],
       "title": "Block t.vendor.test", "body": "seen on m.shop.test"},
      {"number": 8, "updated_at": "2026-11-02T00:00:00Z", "state": "open",
       "labels": [], "title": "allow cdn.shop.test", "body": null},
      {"number": 9, "pull_request": {}, "updated_at": "x", "state": "open", "labels": []}
    ]"#;
    let issues = audit::parse_issues(page, "allow", |_| true).expect("issues");
    assert_eq!(issues.len(), 2);
    assert_eq!(issues[0].number, 7);
    assert_eq!(issues[0].updated, "2026-11-01T00:00:00Z");
    assert!(issues[0].hosts.contains(&"t.vendor.test".to_string()));
    assert_eq!(issues[1].outcome, audit::PENDING);
    assert!(audit::parse_issues(br#"{"message": "rate limited"}"#, "allow", |_| true).is_err());
    assert!(audit::parse_issues(b"nope", "allow", |_| true).is_err());
    let first = audit::issues_url("allow", None, 1);
    assert!(first.contains("labels=allow") && first.ends_with("page=1"));
    assert!(
        audit::issues_url("deny", Some("2026-01-01T00:00:00Z"), 2)
            .ends_with("&since=2026-01-01T00:00:00Z")
    );
    assert!(audit::last_page(3));
    assert!(!audit::last_page(100));
}

#[test]
fn reads_hosts_from_prebid_tarballs() -> anyhow::Result<()> {
    let dir = scratch("tar");
    let path = dir.join("pb.tar.gz");
    let gz =
        flate2::write::GzEncoder::new(std::fs::File::create(&path)?, flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    let files: [(&str, &[u8]); 3] = [
        (
            "pb/modules/fooBidAdapter.js",
            b"const URL = 'https://hb.foo-ads.test/bid';",
        ),
        (
            "pb/static/bidder-info/bar.yaml",
            b"endpoint: \"https://rtb.bar.test/openrtb\"",
        ),
        ("pb/README.md", b"https://docs.ignored.test/"),
    ];
    for (name, body) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, name, body)?;
    }
    tar.into_inner()?.finish()?.flush()?;
    let hosts = adtech::hosts_in_tarball(&path, adtech::prebid_member)?;
    let names: Vec<&str> = hosts.iter().map(|(h, _)| h.as_str()).collect();
    assert_eq!(names, ["hb.foo-ads.test", "rtb.bar.test"]);
    assert_eq!(hosts[0].1, "fooBidAdapter.js");
    assert!(adtech::hosts_in_tarball(&dir.join("absent.tgz"), adtech::prebid_member).is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn reads_ranked_names_from_zipped_top_lists() -> anyhow::Result<()> {
    let dir = scratch("zip");
    let path = dir.join("top.csv.zip");
    let mut z = zip::ZipWriter::new(std::fs::File::create(&path)?);
    z.start_file(
        "top-1m.csv",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    z.write_all(b"1,google.test\n2,shop.test\n3,third.test\n")?;
    z.finish()?;
    assert_eq!(
        toplist::read(&path, 2)?,
        [(1, "google.test".to_string()), (2, "shop.test".to_string())]
    );
    assert!(toplist::read(&dir.join("absent.zip"), 2).is_err());
    assert_eq!(toplist::url("tranco")?, toplist::TRANCO);
    assert_eq!(toplist::url("umbrella")?, toplist::UMBRELLA);
    assert!(toplist::url("alexa").is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn container_urls_follow_the_id_kind() {
    assert_eq!(
        container::url("GTM-ABC1"),
        "https://www.googletagmanager.com/gtm.js?id=GTM-ABC1"
    );
    assert_eq!(
        container::url("G-XYZ9"),
        "https://www.googletagmanager.com/gtag/js?id=G-XYZ9"
    );
}

#[test]
fn pivots_from_picks_to_neighbours_sans_and_zones() -> anyhow::Result<()> {
    let dir = scratch("pivot");
    let store = Store::open(&dir.join("t.db"))?;
    let w = store.writer()?;
    let hit = |host: &str, verdict: &str| Row::Hit {
        host: host.into(),
        product: "sgtm".into(),
        evidence: "x".into(),
        verdict: verdict.into(),
    };
    let addr = |a: &str, host: &str| Row::Addr {
        addr: a.into(),
        host: host.into(),
    };
    for r in [
        hit("t.shop.test", "PICK"),
        hit("r.blog.test", "REVIEW"),
        addr("198.51.100.1", "t.shop.test"),
        addr("198.51.100.1", "n.shop.test"),
        addr("198.51.100.2", "r.blog.test"),
        addr("198.51.100.2", "m.blog.test"),
        Row::Cert {
            host: "t.shop.test".into(),
            san: "s.shop.test".into(),
        },
    ] {
        w.send(r);
    }
    w.finish()?;
    let psl = Psl::parse("test\n");
    let picks = pivot::collect(&store.conn, &psl, 10, false)?;
    assert_eq!(
        picks.neighbours,
        [(
            "n.shop.test".to_string(),
            "198.51.100.1".to_string(),
            "t.shop.test".to_string()
        )]
    );
    assert_eq!(
        picks.sans,
        [("s.shop.test".to_string(), "t.shop.test".to_string())]
    );
    assert_eq!(picks.zones, ["shop.test"]);
    let both = pivot::collect(&store.conn, &psl, 10, true)?;
    assert_eq!(both.neighbours.len(), 2);
    assert_eq!(both.zones, ["blog.test", "shop.test"]);
    assert!(
        pivot::collect(&store.conn, &psl, 1, true)?
            .neighbours
            .is_empty()
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
