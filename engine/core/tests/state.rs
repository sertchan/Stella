use std::path::PathBuf;
use stella_core::config::{self, Paths};
use stella_core::known::Known;
use stella_core::progress::{self, Progress};
use stella_core::public_suffix::Psl;
use stella_core::store::{Row, Store};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stella-core-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn s(v: &str) -> String {
    v.to_string()
}

#[test]
fn every_row_kind_lands_in_its_table() -> anyhow::Result<()> {
    let dir = scratch("rows");
    let store = Store::open(&dir.join("deep/t.db"))?;
    let w = store.writer()?;
    let rows = vec![
        Row::Name {
            host: s("a.shop.test"),
            regdom: s("shop.test"),
            known: s(""),
        },
        Row::Origin {
            host: s("a.shop.test"),
            source: s("ct"),
            detail: s("shop.test"),
        },
        Row::Resolution {
            host: s("a.shop.test"),
            rcode: 0,
            chain: s("edge.cdn.test"),
            addrs: s("192.0.2.1"),
            wild: s("REAL"),
            known: s(""),
        },
        Row::Addr {
            addr: s("192.0.2.1"),
            host: s("a.shop.test"),
        },
        Row::Cert {
            host: s("a.shop.test"),
            san: s("b.shop.test"),
        },
        Row::Hit {
            host: s("a.shop.test"),
            product: s("sgtm"),
            evidence: s("healthy ok"),
            verdict: s("PICK"),
        },
        Row::Done {
            kind: s("zone"),
            key: s("shop.test"),
        },
        Row::Tag {
            site: s("shop.test"),
            id: s("GTM-X1"),
        },
        Row::Request {
            site: s("shop.test"),
            method: s("POST"),
            url: s("https://a.shop.test/g/collect"),
        },
        Row::Score {
            host: s("a.shop.test"),
            sites: 3,
            requests: 9,
            post: 0.5,
            id: 0.25,
            path: 1.0,
            score: 4,
            known: s(""),
        },
        Row::Allow {
            host: s("ok.shop.test"),
            reason: s("checkout"),
        },
        Row::ApkUrl {
            pkg: s("com.shop"),
            method: s("literal"),
            url: s("https://a.shop.test/v1"),
            member: s("classes.dex"),
        },
        Row::ZoneDns {
            zone: s("shop.test"),
            kind: "mx",
            value: s("mx.mail.test"),
        },
        Row::TlsPrint {
            host: s("a.shop.test"),
            print: s("TLSv1_3|x|h2|2"),
        },
        Row::CtMark {
            zone: s("shop.test"),
            last: 42,
        },
        Row::Hook {
            site: s("shop.test"),
            api: s("canvas"),
            target: s("toDataURL"),
            script: s("fp.shop.test"),
            calls: 2,
        },
    ];
    let n = rows.len() as u64;
    for r in rows {
        w.send(r);
    }
    w.flush();
    assert_eq!(store.resolved()?.len(), 1);
    assert_eq!(w.finish()?, n);
    for table in [
        "name",
        "origin",
        "resolution",
        "addr",
        "cert",
        "hit",
        "done",
        "tag",
        "request",
        "score",
        "allow",
        "apk_url",
        "zonedns",
        "tlsprint",
        "ctmark",
        "hook",
    ] {
        let count = store.rows(&format!("SELECT count(*) FROM {table}"))?;
        assert_eq!(count[0][0], "1", "{table}");
    }
    assert_eq!(store.done("zone")?.len(), 1);
    assert!(store.probed()?.is_empty());
    assert_eq!(store.rows("SELECT post FROM score")?[0][0], "0.500");
    assert_eq!(
        store
            .set("SELECT host FROM hit WHERE verdict = ?1", "PICK")?
            .len(),
        1
    );
    drop(store);
    let again = Store::open(&dir.join("deep/t.db"))?;
    assert_eq!(again.all("SELECT host FROM name")?.len(), 1);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn paths_live_under_the_state_dir() -> anyhow::Result<()> {
    let dir = scratch("paths");
    let p = Paths { state: dir.clone() };
    p.ensure()?;
    assert!(p.known().is_dir() && p.cache().is_dir() && p.apk().is_dir());
    assert_eq!(p.db(), dir.join("stella.db"));
    assert_eq!(p.psl(), dir.join("public_suffix_list.dat"));
    assert!(!Paths::from_env().state.as_os_str().is_empty());
    assert_eq!(config::resolvers().len(), config::RESOLVERS.len());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn lists_and_suffixes_load_from_files() -> anyhow::Result<()> {
    let dir = scratch("lists");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("pro-onlydomains.txt"),
        "# comment\n\n*.track.test\nads.test\n",
    )?;
    let k = Known::load(&dir, &["pro", "missing"])?;
    assert_eq!(k.len(), 2);
    assert!(!k.is_empty());
    assert!(k.contains("x.track.test"));
    assert!(Known::default().is_empty());
    std::fs::write(
        dir.join("psl.dat"),
        "// ===BEGIN ICANN DOMAINS===\ntest\nco.test\n*.wild.test\n!keep.wild.test\n// ===BEGIN PRIVATE DOMAINS===\npages.test\n",
    )?;
    let psl = Psl::load(&dir.join("psl.dat"))?;
    assert_eq!(psl.public_suffix("a.b.co.test"), "co.test");
    assert_eq!(psl.regdom("a.b.co.test"), Some("b.co.test"));
    assert_eq!(psl.regdom_or_self("co.test"), "co.test");
    assert_eq!(psl.regdom_or_self("me.pages.test"), "me.pages.test");
    assert_eq!(psl.icann_regdom_or_self("me.pages.test"), "pages.test");
    assert_eq!(psl.regdom("a.x.wild.test"), Some("a.x.wild.test"));
    assert_eq!(psl.regdom("a.keep.wild.test"), Some("keep.wild.test"));
    assert!(psl.listed_tld("shop.test"));
    assert!(!psl.listed_tld("shop.nope"));
    assert!(Psl::load(&dir.join("absent.dat")).is_err());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn progress_prints_text_and_json() {
    let mut p = Progress::new("probe", 10);
    assert!(!p.due());
    p.print(3, 2, Some(1), &[("slow.test".into(), 12.0)]);
    p.tick(4, 1, None);
    progress::set_json(true);
    p.print(5, 0, None, &[]);
    progress::set_json(false);
}
