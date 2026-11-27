use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use stella_dns::transport::{self, Config, Query};
use stella_dns::wire::{self, Data};
use stella_dns::{ecs, resolver, stub, wildcard, zone};
use stella_testkit::dns::{self as fake, Answer, Dns, Zone, a, cname, ns, nsec, rr, soa};

fn cfg(d: &Dns) -> Config {
    Config {
        servers: vec![d.addr],
        qps: 2000,
        timeout: Duration::from_millis(300),
        tries: 3,
        sockets: 2,
        ecs_server: d.addr,
    }
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

fn ip(o: [u8; 4]) -> Ipv4Addr {
    Ipv4Addr::from(o)
}

#[tokio::test]
async fn engine_retries_servfail_and_reports_silence() {
    let d = Dns::start(
        Zone::new()
            .record(a("ok.test", [9, 9, 9, 9]))
            .record(a("flaky.test", [9, 9, 9, 8]))
            .failing("flaky.test", 2)
            .silent("mute.test"),
    )
    .await
    .expect("dns");
    let qs: Vec<Query> = ["ok.test", "flaky.test", "mute.test", "nx.test"]
        .iter()
        .map(|n| Query::recursive((*n).into(), wire::A))
        .collect();
    let mut got = std::collections::BTreeMap::new();
    transport::run(&cfg(&d), &qs, |r| {
        got.insert(r.query.name.clone(), r.msg.map(|m| m.rcode));
    })
    .await
    .expect("run");
    assert_eq!(got["ok.test"], Some(wire::NOERROR));
    assert_eq!(got["flaky.test"], Some(wire::NOERROR));
    assert_eq!(got["mute.test"], None);
    assert_eq!(got["nx.test"], Some(wire::NXDOMAIN));
    let flaky = d.asked().iter().filter(|q| q.name == "flaky.test").count();
    assert_eq!(flaky, 3);
    assert!(d.asked().iter().all(|q| q.rd && !q.tcp));
    transport::run(&cfg(&d), &[], |_| {}).await.expect("empty");
}

#[tokio::test]
async fn resolve_follows_chains_and_retries_lost_names() {
    let d = Dns::start(
        Zone::new()
            .answer(
                "www.shop.test",
                fake::A,
                Answer::records(vec![cname("www.shop.test", "edge.cdn.test")]),
            )
            .answer(
                "edge.cdn.test",
                fake::A,
                Answer::records(vec![
                    cname("edge.cdn.test", "e1.cdn.test"),
                    a("e1.cdn.test", [9, 9, 9, 9]),
                ]),
            )
            .record(a("direct.test", [9, 9, 9, 7]))
            .record(a("direct.test", [9, 9, 9, 7]))
            .silent("mute.test"),
    )
    .await
    .expect("dns");
    let got = resolver::resolve(
        &cfg(&d),
        names(&["www.shop.test", "direct.test", "gone.test", "mute.test"]),
    )
    .await
    .expect("resolve");
    let by = |h: &str| got.iter().find(|r| r.host == h).expect("host").clone();
    let www = by("www.shop.test");
    assert_eq!(www.chain, ["edge.cdn.test", "e1.cdn.test"]);
    assert_eq!(www.addrs, [ip([9, 9, 9, 9])]);
    assert_eq!(www.last(), "e1.cdn.test");
    assert!(www.answered());
    assert_eq!(by("direct.test").addrs, [ip([9, 9, 9, 7])]);
    assert_eq!(by("gone.test").rcode, i64::from(wire::NXDOMAIN));
    assert!(!by("gone.test").answered());
    assert_eq!(by("mute.test").rcode, resolver::TIMEOUT);
    assert!(resolver::public(&ip([9, 9, 9, 9])));
    assert!(!resolver::public(&ip([100, 64, 0, 1])));
    assert!(!resolver::public(&ip([127, 0, 0, 1])));
}

#[tokio::test]
async fn lookup_returns_records_of_the_asked_type() {
    let d = Dns::start(
        Zone::new()
            .record(rr("t.test", fake::Data::Txt(vec!["v=spf1 -all".into()])))
            .record(rr(
                "h.test",
                fake::Data::Https(1, "svc.test".into(), vec!["h2".into(), "h3".into()]),
            ))
            .record(rr(
                "six.test",
                fake::Data::Aaaa("2001:db8::1".parse().expect("v6")),
            )),
    )
    .await
    .expect("dns");
    let c = cfg(&d);
    let txt = resolver::lookup(&c, &names(&["t.test", "none.test"]), wire::TXT)
        .await
        .expect("txt");
    assert_eq!(txt["t.test"], [Data::Txt(vec!["v=spf1 -all".into()])]);
    assert!(!txt.contains_key("none.test"));
    let https = resolver::lookup(&c, &names(&["h.test"]), wire::HTTPS)
        .await
        .expect("https");
    assert_eq!(
        https["h.test"],
        [Data::Svcb {
            priority: 1,
            target: "svc.test".into(),
            alpn: vec!["h2".into(), "h3".into()],
        }]
    );
    let six = resolver::lookup(&c, &names(&["six.test"]), wire::AAAA)
        .await
        .expect("aaaa");
    assert_eq!(
        six["six.test"],
        [Data::Aaaa("2001:db8::1".parse().expect("v6"))]
    );
}

#[tokio::test]
async fn wildcard_controls_separate_real_and_wild_names() {
    let d = Dns::start(
        Zone::new()
            .record(a("*.wild.test", [9, 9, 9, 1]))
            .record(a("api.real.test", [9, 9, 9, 2]))
            .record(a("*.other.test", [8, 8, 8, 8])),
    )
    .await
    .expect("dns");
    let c = cfg(&d);
    let hosts = resolver::resolve(
        &c,
        names(&[
            "a.wild.test",
            "api.real.test",
            "x.other.test",
            "nx.real.test",
        ]),
    )
    .await
    .expect("resolve");
    let v = wildcard::check(&c, &hosts).await.expect("check");
    assert_eq!(v["a.wild.test"], wildcard::Verdict::Wild);
    assert_eq!(v["api.real.test"], wildcard::Verdict::Real);
    assert_eq!(v["nx.real.test"], wildcard::Verdict::Nx);
    assert_eq!(wildcard::Verdict::Wild.as_str(), "WILD");
    assert_eq!(wildcard::Verdict::Real.as_str(), "REAL");
}

#[tokio::test]
async fn client_subnets_give_regional_answers() {
    let eu = ecs::REGIONS[0].1;
    let us = ecs::REGIONS[1].1;
    let d = Dns::start(
        Zone::new()
            .subnet(
                "geo.test",
                fake::A,
                eu,
                Answer::records(vec![a("geo.test", [9, 9, 9, 1])]),
            )
            .subnet(
                "geo.test",
                fake::A,
                us,
                Answer::records(vec![cname("geo.test", "us.edge.test")]),
            )
            .record(a("us.edge.test", [9, 9, 9, 2]))
            .record(a("geo.test", [9, 9, 9, 3])),
    )
    .await
    .expect("dns");
    let c = cfg(&d);
    let placed = ecs::addresses(&c, &names(&["geo.test"]))
        .await
        .expect("addresses");
    let mut seen: Vec<(&str, Vec<Ipv4Addr>)> =
        placed.iter().map(|p| (p.region, p.addrs.clone())).collect();
    seen.sort();
    assert_eq!(
        seen,
        [
            ("asia", vec![ip([9, 9, 9, 3])]),
            ("eu", vec![ip([9, 9, 9, 1])]),
            ("us", vec![ip([9, 9, 9, 2])]),
        ]
    );
    let chains = ecs::chains(&c, &names(&["geo.test"]))
        .await
        .expect("chains");
    let us_chain = chains.iter().find(|s| s.region == "us").expect("us");
    assert_eq!(us_chain.chain, ["us.edge.test"]);
    assert!(chains.iter().all(|s| s.region == "us"));
    assert!(d.asked().iter().all(|q| q.subnet.is_some()));
}

#[tokio::test]
async fn stub_follows_cnames_one_query_at_a_time() {
    let d = Dns::start(
        Zone::new()
            .answer(
                "s.stub.test",
                fake::A,
                Answer::records(vec![cname("s.stub.test", "t.stub.test")]),
            )
            .record(a("t.stub.test", [9, 9, 9, 4])),
    )
    .await
    .expect("dns");
    assert_eq!(
        stub::lookup_a_with(&[d.addr], "S.Stub.Test.").await,
        [ip([9, 9, 9, 4])]
    );
    assert_eq!(
        stub::lookup_a_with(&[d.addr], "s.stub.test").await,
        [ip([9, 9, 9, 4])]
    );
    assert!(
        stub::lookup_a_with(&[d.addr], "nx.stub.test")
            .await
            .is_empty()
    );
    assert!(stub::lookup_a_with(&[], "empty.stub.test").await.is_empty());
    let asked = d.asked();
    assert_eq!(asked.iter().filter(|q| q.name == "s.stub.test").count(), 1);
    let mut s = stub::Stub::new().await.expect("stub");
    let m = s
        .ask(
            d.addr,
            "t.stub.test",
            wire::A,
            false,
            true,
            Duration::from_secs(1),
        )
        .await
        .expect("reply");
    assert_eq!(m.answers.len(), 1);
    assert!(d.asked().iter().any(|q| q.dnssec && !q.rd));
}

#[tokio::test]
async fn zones_transfer_probe_and_walk() {
    let d = Dns::start(
        Zone::new()
            .record(ns("own.test", "ns1.own.test"))
            .record(ns("own.test", "ns2.own.test"))
            .record(a("ns1.own.test", [9, 9, 9, 5]))
            .record(a("ns2.own.test", [9, 9, 9, 6]))
            .record(ns("hosted.test", "kim.ns.cloudflare.com"))
            .transfer(
                "own.test",
                vec![
                    soa("own.test", "ns1.own.test", "admin.own.test"),
                    a("www.own.test", [9, 9, 9, 7]),
                    a("mail.own.test", [9, 9, 9, 8]),
                    soa("own.test", "ns1.own.test", "admin.own.test"),
                ],
            )
            .answer(
                "*.own.test",
                fake::A,
                Answer::rcode(fake::NXDOMAIN).authority(vec![nsec("own.test", "api.own.test")]),
            )
            .answer(
                "*.lies.test",
                fake::A,
                Answer::rcode(fake::NXDOMAIN).authority(vec![nsec("lies.test", "\\000.lies.test")]),
            )
            .record(nsec("own.test", "api.own.test"))
            .record(nsec("api.own.test", "www.own.test"))
            .record(nsec("www.own.test", "own.test")),
    )
    .await
    .expect("dns");
    let c = cfg(&d);
    let pairs = zone::selfhosted(&c, names(&["own.test", "hosted.test"]))
        .await
        .expect("selfhosted");
    let servers: BTreeSet<String> = pairs
        .iter()
        .map(|p| format!("{} {}", p.zone, p.server))
        .collect();
    assert_eq!(
        servers,
        BTreeSet::from(["own.test 9.9.9.5:53".into(), "own.test 9.9.9.6:53".into()])
    );
    assert_eq!(
        zone::axfr("own.test", d.addr).await,
        ["mail.own.test", "own.test", "www.own.test"]
    );
    assert!(zone::axfr("hosted.test", d.addr).await.is_empty());
    let local = vec![
        zone::Pair {
            zone: "own.test".into(),
            server: d.addr,
        },
        zone::Pair {
            zone: "lies.test".into(),
            server: d.addr,
        },
    ];
    assert_eq!(
        zone::nsec_probe(&c, &local).await.expect("probe"),
        [(0, "api.own.test".to_string())]
    );
    assert_eq!(
        zone::walk("own.test", d.addr, Duration::from_secs(5), 100).await,
        ["api.own.test", "www.own.test"]
    );
    assert_eq!(
        zone::walk("own.test", d.addr, Duration::from_secs(5), 1).await,
        ["api.own.test"]
    );
    let closed: SocketAddr = ([127, 0, 0, 1], 9).into();
    assert!(zone::axfr("own.test", closed).await.is_empty());
}
