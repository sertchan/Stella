use anyhow::Result;
use rusqlite::Connection;
use rustc_hash::{FxHashMap, FxHashSet};
use stella_core::public_suffix::Psl;

pub fn learn(conn: &Connection, psl: &Psl, min_zones: usize) -> Result<Vec<(String, usize)>> {
    let mut stmt = conn.prepare("SELECT DISTINCT host FROM hit WHERE verdict = 'PICK'")?;
    let hosts: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(std::result::Result::ok)
        .collect();
    let mut zones: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();
    for h in &hosts {
        let rd = psl.regdom_or_self(h);
        let sub = stella_core::name::subdomain(h, rd);
        if sub.is_empty()
            || sub == "www"
            || stella_core::token::skipped(sub)
            || sub.bytes().any(|b| b.is_ascii_digit()) && sub.len() > 12
        {
            continue;
        }
        zones
            .entry(sub.to_string())
            .or_default()
            .insert(rd.to_string());
    }
    let mut out: Vec<(String, usize)> = zones
        .into_iter()
        .filter(|(_, z)| z.len() >= min_zones)
        .map(|(l, z)| (l, z.len()))
        .collect();
    out.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok(out)
}

pub fn candidates(labels: &[(String, usize)], sites: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(labels.len() * sites.len());
    for site in sites {
        for (l, _) in labels {
            if let Some(n) = stella_core::name::normalize(&format!("{l}.{site}")) {
                out.push(n);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learns_shared_labels() -> Result<()> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE hit(host TEXT, product TEXT, evidence TEXT, verdict TEXT, at INTEGER);
             INSERT INTO hit VALUES('sgtm.a.com','sgtm','','PICK',0),('sgtm.b.com','sgtm','','PICK',0),
             ('evs.cdp.c.com','x','','PICK',0),('evs.cdp.d.com','x','','PICK',0),('one.e.com','x','','PICK',0),
             ('sgtm.dev.f.com','x','','PICK',0),('sgtm.dev.g.com','x','','PICK',0);",
        )?;
        let psl = Psl::parse("com\n");
        let l = learn(&conn, &psl, 2)?;
        assert_eq!(l, [("evs.cdp".to_string(), 2), ("sgtm".to_string(), 2)]);
        assert_eq!(
            candidates(&l, &["x.org".into()]),
            ["evs.cdp.x.org", "sgtm.x.org"]
        );
        Ok(())
    }
}
