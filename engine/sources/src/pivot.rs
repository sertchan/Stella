use anyhow::Result;
use rusqlite::Connection;
use rustc_hash::FxHashSet;
use stella_core::public_suffix::Psl;

pub struct Pivot {
    pub neighbours: Vec<(String, String, String)>,
    pub sans: Vec<(String, String)>,
    pub zones: Vec<String>,
}

const PICKS: &str = "SELECT DISTINCT host FROM hit WHERE verdict = 'PICK'";
const PICKS_AND_REVIEWS: &str = "SELECT DISTINCT host FROM hit WHERE verdict IN ('PICK', 'REVIEW')";

pub fn collect(
    conn: &Connection,
    psl: &Psl,
    max_per_addr: i64,
    with_review: bool,
) -> Result<Pivot> {
    let hits = if with_review {
        PICKS_AND_REVIEWS
    } else {
        PICKS
    };
    let mut stmt = conn.prepare(&format!(
        "WITH h AS ({hits}),
              a AS (SELECT addr, host AS via FROM addr WHERE host IN h),
              c AS (SELECT addr, count(*) AS n FROM addr WHERE addr IN (SELECT addr FROM a) GROUP BY addr HAVING n > 1 AND n <= ?1)
         SELECT DISTINCT addr.host, addr.addr, a.via FROM addr JOIN c USING(addr) JOIN a USING(addr)
         WHERE addr.host NOT IN h"
    ))?;
    let neighbours = stmt
        .query_map([max_per_addr], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .filter_map(std::result::Result::ok)
        .collect();
    let mut stmt = conn.prepare(&format!(
        "SELECT DISTINCT san, host FROM cert WHERE host IN ({hits}) AND san != host"
    ))?;
    let sans = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(std::result::Result::ok)
        .collect();
    let mut stmt = conn.prepare(hits)?;
    let zones: FxHashSet<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(std::result::Result::ok)
        .map(|h| psl.regdom_or_self(&h).to_string())
        .collect();
    let mut zones: Vec<String> = zones.into_iter().collect();
    zones.sort_unstable();
    Ok(Pivot {
        neighbours,
        sans,
        zones,
    })
}
