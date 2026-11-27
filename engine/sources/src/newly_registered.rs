use base64::Engine;
use std::io::{Cursor, Read};

const BASE: &str = "https://www.whoisds.com/whois-database/newly-registered-domains";
const MEMBER: &str = "domain-names.txt";
const SECONDS_PER_DAY: i64 = 86_400;

pub fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

pub fn day_before(unix: i64) -> String {
    let (y, m, d) = civil(unix.div_euclid(SECONDS_PER_DAY) - 1);
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

pub fn url(date: &str) -> String {
    let name = base64::engine::general_purpose::STANDARD.encode(format!("{date}.zip"));
    format!("{BASE}/{name}/nrd")
}

pub fn domains(zip_bytes: &[u8]) -> Option<Vec<String>> {
    let mut zip = zip::ZipArchive::new(Cursor::new(zip_bytes)).ok()?;
    let mut f = zip.by_name(MEMBER).ok()?;
    let mut text = String::new();
    f.read_to_string(&mut text).ok()?;
    let mut out: Vec<String> = text
        .lines()
        .filter_map(|l| stella_core::name::normalize(l.trim()))
        .filter(|d| d.contains('.'))
        .collect();
    out.sort_unstable();
    out.dedup();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn builds_dates_urls_and_reads_the_list() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_418), (2025, 11, 26));
        assert_eq!(day_before(1_795_737_600), "2026-11-26");
        assert!(valid_date("2026-11-25"));
        assert!(!valid_date("2026-1-25"));
        assert_eq!(
            url("2026-11-25"),
            "https://www.whoisds.com/whois-database/newly-registered-domains/MjAyNi0xMS0yNS56aXA=/nrd"
        );
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file(MEMBER, zip::write::SimpleFileOptions::default())
            .expect("start");
        w.write_all(b"b-trk.com\r\nA-ads.net\nlocalhost\n")
            .expect("write");
        let z = w.finish().expect("finish").into_inner();
        assert_eq!(domains(&z).expect("zip"), ["a-ads.net", "b-trk.com"]);
    }
}
