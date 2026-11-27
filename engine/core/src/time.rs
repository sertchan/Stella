pub const SECONDS_PER_DAY: i64 = 86_400;

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

pub fn date(unix: i64) -> String {
    let (y, m, d) = civil(unix.div_euclid(SECONDS_PER_DAY));
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn utc(unix: i64) -> String {
    let secs = unix.rem_euclid(SECONDS_PER_DAY);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        date(unix),
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn list_modified(unix: i64) -> String {
    let (y, m, d) = civil(unix.div_euclid(SECONDS_PER_DAY));
    let secs = unix.rem_euclid(SECONDS_PER_DAY);
    format!(
        "{d} {} {y} {:02}:{:02} UTC",
        MONTHS[(m - 1) as usize],
        secs / 3600,
        secs % 3600 / 60
    )
}

pub fn list_version(unix: i64) -> String {
    let (y, m, d) = civil(unix.div_euclid(SECONDS_PER_DAY));
    let secs = unix.rem_euclid(SECONDS_PER_DAY);
    format!(
        "{y}.{m:02}{d:02}.{:02}{:02}.{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_unix_time() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_418), (2025, 11, 26));
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(-1), "1969-12-31");
        assert_eq!(utc(1_795_234_589), "2026-11-21T04:16:29Z");
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(list_modified(1_795_234_589), "21 Nov 2026 04:16 UTC");
        assert_eq!(list_version(1_795_234_589), "2026.1121.0416.29");
        assert_eq!(list_modified(0), "1 Jan 1970 00:00 UTC");
    }
}
