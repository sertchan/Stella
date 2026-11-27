use anyhow::{Context, Result, bail};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const UMBRELLA: &str = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip";
pub const TRANCO: &str = "https://tranco-list.eu/top-1m.csv.zip";

const MAX_AGE: Duration = Duration::from_secs(20 * 3600);
const ZIP_CAP: u64 = 256 * 1024 * 1024;

pub fn url(list: &str) -> Result<&'static str> {
    match list {
        "umbrella" => Ok(UMBRELLA),
        "tranco" => Ok(TRANCO),
        _ => bail!("unknown list {list}, use umbrella or tranco"),
    }
}

pub async fn fetch(client: &reqwest::Client, list: &str, cache: &Path) -> Result<PathBuf> {
    let path = cache.join(format!("{list}-top-1m.csv.zip"));
    let fresh = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < MAX_AGE);
    if !fresh {
        stella_net::client::download(client, url(list)?, &path, ZIP_CAP).await?;
    }
    Ok(path)
}

pub fn read(path: &Path, top: usize) -> Result<Vec<(u32, String)>> {
    let file = std::fs::File::open(path).with_context(|| path.display().to_string())?;
    let mut zip = zip::ZipArchive::new(file)?;
    let mut entry = zip.by_index(0)?;
    let mut text = String::new();
    entry.read_to_string(&mut text)?;
    Ok(parse(&text, top))
}

pub fn parse(text: &str, top: usize) -> Vec<(u32, String)> {
    text.lines()
        .filter_map(|l| {
            let (rank, name) = l.trim().split_once(',')?;
            let rank: u32 = rank.trim().parse().ok()?;
            Some((rank, stella_core::name::normalize(name)?))
        })
        .take_while(|(rank, _)| (*rank as usize) <= top)
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_ranked_csv() {
        let v = super::parse(
            "1,Google.com\r\n2,bad name\r\n3,api.example.org\r\n4,x.com\n",
            3,
        );
        assert_eq!(
            v,
            [
                (1, "google.com".to_string()),
                (3, "api.example.org".to_string())
            ]
        );
    }
}
