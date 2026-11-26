use anyhow::{Result, anyhow};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_postgres::{Client, Config, NoTls};

const CRTSH: &str = "crt.sh";
const STATEMENT_CAP: Duration = Duration::from_secs(100);
const RETRY_PAUSE_MIN_MS: u64 = 4000;
const RETRY_PAUSE_SPREAD_MS: u64 = 8000;
const ZONE_TRIES: usize = 3;

async fn connect() -> Result<Client> {
    let ip = stella_dns::stub::lookup_a(CRTSH)
        .await
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no address for {CRTSH}"))?;
    let mut cfg = Config::new();
    cfg.host(CRTSH)
        .hostaddr(ip.into())
        .port(5432)
        .user("guest")
        .dbname("certwatch")
        .connect_timeout(Duration::from_secs(15));
    let (client, conn) = cfg.connect(NoTls).await.map_err(|e| {
        let detail = e
            .as_db_error()
            .map_or(e.to_string(), |d| d.message().to_string());
        anyhow!("crt.sh connect: {detail}")
    })?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(client)
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

const NAMES_SQL: &str = "SELECT DISTINCT lower(ci.name_value) FROM certificate_and_identities ci WHERE plainto_tsquery('certwatch', $1) @@ identities(ci.certificate) AND lower(ci.name_value) LIKE $2";

fn pattern(zone: &str, subzone: bool) -> String {
    let escaped = like_escape(zone);
    if subzone {
        format!("%{escaped}")
    } else {
        format!("%.{escaped}")
    }
}

async fn names(client: &Client, zone: &str, subzone: bool) -> Result<Vec<String>> {
    let like = pattern(zone, subzone);
    let rows = tokio::time::timeout(STATEMENT_CAP, client.query(NAMES_SQL, &[&zone, &like]))
        .await
        .map_err(|_| anyhow!("timeout"))??;
    let mut out: Vec<String> = rows
        .iter()
        .filter_map(|r| r.get::<_, Option<String>>(0))
        .filter_map(|n| stella_core::name::normalize(&n))
        .filter(|n| n.ends_with(zone))
        .collect();
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

pub type Outcome = (String, Result<Vec<String>>);

fn take(queue: &Mutex<VecDeque<String>>) -> Option<String> {
    queue.lock().ok()?.pop_front()
}

pub async fn run(zones: Vec<String>, par: usize, subzone: bool, tx: mpsc::Sender<Outcome>) {
    let queue = Arc::new(Mutex::new(VecDeque::from(zones)));
    let mut workers = Vec::new();
    for w in 0..par.max(1) {
        let queue = queue.clone();
        let tx = tx.clone();
        workers.push(tokio::spawn(async move {
            let mut rng = stella_core::rng::Rng::seeded();
            let mut client: Option<Client> = None;
            while let Some(zone) = take(&queue) {
                let mut result = Err(anyhow!("not tried"));
                for attempt in 0..ZONE_TRIES {
                    if client.as_ref().is_none_or(Client::is_closed) {
                        match connect().await {
                            Ok(c) => client = Some(c),
                            Err(e) => result = Err(e),
                        }
                    }
                    if let Some(c) = &client {
                        result = names(c, &zone, subzone).await;
                        if result.is_ok() {
                            break;
                        }
                        client = None;
                    }
                    if attempt + 1 < ZONE_TRIES {
                        let pause = (RETRY_PAUSE_MIN_MS + rng.below(RETRY_PAUSE_SPREAD_MS))
                            * (attempt as u64 + 1)
                            + w as u64;
                        tokio::time::sleep(Duration::from_millis(pause)).await;
                    }
                }
                if tx.send((zone, result)).await.is_err() {
                    break;
                }
            }
        }));
    }
    drop(tx);
    for w in workers {
        let _ = w.await;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds_like_patterns() {
        assert_eq!(super::pattern("example.com", false), "%.example.com");
        assert_eq!(super::pattern("sub.example.com", true), "%sub.example.com");
        assert_eq!(super::pattern("my_zone.com", false), "%.my\\_zone.com");
        assert_eq!(super::pattern("a%b.com", false), "%.a\\%b.com");
    }
}
