use anyhow::{Context, Result, anyhow};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_postgres::{Client, Config, NoTls, SimpleQueryMessage};

const CRTSH: &str = "crt.sh";
const STATEMENT_CAP: Duration = Duration::from_secs(100);
const RETRY_PAUSE_MIN_MS: u64 = 4000;
const RETRY_PAUSE_SPREAD_MS: u64 = 8000;

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
    let (client, conn) = cfg.connect(NoTls).await.context("crt.sh connect")?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(client)
}

fn query(zone: &str, subzone: bool) -> String {
    let like = if subzone {
        format!("%{zone}")
    } else {
        format!("%.{zone}")
    };
    format!(
        "SELECT DISTINCT lower(ci.name_value) FROM certificate_and_identities ci WHERE plainto_tsquery('certwatch', '{zone}') @@ identities(ci.certificate) AND lower(ci.name_value) LIKE '{like}'"
    )
}

async fn names(client: &Client, zone: &str, subzone: bool) -> Result<Vec<String>> {
    let rows = tokio::time::timeout(STATEMENT_CAP, client.simple_query(&query(zone, subzone)))
        .await
        .map_err(|_| anyhow!("timeout"))??;
    let mut out: Vec<String> = rows
        .iter()
        .filter_map(|m| match m {
            SimpleQueryMessage::Row(r) => r.get(0),
            _ => None,
        })
        .filter_map(stella_core::name::normalize)
        .filter(|n| n.ends_with(zone))
        .collect();
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

pub type Outcome = (String, Result<Vec<String>>);

pub async fn run(zones: Vec<String>, par: usize, subzone: bool, tx: mpsc::Sender<Outcome>) {
    let queue = Arc::new(Mutex::new(VecDeque::from(zones)));
    let mut workers = Vec::new();
    for w in 0..par.max(1) {
        let queue = queue.clone();
        let tx = tx.clone();
        workers.push(tokio::spawn(async move {
            let mut rng = stella_core::rng::Rng::seeded();
            let mut client: Option<Client> = None;
            loop {
                let Some(zone) = queue.lock().ok().and_then(|mut q| q.pop_front()) else {
                    break;
                };
                let mut result = Err(anyhow!("not tried"));
                for attempt in 0..2 {
                    if client.as_ref().is_none_or(Client::is_closed) {
                        client = connect().await.ok();
                    }
                    if let Some(c) = &client {
                        result = names(c, &zone, subzone).await;
                        if result.is_ok() {
                            break;
                        }
                        client = None;
                    }
                    if attempt == 0 {
                        let pause =
                            RETRY_PAUSE_MIN_MS + rng.below(RETRY_PAUSE_SPREAD_MS) + w as u64;
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
    fn builds_queries() {
        assert!(super::query("example.com", false).ends_with("LIKE '%.example.com'"));
        assert!(super::query("sub.example.com", true).ends_with("LIKE '%sub.example.com'"));
    }
}
