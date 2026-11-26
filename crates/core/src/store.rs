use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, params};
use rustc_hash::FxHashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::JoinHandle;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS name(host TEXT PRIMARY KEY, regdom TEXT NOT NULL, known TEXT NOT NULL, seen INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS origin(host TEXT NOT NULL, source TEXT NOT NULL, detail TEXT NOT NULL, PRIMARY KEY(host, source, detail)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS resolution(host TEXT PRIMARY KEY, rcode INTEGER NOT NULL, chain TEXT NOT NULL, addrs TEXT NOT NULL, wild TEXT NOT NULL, known TEXT NOT NULL, at INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS addr(addr TEXT NOT NULL, host TEXT NOT NULL, PRIMARY KEY(addr, host)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS probe(host TEXT NOT NULL, path TEXT NOT NULL, addr TEXT NOT NULL, status INTEGER NOT NULL, ctype TEXT NOT NULL, server TEXT NOT NULL, cookies TEXT NOT NULL, length INTEGER NOT NULL, head TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(host, path)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS cert(host TEXT NOT NULL, san TEXT NOT NULL, PRIMARY KEY(host, san)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hit(host TEXT NOT NULL, product TEXT NOT NULL, evidence TEXT NOT NULL, verdict TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(host, product)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS done(kind TEXT NOT NULL, key TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(kind, key)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS tag(site TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY(site, id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS request(site TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS score(host TEXT PRIMARY KEY, sites INTEGER NOT NULL, requests INTEGER NOT NULL, post REAL NOT NULL, id REAL NOT NULL, path REAL NOT NULL, score INTEGER NOT NULL, known TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS apk_url(pkg TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL, member TEXT NOT NULL, PRIMARY KEY(pkg, method, url)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS allow(host TEXT PRIMARY KEY, reason TEXT NOT NULL, at INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS issue(host TEXT NOT NULL, number INTEGER NOT NULL, kind TEXT NOT NULL, outcome TEXT NOT NULL, PRIMARY KEY(host, number)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS exception(host TEXT NOT NULL, list TEXT NOT NULL, kind TEXT NOT NULL, PRIMARY KEY(host, list)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS vendor(suffix TEXT PRIMARY KEY, listed INTEGER NOT NULL, background INTEGER NOT NULL, source TEXT NOT NULL) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS issue_number ON issue(number);
CREATE INDEX IF NOT EXISTS exception_list ON exception(list);
CREATE INDEX IF NOT EXISTS origin_source ON origin(source);
CREATE INDEX IF NOT EXISTS addr_host ON addr(host);
CREATE INDEX IF NOT EXISTS request_site ON request(site);
";

pub enum Row {
    Name {
        host: String,
        regdom: String,
        known: String,
    },
    Origin {
        host: String,
        source: String,
        detail: String,
    },
    Resolution {
        host: String,
        rcode: i64,
        chain: String,
        addrs: String,
        wild: String,
        known: String,
    },
    Addr {
        addr: String,
        host: String,
    },
    Probe {
        host: String,
        path: String,
        addr: String,
        status: i64,
        ctype: String,
        server: String,
        cookies: String,
        length: i64,
        head: String,
        digest: String,
    },
    Cert {
        host: String,
        san: String,
    },
    Hit {
        host: String,
        product: String,
        evidence: String,
        verdict: String,
    },
    Done {
        kind: String,
        key: String,
    },
    Tag {
        site: String,
        id: String,
    },
    Request {
        site: String,
        method: String,
        url: String,
    },
    Score {
        host: String,
        sites: i64,
        requests: i64,
        post: f64,
        id: f64,
        path: f64,
        score: i64,
        known: String,
    },
    Allow {
        host: String,
        reason: String,
    },
    ApkUrl {
        pkg: String,
        method: String,
        url: String,
        member: String,
    },
    ZoneDns {
        zone: String,
        kind: &'static str,
        value: String,
    },
}

pub struct Store {
    pub conn: Connection,
    path: PathBuf,
}

const PROBE_DIGEST: &str = "ALTER TABLE probe ADD COLUMN digest TEXT NOT NULL DEFAULT '';";

const RUN_LOG: &str = "CREATE TABLE IF NOT EXISTS run(started INTEGER NOT NULL, seq INTEGER NOT NULL, stage TEXT NOT NULL, secs REAL NOT NULL, detail TEXT NOT NULL, PRIMARY KEY(started, seq)) WITHOUT ROWID;";

const ZONE_DNS: &str = "CREATE TABLE IF NOT EXISTS zonedns(zone TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(zone, kind, value)) WITHOUT ROWID; CREATE INDEX IF NOT EXISTS zonedns_value ON zonedns(kind, value);";

const MIGRATIONS: &[&str] = &[SCHEMA, PROBE_DIGEST, RUN_LOG, ZONE_DNS];

pub fn migrate(conn: &Connection) -> Result<i64> {
    let mut version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let target = MIGRATIONS.len() as i64;
    if version > target {
        anyhow::bail!("database schema {version} is newer than this build, which knows {target}");
    }
    while version < target {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATIONS[version as usize])?;
        version += 1;
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
    Ok(version)
}

fn tune(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-262144; PRAGMA busy_timeout=60000;",
    )?;
    Ok(())
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .with_context(|| format!("open {}", path.display()))?;
        tune(&conn)?;
        migrate(&conn)?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    pub fn writer(&self) -> Result<Writer> {
        Writer::spawn(&self.path)
    }

    pub fn set(&self, sql: &str, key: &str) -> Result<FxHashSet<String>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([key], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn all(&self, sql: &str) -> Result<FxHashSet<String>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn done(&self, kind: &str) -> Result<FxHashSet<String>> {
        self.set("SELECT key FROM done WHERE kind = ?1", kind)
    }

    pub fn resolved(&self) -> Result<FxHashSet<String>> {
        self.all("SELECT host FROM resolution")
    }

    pub fn probed(&self) -> Result<FxHashSet<String>> {
        self.all("SELECT DISTINCT host FROM probe")
    }

    pub fn rows(&self, sql: &str) -> Result<Vec<Vec<String>>> {
        let mut stmt = self.conn.prepare(sql)?;
        let n = stmt.column_count();
        let rows = stmt.query_map([], |r| {
            (0..n)
                .map(|i| {
                    r.get_ref(i).map(|v| match v {
                        rusqlite::types::ValueRef::Null => String::new(),
                        rusqlite::types::ValueRef::Integer(x) => x.to_string(),
                        rusqlite::types::ValueRef::Real(x) => format!("{x:.3}"),
                        rusqlite::types::ValueRef::Text(t) | rusqlite::types::ValueRef::Blob(t) => {
                            String::from_utf8_lossy(t).into_owned()
                        }
                    })
                })
                .collect::<rusqlite::Result<Vec<String>>>()
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}

#[derive(Clone)]
pub struct Writer {
    tx: mpsc::Sender<Msg>,
    handle: std::sync::Arc<std::sync::Mutex<Option<JoinHandle<Result<u64>>>>>,
}

const BATCH: usize = 50_000;

fn insert(conn: &Connection, row: Row, at: i64) -> rusqlite::Result<usize> {
    match row {
        Row::Name {
            host,
            regdom,
            known,
        } => conn
            .prepare_cached("INSERT INTO name VALUES(?1, ?2, ?3, ?4) ON CONFLICT(host) DO UPDATE SET known = excluded.known")?
            .execute(params![host, regdom, known, at]),
        Row::Origin {
            host,
            source,
            detail,
        } => conn
            .prepare_cached("INSERT OR IGNORE INTO origin VALUES(?1, ?2, ?3)")?
            .execute(params![host, source, detail]),
        Row::Resolution {
            host,
            rcode,
            chain,
            addrs,
            wild,
            known,
        } => conn
            .prepare_cached("INSERT OR REPLACE INTO resolution VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)")?
            .execute(params![host, rcode, chain, addrs, wild, known, at]),
        Row::Addr { addr, host } => conn
            .prepare_cached("INSERT OR IGNORE INTO addr VALUES(?1, ?2)")?
            .execute(params![addr, host]),
        Row::Probe {
            host,
            path,
            addr,
            status,
            ctype,
            server,
            cookies,
            length,
            head,
            digest,
        } => conn
            .prepare_cached(
                "INSERT OR REPLACE INTO probe(host, path, addr, status, ctype, server, cookies, length, head, at, digest) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?
            .execute(params![
                host, path, addr, status, ctype, server, cookies, length, head, at, digest
            ]),
        Row::Cert { host, san } => conn
            .prepare_cached("INSERT OR IGNORE INTO cert VALUES(?1, ?2)")?
            .execute(params![host, san]),
        Row::Hit {
            host,
            product,
            evidence,
            verdict,
        } => conn
            .prepare_cached("INSERT OR REPLACE INTO hit VALUES(?1, ?2, ?3, ?4, ?5)")?
            .execute(params![host, product, evidence, verdict, at]),
        Row::Done { kind, key } => conn
            .prepare_cached("INSERT OR REPLACE INTO done VALUES(?1, ?2, ?3)")?
            .execute(params![kind, key, at]),
        Row::Tag { site, id } => conn
            .prepare_cached("INSERT OR IGNORE INTO tag VALUES(?1, ?2)")?
            .execute(params![site, id]),
        Row::Request { site, method, url } => conn
            .prepare_cached("INSERT INTO request VALUES(?1, ?2, ?3)")?
            .execute(params![site, method, url]),
        Row::Score {
            host,
            sites,
            requests,
            post,
            id,
            path,
            score,
            known,
        } => conn
            .prepare_cached("INSERT OR REPLACE INTO score VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")?
            .execute(params![host, sites, requests, post, id, path, score, known]),
        Row::Allow { host, reason } => conn
            .prepare_cached("INSERT OR REPLACE INTO allow VALUES(?1, ?2, ?3)")?
            .execute(params![host, reason, at]),
        Row::ApkUrl {
            pkg,
            method,
            url,
            member,
        } => conn
            .prepare_cached("INSERT OR IGNORE INTO apk_url VALUES(?1, ?2, ?3, ?4)")?
            .execute(params![pkg, method, url, member]),
        Row::ZoneDns { zone, kind, value } => conn
            .prepare_cached("INSERT OR IGNORE INTO zonedns VALUES(?1, ?2, ?3)")?
            .execute(params![zone, kind, value]),
    }
}

enum Msg {
    Row(Row),
    Barrier(mpsc::Sender<()>),
}

fn run(path: PathBuf, rx: mpsc::Receiver<Msg>) -> Result<u64> {
    let mut conn = Connection::open(&path)?;
    tune(&conn)?;
    let mut total = 0u64;
    while let Ok(first) = rx.recv() {
        let tx = conn.transaction()?;
        let at = crate::now();
        let mut barriers = Vec::new();
        let mut n = 0usize;
        let mut next = Some(first);
        while let Some(msg) = next.take() {
            match msg {
                Msg::Row(row) => {
                    insert(&tx, row, at)?;
                    n += 1;
                }
                Msg::Barrier(s) => barriers.push(s),
            }
            if n >= BATCH {
                break;
            }
            next = rx.try_recv().ok();
        }
        tx.commit()?;
        for b in barriers {
            let _ = b.send(());
        }
        total += n as u64;
    }
    Ok(total)
}

impl Writer {
    fn spawn(path: &Path) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let path = path.to_path_buf();
        let handle = std::thread::Builder::new()
            .name("stella-writer".into())
            .spawn(move || run(path, rx))?;
        Ok(Self {
            tx,
            handle: std::sync::Arc::new(std::sync::Mutex::new(Some(handle))),
        })
    }

    pub fn send(&self, row: Row) {
        if self.tx.send(Msg::Row(row)).is_err() {
            eprintln!("store: writer stopped");
        }
    }

    pub fn flush(&self) {
        let (tx, rx) = mpsc::channel();
        if self.tx.send(Msg::Barrier(tx)).is_ok() {
            let _ = rx.recv();
        }
    }

    pub fn finish(self) -> Result<u64> {
        let handle = self.handle.lock().ok().and_then(|mut h| h.take());
        drop(self.tx);
        match handle {
            Some(h) => h
                .join()
                .map_err(|_| anyhow::anyhow!("store writer panicked"))?,
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_once_and_refuses_newer_schemas() {
        let conn = Connection::open_in_memory().expect("memory db");
        assert_eq!(migrate(&conn).expect("first"), MIGRATIONS.len() as i64);
        assert_eq!(migrate(&conn).expect("again"), MIGRATIONS.len() as i64);
        conn.pragma_update(None, "user_version", 99).expect("bump");
        assert!(migrate(&conn).is_err());
    }

    #[test]
    fn writes_and_reads() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("stella-store-{}", std::process::id()));
        let store = Store::open(&dir.join("t.db"))?;
        let w = store.writer()?;
        for i in 0..1000 {
            w.send(Row::Done {
                kind: "ct".into(),
                key: format!("z{i}.com"),
            });
        }
        w.send(Row::Name {
            host: "a.example.com".into(),
            regdom: "example.com".into(),
            known: String::new(),
        });
        w.send(Row::Probe {
            host: "a.example.com".into(),
            path: "/".into(),
            addr: "192.0.2.1".into(),
            status: 200,
            ctype: "text/plain".into(),
            server: String::new(),
            cookies: String::new(),
            length: 2,
            head: "ok".into(),
            digest: "00ff".into(),
        });
        assert_eq!(w.finish()?, 1002);
        assert_eq!(store.rows("SELECT digest FROM probe")?[0][0], "00ff");
        assert_eq!(store.done("ct")?.len(), 1000);
        assert_eq!(
            store.rows("SELECT host, regdom FROM name")?[0][1],
            "example.com"
        );
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
