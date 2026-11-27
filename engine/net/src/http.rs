use std::io::{Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEAD: usize = 32 * 1024;
const MAX_HEADERS: usize = 96;
const READ_CHUNK: usize = 16 * 1024;

#[derive(Clone, Debug, Default)]
pub struct Resp {
    pub status: u16,
    pub ctype: String,
    pub server: String,
    pub location: String,
    pub cookies: Vec<String>,
    pub length: i64,
    pub body: Vec<u8>,
    pub close: bool,
}

pub struct Conn<S> {
    s: S,
    buf: Vec<u8>,
    eof: bool,
}

fn bad(msg: &str) -> Error {
    Error::new(ErrorKind::InvalidData, msg.to_string())
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub fn new(s: S) -> Self {
        Self {
            s,
            buf: Vec::with_capacity(READ_CHUNK),
            eof: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.s
    }

    pub fn get_ref(&self) -> &S {
        &self.s
    }

    async fn fill(&mut self) -> Result<usize> {
        if self.eof {
            return Ok(0);
        }
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let n = self.s.read(&mut self.buf[start..]).await;
        self.buf.truncate(start + *n.as_ref().unwrap_or(&0));
        let n = n?;
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }

    async fn line(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(i) = memchr::memchr(b'\n', &self.buf) {
                let mut l: Vec<u8> = self.buf.drain(..=i).collect();
                while matches!(l.last(), Some(b'\n' | b'\r')) {
                    l.pop();
                }
                return Ok(l);
            }
            if self.buf.len() > MAX_HEAD || self.fill().await? == 0 {
                return Err(bad("line"));
            }
        }
    }

    async fn take(&mut self, n: usize, cap: usize, out: &mut Vec<u8>) -> Result<bool> {
        let mut left = n;
        while left > 0 {
            if self.buf.is_empty() && self.fill().await? == 0 {
                return Err(Error::from(ErrorKind::UnexpectedEof));
            }
            let k = left.min(self.buf.len());
            let room = cap.saturating_sub(out.len());
            out.extend_from_slice(&self.buf[..k.min(room)]);
            self.buf.drain(..k);
            left -= k;
            if out.len() >= cap && left > 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn request(host: &str, path: &str, ua: &str) -> String {
        format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n"
        )
    }

    async fn read_one(&mut self, cap: usize) -> Result<Resp> {
        loop {
            let resp = self.head().await?;
            if (100..200).contains(&resp.0.status) && resp.0.status != 101 {
                continue;
            }
            return self.body(resp, cap).await;
        }
    }

    pub async fn get(&mut self, host: &str, path: &str, ua: &str, cap: usize) -> Result<Resp> {
        self.s
            .write_all(Self::request(host, path, ua).as_bytes())
            .await?;
        self.s.flush().await?;
        self.read_one(cap).await
    }

    pub async fn send_many(&mut self, host: &str, paths: &[&str], ua: &str) -> Result<()> {
        let mut wire = String::new();
        for p in paths {
            wire.push_str(&Self::request(host, p, ua));
        }
        self.s.write_all(wire.as_bytes()).await?;
        self.s.flush().await
    }

    pub async fn read_next(&mut self, cap: usize) -> Result<Resp> {
        self.read_one(cap).await
    }

    pub async fn get_many(
        &mut self,
        host: &str,
        paths: &[&str],
        ua: &str,
        cap: usize,
        got: &mut Vec<Resp>,
    ) -> Result<()> {
        self.send_many(host, paths, ua).await?;
        for _ in paths {
            let r = self.read_one(cap).await?;
            let close = r.close;
            got.push(r);
            if close {
                break;
            }
        }
        Ok(())
    }

    async fn head(&mut self) -> Result<(Resp, Option<usize>, bool, bool)> {
        loop {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut parsed = httparse::Response::new(&mut headers);
            match parsed.parse(&self.buf) {
                Ok(httparse::Status::Complete(used)) => {
                    let mut r = Resp {
                        status: parsed.code.unwrap_or(0),
                        ..Resp::default()
                    };
                    let mut length = None;
                    let mut chunked = false;
                    let mut close = parsed.version == Some(0);
                    for h in parsed.headers.iter() {
                        let v = String::from_utf8_lossy(h.value).trim().to_string();
                        match h.name.to_ascii_lowercase().as_str() {
                            "content-type" => r.ctype = v,
                            "server" => r.server = v,
                            "location" => r.location = v,
                            "set-cookie" => {
                                if let Some((k, _)) = v.split_once('=') {
                                    r.cookies.push(k.trim().to_string());
                                }
                            }
                            "content-length" => length = v.parse::<usize>().ok(),
                            "transfer-encoding" => {
                                chunked = v.to_ascii_lowercase().contains("chunked");
                            }
                            "connection" => close = close || v.eq_ignore_ascii_case("close"),
                            _ => {}
                        }
                    }
                    self.buf.drain(..used);
                    return Ok((r, length, chunked, close));
                }
                Ok(httparse::Status::Partial) => {
                    if self.buf.len() > MAX_HEAD || self.fill().await? == 0 {
                        return Err(bad("head"));
                    }
                }
                Err(_) => return Err(bad("head")),
            }
        }
    }

    async fn body(
        &mut self,
        (mut r, length, chunked, close): (Resp, Option<usize>, bool, bool),
        cap: usize,
    ) -> Result<Resp> {
        r.close = close;
        let empty = matches!(r.status, 204 | 304) || (100..200).contains(&r.status);
        let mut body = Vec::new();
        if empty {
        } else if chunked {
            loop {
                let line = self.line().await?;
                let size = std::str::from_utf8(&line)
                    .ok()
                    .and_then(|l| {
                        usize::from_str_radix(l.split(';').next().unwrap_or("").trim(), 16).ok()
                    })
                    .ok_or_else(|| bad("chunk"))?;
                if size == 0 {
                    while !self.line().await?.is_empty() {}
                    break;
                }
                if self.take(size, cap, &mut body).await? {
                    r.close = true;
                    break;
                }
                self.line().await?;
            }
        } else if let Some(n) = length {
            if self.take(n, cap, &mut body).await? {
                r.close = true;
            }
        } else {
            r.close = true;
            loop {
                let room = cap.saturating_sub(body.len());
                let k = room.min(self.buf.len());
                body.extend_from_slice(&self.buf[..k]);
                self.buf.drain(..k);
                if body.len() >= cap || self.fill().await? == 0 {
                    break;
                }
            }
        }
        r.length = length.map_or(body.len() as i64, |n| n as i64);
        r.body = body;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(wire: &'static [u8], cap: usize) -> Resp {
        let (client, mut server) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let mut sink = [0u8; 4096];
            let _ = server.read(&mut sink).await;
            let _ = server.write_all(wire).await;
        });
        let mut c = Conn::new(client);
        c.get("h", "/", "ua", cap).await.expect("response")
    }

    #[tokio::test]
    async fn reads_lengths_and_chunks() {
        let r = run(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: sp=1; Path=/\r\nContent-Length: 2\r\n\r\nok", 64).await;
        assert_eq!(
            (r.status, r.body.as_slice(), r.cookies[0].as_str()),
            (200, &b"ok"[..], "sp")
        );
        let r = run(b"HTTP/1.1 400 Bad\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", 64).await;
        assert_eq!(
            (r.status, r.body.as_slice(), r.close),
            (400, &b"abcde"[..], false)
        );
        let r = run(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
            64,
        )
        .await;
        assert_eq!((r.status, r.length), (204, 0));
        let r = run(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789",
            4,
        )
        .await;
        assert_eq!(
            (r.body.as_slice(), r.close, r.length),
            (&b"0123"[..], false, 10)
        );
    }

    #[tokio::test]
    async fn reads_pipelined_replies_in_order() {
        let (client, mut server) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let mut sink = [0u8; 4096];
            let _ = server.read(&mut sink).await;
            let _ = server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 404 NF\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 1\r\n\r\nx")
                .await;
        });
        let mut c = Conn::new(client);
        let mut got = Vec::new();
        c.get_many("h", &["/a", "/b", "/c", "/d"], "ua", 64, &mut got)
            .await
            .expect("pipeline");
        let s: Vec<u16> = got.iter().map(|r| r.status).collect();
        assert_eq!(s, [200, 404, 200]);
        assert!(got[2].close);
    }
}
