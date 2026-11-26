#![no_main]

use libfuzzer_sys::fuzz_target;
use stella_net::http::Conn;

const BODY_CAP: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().build() else {
        return;
    };
    rt.block_on(async {
        let mut conn = Conn::new(tokio::io::join(data, tokio::io::sink()));
        while conn
            .get("a.example.com", "/", "fuzz", BODY_CAP)
            .await
            .is_ok()
        {}
    });
});
