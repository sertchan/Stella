#![no_main]

use libfuzzer_sys::fuzz_target;
use stella_dns::{chase, wire};

fuzz_target!(|data: &[u8]| {
    if let Some(msg) = wire::parse(data) {
        let _ = chase::follow(&msg, "a.example.com");
    }
    let _ = wire::labels(&String::from_utf8_lossy(data));
});
