pub mod config;
pub mod known;
pub mod name;
pub mod progress;
pub mod psl;
pub mod rng;
pub mod shape;
pub mod store;
pub mod token;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
