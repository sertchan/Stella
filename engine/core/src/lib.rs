pub mod category;
pub mod config;
pub mod digest;
pub mod known;
pub mod list;
pub mod md5;
pub mod name;
pub mod progress;
pub mod public_suffix;
pub mod random;
pub mod store;
pub mod time;
pub mod token;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
