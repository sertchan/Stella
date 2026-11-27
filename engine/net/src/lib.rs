pub mod client;
pub mod http;
pub mod limiter;
pub mod tls;

pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
