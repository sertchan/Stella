use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

pub const HANDSHAKES: usize = 200;

pub struct Limiter {
    open: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
    gap: Duration,
    next: Mutex<Instant>,
}

impl Limiter {
    pub fn new(concurrent: usize, new_per_second: u32) -> Arc<Self> {
        Self::with_handshakes(concurrent, new_per_second, HANDSHAKES)
    }

    pub fn with_handshakes(concurrent: usize, new_per_second: u32, handshakes: usize) -> Arc<Self> {
        Arc::new(Self {
            open: Arc::new(Semaphore::new(concurrent.max(1))),
            handshakes: Arc::new(Semaphore::new(handshakes.max(1))),
            gap: Duration::from_secs(1) / new_per_second.max(1),
            next: Mutex::new(Instant::now()),
        })
    }

    pub async fn slot(&self) -> Option<OwnedSemaphorePermit> {
        let permit = self.open.clone().acquire_owned().await.ok()?;
        self.pace().await;
        Some(permit)
    }

    pub async fn handshake(&self) -> Option<OwnedSemaphorePermit> {
        self.handshakes.clone().acquire_owned().await.ok()
    }

    pub async fn pace(&self) {
        let at = match self.next.lock() {
            Ok(mut n) => {
                let now = Instant::now();
                let at = (*n).max(now);
                *n = at + self.gap;
                at
            }
            Err(_) => Instant::now(),
        };
        tokio::time::sleep_until(at).await;
    }
}
