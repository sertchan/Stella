use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

pub struct Limiter {
    sem: Arc<Semaphore>,
    gap: Duration,
    next: Mutex<Instant>,
}

impl Limiter {
    pub fn new(concurrent: usize, new_per_second: u32) -> Arc<Self> {
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(concurrent.max(1))),
            gap: Duration::from_secs(1) / new_per_second.max(1),
            next: Mutex::new(Instant::now()),
        })
    }

    pub async fn slot(&self) -> Option<OwnedSemaphorePermit> {
        let permit = self.sem.clone().acquire_owned().await.ok()?;
        self.pace().await;
        Some(permit)
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
