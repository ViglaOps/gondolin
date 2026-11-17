//! Optional, single-attachment Ethernet budget for a supervised netdev.
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// The maximum interval between driver heartbeats on an idle, monitored netdev.
pub const FRAME_HEARTBEAT: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameState {
    Waiting,
    Attached,
    Disconnected,
    Exhausted,
}

/// Point-in-time counters. Each reservation covers one complete Ethernet
/// frame, excluding the transport prefix. TX includes frames admitted to a
/// write that subsequently failed; these counters are not delivery receipts.
#[derive(Clone, Copy, Debug)]
pub struct FrameStats {
    pub state: FrameState,
    /// Guest to host, including frames later rejected by policy or parsing.
    pub rx_bytes: u64,
    /// Host to guest, reserved before issuing the write.
    pub tx_bytes: u64,
    /// Largest number of simultaneous TCP socket entries, including handshakes.
    pub peak_tcp_sockets: usize,
    /// Last poll of the running driver (monotonic host time).
    pub last_heartbeat: Option<Instant>,
}

/// One shared allowance for both directions. A budget cannot be reset or
/// reattached. Dropping the stream marks it disconnected, including on abort.
pub struct FrameBudget {
    limit: u64,
    stats: Mutex<FrameStats>,
    stopped: Notify,
}

impl FrameBudget {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            stats: Mutex::new(FrameStats {
                state: FrameState::Waiting,
                rx_bytes: 0,
                tx_bytes: 0,
                peak_tcp_sockets: 0,
                last_heartbeat: None,
            }),
            stopped: Notify::new(),
        }
    }

    pub fn snapshot(&self) -> FrameStats {
        *self.stats.lock().unwrap()
    }

    /// Returns the latched terminal state, even if the caller subscribed late.
    pub async fn stopped(&self) -> FrameState {
        loop {
            let wait = self.stopped.notified();
            tokio::pin!(wait);
            wait.as_mut().enable();
            let state = self.snapshot().state;
            if matches!(state, FrameState::Exhausted | FrameState::Disconnected) {
                return state;
            }
            wait.await;
        }
    }

    pub(crate) fn attach(&self) -> io::Result<()> {
        let mut s = self.stats.lock().unwrap();
        if s.state != FrameState::Waiting {
            return Err(io::Error::other("frame budget already used"));
        }
        s.state = FrameState::Attached;
        s.last_heartbeat = Some(Instant::now());
        Ok(())
    }

    pub(crate) fn disconnect(&self) {
        let mut s = self.stats.lock().unwrap();
        if s.state == FrameState::Attached {
            s.state = FrameState::Disconnected;
            self.stopped.notify_waiters();
        }
    }

    pub(crate) fn heartbeat(&self) {
        self.stats.lock().unwrap().last_heartbeat = Some(Instant::now());
    }

    pub(crate) fn observe_tcp(&self, sockets: usize) {
        let mut s = self.stats.lock().unwrap();
        s.peak_tcp_sockets = s.peak_tcp_sockets.max(sockets);
    }

    pub(crate) fn reserve(&self, direction: Direction, length: usize) -> io::Result<()> {
        let mut s = self.stats.lock().unwrap();
        if s.state != FrameState::Attached {
            return Err(io::Error::other("frame accounting stopped"));
        }
        let n = length as u64;
        if n > self.limit - s.rx_bytes - s.tx_bytes {
            s.state = FrameState::Exhausted;
            self.stopped.notify_waiters();
            return Err(io::Error::other("Ethernet frame budget exhausted"));
        }
        match direction {
            Direction::Rx => s.rx_bytes += n,
            Direction::Tx => s.tx_bytes += n,
        }
        Ok(())
    }
}

pub(crate) enum Direction {
    Rx,
    Tx,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn concurrent_rx_and_tx_share_one_latched_limit() {
        let budget = Arc::new(FrameBudget::new(403));
        budget.attach().unwrap();
        std::thread::scope(|threads| {
            for i in 0..8 {
                let b = budget.clone();
                threads.spawn(move || {
                    while b
                        .reserve(if i % 2 == 0 { Direction::Rx } else { Direction::Tx }, 4)
                        .is_ok()
                    {}
                });
            }
        });
        let s = budget.snapshot();
        assert_eq!(s.rx_bytes + s.tx_bytes, 400);
        budget.disconnect();
        assert_eq!(budget.stopped().await, FrameState::Exhausted);
        assert!(budget.attach().is_err());
    }
}
