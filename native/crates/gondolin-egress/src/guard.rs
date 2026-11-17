//! Optional terminal failure signal for supervised HTTP(S)-only egress.
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

/// Redacted, host-visible cause of the first terminal failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressFailure {
    Protocol,
    Request,
    Limit,
    Policy,
    GuestTls,
    UpstreamTls,
    Upstream,
    Controller,
}

/// One latch per invocation. A late subscriber observes the same first cause.
#[derive(Default)]
pub struct HttpEgressGuard {
    failure: watch::Sender<Option<EgressFailure>>,
}

impl HttpEgressGuard {
    pub fn failure(&self) -> Option<EgressFailure> {
        *self.failure.borrow()
    }

    pub fn stop(&self, cause: EgressFailure) {
        self.failure.send_if_modified(|state| {
            if state.is_some() {
                return false;
            }
            *state = Some(cause);
            true
        });
    }

    pub async fn stopped(&self) -> EgressFailure {
        let mut state = self.failure.subscribe();
        state.wait_for(Option::is_some).await.expect("sender is borrowed").unwrap()
    }

    // Also guards pooled connections and body writers completing after an
    // early upstream response. Serialize each nonblocking syscall with stop.
    pub(crate) fn protect<S>(self: &Arc<Self>, socket: S) -> GuardedSocket<S> {
        GuardedSocket { socket, guard: self.clone() }
    }
}

pub(crate) struct GuardedSocket<S> {
    socket: S,
    guard: Arc<HttpEgressGuard>,
}

impl<S> GuardedSocket<S> {
    fn poll_io<T>(
        &mut self,
        op: impl FnOnce(&mut S) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let state = self.guard.failure.borrow();
        if state.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "egress stopped",
            )));
        }
        op(&mut self.socket)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GuardedSocket<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_io(|s| Pin::new(s).poll_read(cx, buf))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GuardedSocket<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_io(|s| Pin::new(s).poll_write(cx, buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_io(|s| Pin::new(s).poll_flush(cx))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn previous_and_future_writers_cannot_emit_after_stop() {
        let guard = Arc::new(HttpEgressGuard::default());
        let (a, mut peer) = tokio::io::duplex(8);
        let mut socket = guard.protect(a);
        socket.write_all(b"allowed").await.unwrap();
        guard.stop(EgressFailure::Controller);
        guard.stop(EgressFailure::Request);
        assert_eq!(guard.stopped().await, EgressFailure::Controller);
        assert!(socket.write_all(b"late").await.is_err());
        drop(socket);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"allowed");
    }
}
