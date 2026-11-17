//! In-process controller: the session runs in the caller's tokio runtime and
//! the controller exchanges [`RawEnvelope`]s with it directly (no process, no
//! pipe). Used by the static `gondolin` CLI (`gondolin-cli`); the protocol
//! is the one the TypeScript controller speaks over stdio.

use std::path::PathBuf;
use std::sync::Arc;

use gondolin_wire::RawEnvelope;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::controller::{Controller, Dispatcher};
use crate::qemu::HostInfo;
use crate::session::Session;
use crate::{mitm_ca, panics, vmm};

/// Host-controlled options for an in-process session.
#[derive(Default)]
pub struct EmbeddedOptions {
    /// Exact directory for this session's sockets and temporary disk. Its
    /// parent must exist and be trusted. On start the engine exclusively
    /// creates the directory with mode 0700 and removes it on teardown.
    /// Relative paths require a stable working directory (including in the
    /// VMM child). Keep the socket names within the platform sun_path limit.
    pub runtime_directory: Option<PathBuf>,
    /// Hostname resolver for native upstream HTTP(S) connections. An injected
    /// resolver is authoritative, including on errors. Guest DNS stays under
    /// the netstack configuration.
    pub upstream_resolver: Option<Arc<dyn gondolin_egress::Resolver>>,
    /// Optional single-attachment frame budget with a direct terminal notification.
    pub frame_budget: Option<Arc<gondolin_netstack::budget::FrameBudget>>,
    /// In-process HTTP hooks, mutually exclusive with JavaScript and remote callbacks.
    /// Request/response data stays inside the trusted host process.
    pub http_hooks: Option<Arc<dyn gondolin_egress::HookBackend>>,
    /// Optional terminal failure latch for HTTP(S)-only egress.
    pub http_egress_guard: Option<Arc<gondolin_egress::HttpEgressGuard>>,
}

/// A running in-process session.
pub struct Embedded {
    ctl: Arc<Controller>,
    dispatcher: Dispatcher,
    session_tx: Option<mpsc::Sender<RawEnvelope>>,
    task: Option<JoinHandle<()>>,
}

impl Embedded {
    /// Starts a session. The first message from [`Embedded::next`] is `hello`.
    pub fn start() -> Embedded {
        Self::start_with_options(EmbeddedOptions::default())
    }

    /// Starts a session with caller-selected host resources.
    pub fn start_with_options(options: EmbeddedOptions) -> Embedded {
        let ctl = Controller::new();
        let dispatcher = Dispatcher::default();
        crate::send_hello(&ctl);
        dispatcher.register(mitm_ca::MITM_CA, Arc::new(mitm_ca::MitmCaHandler));
        let (mut session, channels) =
            Session::new(ctl.clone(), dispatcher.clone(), HostInfo::detect());
        session.embedded = options;
        let (session_tx, session_rx) = mpsc::channel(64);
        let session_task = tokio::spawn(session.run(channels, session_rx));
        // fail closed like the daemon: a panicking session kills the VMM and
        // reports an `exit` with the reason
        let supervisor = {
            let ctl = ctl.clone();
            tokio::spawn(async move {
                if let Err(err) = session_task.await {
                    let reason = match err.try_into_panic() {
                        Ok(payload) => format!(
                            "session task panicked: {}",
                            panics::payload_message(payload.as_ref())
                        ),
                        Err(err) => format!("session task failed: {err}"),
                    };
                    vmm::kill_current();
                    ctl.send(
                        gondolin_proto::session::EXIT,
                        0,
                        &gondolin_proto::session::Exit {
                            code: None,
                            signal: None,
                            error: Some(format!("internal error, VM stopped: {reason}")),
                        },
                    );
                }
                // let the controller drain what is queued, then end `next()`
                let drain = async {
                    while ctl.queued_bytes() > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                };
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), drain).await;
                ctl.close();
            })
        };
        Embedded { ctl, dispatcher, session_tx: Some(session_tx), task: Some(supervisor) }
    }

    /// Delivers one controller message. Returns `false` once the session ended.
    pub async fn send(&self, msg: RawEnvelope) -> bool {
        let Some(tx) = &self.session_tx else { return false };
        self.dispatcher.dispatch(msg, &self.ctl, tx).await
    }

    /// The next daemon message; `None` once the session ended.
    pub async fn next(&self) -> Option<RawEnvelope> {
        loop {
            let frame = self.ctl.next_frame().await?;
            match gondolin_wire::decode(&frame[4..]) {
                Ok(msg) => return Some(msg),
                Err(err) => eprintln!("gondolin: dropping undecodable daemon message: {err}"),
            }
        }
    }

    /// A handle that can deliver messages from other tasks.
    pub fn sender(&self) -> EmbeddedSender {
        EmbeddedSender {
            ctl: self.ctl.clone(),
            dispatcher: self.dispatcher.clone(),
            session_tx: self.session_tx.clone(),
        }
    }

    /// Ends the session as if the controller disconnected (the VMM is
    /// stopped) and waits for it.
    pub async fn close(mut self) {
        self.session_tx = None;
        if let Some(task) = self.task.take() {
            // the session ends once every sender is gone (`EmbeddedSender`s
            // included), then drains
            let _ = task.await;
        }
        vmm::kill_current();
    }
}

/// Cloneable sending half of an [`Embedded`] session.
#[derive(Clone)]
pub struct EmbeddedSender {
    ctl: Arc<Controller>,
    dispatcher: Dispatcher,
    session_tx: Option<mpsc::Sender<RawEnvelope>>,
}

impl EmbeddedSender {
    /// Delivers one controller message. Returns `false` once the session ended.
    pub async fn send(&self, msg: RawEnvelope) -> bool {
        let Some(tx) = &self.session_tx else { return false };
        self.dispatcher.dispatch(msg, &self.ctl, tx).await
    }
}

#[cfg(test)]
mod tests {
    use gondolin_wire::{Envelope, Value};

    use super::*;

    #[tokio::test]
    async fn hello_requests_and_close() {
        crate::test_timeout(async {
            let e = Embedded::start();
            let hello = e.next().await.unwrap();
            assert_eq!(hello.t, "hello");
            // a request the session answers without a VM
            assert!(e.send(Envelope::new("start", 7, Value::Map(vec![]))).await);
            let reply = e.next().await.unwrap();
            assert_eq!((reply.t.as_str(), reply.id), ("start_result", 7));
            // senders from other tasks work too
            let sender = e.sender();
            assert!(sender.send(Envelope::new("bogus", 0, Value::Map(vec![]))).await);
            let err = e.next().await.unwrap();
            assert_eq!(err.t, "error");
            drop(sender);
            e.close().await;
        })
        .await;
    }
}
