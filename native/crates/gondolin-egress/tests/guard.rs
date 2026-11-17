mod common;

use common::*;
use gondolin_egress::{Egress, EgressFailure, HttpEgressGuard, NoHooks};
use gondolin_proto::net::NetConfig;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn supervised(mut config: NetConfig) -> (Harness, Arc<HttpEgressGuard>) {
    config.policy.allow_websockets = false;
    let guard = Arc::new(HttpEgressGuard::default());
    let resolver = Arc::new(TestResolver::default());
    let egress = Egress::with_options(
        config,
        Arc::new(NoHooks),
        Some(resolver.clone()),
        Some(guard.clone()),
    )
    .unwrap();
    (Harness { egress, resolver }, guard)
}

#[tokio::test]
async fn malformed_head_cancels_waiting_and_future_flows_without_callback() {
    let (h, guard) = supervised(config(Some(open_rules()), None));
    let (mut idle, idle_abort) = h.open(80);
    idle.write_all(b"GET /").await.unwrap();
    let reply =
        h.raw(b"GET / HTTP/1.1\r\nHost: example.org\r\nX header: private-canary\r\n\r\n").await;
    assert_eq!(guard.failure(), Some(EgressFailure::Request));
    assert!(!String::from_utf8_lossy(&reply).contains("private-canary"));
    let (late, late_abort) = h.open(80);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !idle_abort.0.load(Ordering::SeqCst) || !late_abort.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(late);
    assert_eq!(h.resolver.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn upstream_error_status_is_data_but_truncated_or_oversize_bodies_are_terminal() {
    use http::Response;
    let server = upstream(
        handler(|_| async { Response::builder().status(403).body(body("abcdef")).unwrap() }),
        None,
    )
    .await;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: test.invalid:{}\r\nConnection: close\r\n\r\n",
        server.port()
    );
    let (h, guard) = supervised(config(Some(open_rules()), None));
    assert_eq!(parse(&h.raw(req.as_bytes()).await).status, 403);
    assert_eq!(guard.failure(), None);
    let mut cfg = config(Some(open_rules()), None);
    cfg.limits.max_response_body_bytes = 5;
    let (h, guard) = supervised(cfg);
    h.raw(req.as_bytes()).await;
    assert_eq!(guard.failure(), Some(EgressFailure::Limit));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut upstream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(upstream.read_u8().await.unwrap());
        }
        upstream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").await.unwrap();
        upstream.shutdown().await.unwrap();
    });
    let (h, guard) = supervised(config(Some(open_rules()), None));
    h.raw(
        format!("GET / HTTP/1.1\r\nHost: test.invalid:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert_eq!(guard.failure(), Some(EgressFailure::Upstream));
}

#[tokio::test]
async fn malformed_sibling_drops_an_in_flight_request_before_upstream_connect() {
    use gondolin_egress::{
        BodyHandle, BoxFuture, HookBackend, HookError, RequestDecision, RequestHead,
    };
    use gondolin_proto::net::{BodyHookRegistration, HookRegistrations};
    use tokio::sync::Notify;

    #[derive(Default)]
    struct PendingHook {
        entered: Notify,
        release: Notify,
    }
    impl HookBackend for PendingHook {
        fn registrations(&self) -> HookRegistrations {
            HookRegistrations {
                on_request: Some(BodyHookRegistration { body: false }),
                ..Default::default()
            }
        }
        fn on_request<'a>(
            &'a self,
            _: RequestHead,
            _: Option<BodyHandle>,
        ) -> BoxFuture<'a, Result<RequestDecision, HookError>> {
            Box::pin(async move {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(RequestDecision::Continue)
            })
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = config(Some(open_rules()), None);
    cfg.policy.allow_websockets = false;
    let guard = Arc::new(HttpEgressGuard::default());
    let hooks = Arc::new(PendingHook::default());
    let resolver = Arc::new(TestResolver::default());
    let egress =
        Egress::with_options(cfg, hooks.clone(), Some(resolver.clone()), Some(guard.clone()))
            .unwrap();
    let h = Harness { egress, resolver };
    let (mut active, abort) = h.open(80);
    active
        .write_all(format!("GET / HTTP/1.1\r\nHost: example.test:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), hooks.entered.notified()).await.unwrap();
    h.raw(b"GET / HTTP/1.1\r\nBad field: x\r\n\r\n").await;
    assert_eq!(guard.failure(), Some(EgressFailure::Request));
    hooks.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !abort.0.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(h.resolver.calls.load(Ordering::SeqCst), 0);
    assert!(tokio::time::timeout(Duration::from_millis(50), listener.accept()).await.is_err());
}
