mod common;

use common::*;
use gondolin_egress::{
    Blocked, BodyChoice, BodyHandle, HookBackend, HookError, IpAllowInfo, RequestDecision,
    RequestHead, ResponseDecision, ResponseHead, full_body,
};
use gondolin_proto::net::{BodyHookRegistration, HookRegistrations, HttpRules, SecretRule};
use http::Response;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

type ReqFn = Box<
    dyn Fn(
            RequestHead,
            Option<BodyHandle>,
        ) -> Pin<Box<dyn Future<Output = Result<RequestDecision, HookError>> + Send>>
        + Send
        + Sync,
>;
type RespFn = Box<
    dyn Fn(
            ResponseHead,
            Option<BodyHandle>,
        ) -> Pin<Box<dyn Future<Output = Result<ResponseDecision, HookError>> + Send>>
        + Send
        + Sync,
>;

#[derive(Default)]
struct Fake {
    regs: HookRegistrations,
    log: Mutex<Vec<String>>,
    deny_request: Option<String>,
    on_request: Option<ReqFn>,
    on_response: Option<RespFn>,
}

impl Fake {
    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl HookBackend for Fake {
    fn registrations(&self) -> HookRegistrations {
        self.regs.clone()
    }

    fn is_request_allowed<'a>(
        &'a self,
        request: &'a RequestHead,
    ) -> gondolin_egress::BoxFuture<'a, Result<bool, HookError>> {
        Box::pin(async move {
            self.log.lock().unwrap().push(format!(
                "is_request_allowed {} {}",
                request.method,
                request.header("authorization").unwrap_or("-")
            ));
            Ok(self.deny_request.is_none()
                || self.deny_request.as_deref() != request.header("authorization"))
        })
    }

    fn is_ip_allowed<'a>(
        &'a self,
        info: &'a IpAllowInfo,
    ) -> gondolin_egress::BoxFuture<'a, Result<bool, HookError>> {
        Box::pin(async move {
            self.log.lock().unwrap().push(format!("is_ip_allowed {} {}", info.hostname, info.ip));
            Ok(true)
        })
    }

    fn on_request<'a>(
        &'a self,
        request: RequestHead,
        body: Option<BodyHandle>,
    ) -> gondolin_egress::BoxFuture<'a, Result<RequestDecision, HookError>> {
        Box::pin(async move {
            self.log.lock().unwrap().push(format!("on_request {}", request.url));
            match &self.on_request {
                Some(f) => f(request, body).await,
                None => Ok(RequestDecision::Continue),
            }
        })
    }

    fn on_response<'a>(
        &'a self,
        response: ResponseHead,
        body: Option<BodyHandle>,
        request: RequestHead,
    ) -> gondolin_egress::BoxFuture<'a, Result<ResponseDecision, HookError>> {
        Box::pin(async move {
            self.log
                .lock()
                .unwrap()
                .push(format!("on_response {} {}", response.status, request.url));
            match &self.on_response {
                Some(f) => f(response, body).await,
                None => Ok(ResponseDecision::Continue),
            }
        })
    }
}

fn all_regs(body: bool) -> HookRegistrations {
    HookRegistrations {
        is_request_allowed: true,
        is_ip_allowed: true,
        on_request: Some(BodyHookRegistration { body }),
        on_response: Some(BodyHookRegistration { body }),
    }
}

fn echo() -> Handler {
    handler(|req| async move {
        let cl = header_text(&req, "content-length").unwrap_or_else(|| "-".into());
        let auth = header_text(&req, "authorization").unwrap_or_else(|| "-".into());
        let data = body_bytes(req).await;
        Response::new(body(format!("cl={cl} auth={auth} body={}", String::from_utf8_lossy(&data))))
    })
}

fn harness(fake: Arc<Fake>, rules: Option<HttpRules>) -> Harness {
    Harness::new(config(rules, None), fake)
}

#[tokio::test]
async fn evaluation_order_with_on_request() {
    let addr = upstream(echo(), None).await;
    let fake = Arc::new(Fake { regs: all_regs(true), ..Fake::default() });
    let h = harness(fake.clone(), None);
    let r = parse(
        &h.raw(format!("GET /a HTTP/1.1\r\nHost: a.test:{}\r\n\r\n", addr.port()).as_bytes()).await,
    );
    assert_eq!(r.status, 200);
    let url = format!("http://a.test:{}/a", addr.port());
    assert_eq!(
        fake.log(),
        vec![
            format!("on_request {url}"),
            "is_request_allowed GET -".into(),
            // resolve check, then the connect-time check of the new connection
            "is_ip_allowed a.test 127.0.0.1".into(),
            "is_ip_allowed a.test 127.0.0.1".into(),
            format!("on_response 200 {url}"),
        ]
    );
}

#[tokio::test]
async fn prechecked_policy_runs_once_and_rechecks_after_secrets() {
    let addr = upstream(echo(), None).await;
    let fake = Arc::new(Fake {
        regs: HookRegistrations {
            is_request_allowed: true,
            is_ip_allowed: true,
            ..Default::default()
        },
        deny_request: Some("Bearer secret-value".into()),
        ..Fake::default()
    });
    let marker = "cd".repeat(24);
    let rules = HttpRules {
        block_internal_ranges: false,
        marker: Some(marker.clone()),
        secrets: vec![SecretRule {
            name: "API_KEY".into(),
            identifier: "api_key".into(),
            placeholder: format!("{marker}.api_key"),
            value: "secret-value".into(),
            hosts: vec!["a.test".into()],
            ..Default::default()
        }],
        ..HttpRules::default()
    };
    let h = harness(fake.clone(), Some(rules));

    let r = parse(
        &h.raw(format!("GET /ok HTTP/1.1\r\nHost: a.test:{}\r\n\r\n", addr.port()).as_bytes())
            .await,
    );
    assert_eq!(r.status, 200);
    assert_eq!(
        fake.log(),
        vec![
            "is_request_allowed GET -".to_string(),
            "is_ip_allowed a.test 127.0.0.1".into(),
            "is_ip_allowed a.test 127.0.0.1".into(),
        ]
    );

    fake.log.lock().unwrap().clear();
    let r = parse(
        &h.raw(
            format!(
                "GET /ok HTTP/1.1\r\nHost: a.test:{}\r\nAuthorization: Bearer {marker}.api_key\r\n\r\n",
                addr.port()
            )
            .as_bytes(),
        )
        .await,
    );
    assert_eq!(r.status, 403);
    assert_eq!(r.text(), "403 Forbidden: blocked by request policy\n");
    assert_eq!(
        fake.log(),
        vec![
            format!("is_request_allowed GET Bearer {marker}.api_key"),
            "is_ip_allowed a.test 127.0.0.1".into(),
            "is_request_allowed GET Bearer secret-value".into(),
        ]
    );
}

#[tokio::test]
async fn short_circuit_skips_policy_and_upstream() {
    let fake = Arc::new(Fake {
        regs: all_regs(false),
        on_request: Some(Box::new(|_req, _body| {
            Box::pin(async {
                Ok(RequestDecision::Respond {
                    head: ResponseHead {
                        status: 200,
                        status_text: "OK".into(),
                        headers: vec![("x-synthetic".into(), "1".into())],
                    },
                    body: BodyChoice::Body(full_body("network-ok\n")),
                })
            })
        })),
        ..Fake::default()
    });
    let h = harness(fake.clone(), None);
    h.resolver.fail.lock().unwrap().push("example.com".into());
    let r = parse(&h.raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await);
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), "network-ok\n");
    assert_eq!(r.header("x-synthetic"), Some("1"));
    assert_eq!(r.header("content-length"), Some("11"));
    assert_eq!(fake.log(), vec!["on_request http://example.com/".to_string()]);
}

#[tokio::test]
async fn request_body_clone_read_keeps_forwarded_body() {
    let addr = upstream(echo(), None).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let fake = Arc::new(Fake {
        regs: HookRegistrations {
            on_request: Some(BodyHookRegistration { body: true }),
            ..Default::default()
        },
        on_request: Some(Box::new(move |_req, body| {
            let seen = seen2.clone();
            Box::pin(async move {
                let b = body.unwrap().read_to_end().await.unwrap();
                seen.lock().unwrap().extend_from_slice(&b);
                Ok(RequestDecision::Continue)
            })
        })),
        ..Fake::default()
    });
    let h = harness(fake, Some(open_rules()));
    let r = parse(
        &h.raw(
            format!(
                "POST /s HTTP/1.1\r\nHost: a.test:{}\r\nContent-Length: 5\r\n\r\nhello",
                addr.port()
            )
            .as_bytes(),
        )
        .await,
    );
    assert_eq!(r.text(), "cl=5 auth=- body=hello");
    assert_eq!(&seen.lock().unwrap()[..], b"hello");
}

#[tokio::test]
async fn request_body_untouched_is_streamed() {
    let addr = upstream(echo(), None).await;
    let fake = Arc::new(Fake {
        regs: HookRegistrations {
            on_request: Some(BodyHookRegistration { body: true }),
            ..Default::default()
        },
        ..Fake::default()
    });
    let mut cfg = config(Some(open_rules()), None);
    cfg.limits.max_request_body_bytes = 10;
    let h = Harness::new(cfg, fake);
    let r = parse(
        &h.raw(
            format!(
                "POST /s HTTP/1.1\r\nHost: a.test:{}\r\nContent-Length: 5\r\n\r\nhello",
                addr.port()
            )
            .as_bytes(),
        )
        .await,
    );
    assert_eq!(r.text(), "cl=5 auth=- body=hello");
}

#[tokio::test]
async fn request_rewrite_with_new_body() {
    let addr = upstream(echo(), None).await;
    let fake = Arc::new(Fake {
        regs: HookRegistrations {
            on_request: Some(BodyHookRegistration { body: true }),
            ..Default::default()
        },
        on_request: Some(Box::new(|mut req, _body| {
            Box::pin(async move {
                req.set_header("authorization", "rewritten");
                Ok(RequestDecision::Request {
                    head: req,
                    body: BodyChoice::Body(full_body("replaced body")),
                })
            })
        })),
        ..Fake::default()
    });
    let h = harness(fake, Some(open_rules()));
    let r = parse(
        &h.raw(
            format!(
                "POST /s HTTP/1.1\r\nHost: a.test:{}\r\nContent-Length: 5\r\n\r\nhello",
                addr.port()
            )
            .as_bytes(),
        )
        .await,
    );
    assert_eq!(r.text(), "cl=13 auth=rewritten body=replaced body");
}

#[tokio::test]
async fn hook_block_and_failure() {
    let fake = Arc::new(Fake {
        regs: all_regs(false),
        on_request: Some(Box::new(|_req, _body| {
            Box::pin(async {
                Err(HookError::Blocked(Blocked::new(451, "Unavailable For Legal Reasons", "nope")))
            })
        })),
        ..Fake::default()
    });
    let h = harness(fake, None);
    let r = parse(&h.raw(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await);
    assert_eq!(r.status, 451);
    assert_eq!(r.text(), "451 Unavailable For Legal Reasons: nope\n");

    let fake = Arc::new(Fake {
        regs: all_regs(false),
        on_request: Some(Box::new(|_req, _body| {
            Box::pin(async { Err(HookError::Failed("boom".into())) })
        })),
        ..Fake::default()
    });
    let h = harness(fake, None);
    let r = parse(&h.raw(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await);
    assert_eq!(r.status, 502);
}

#[tokio::test]
async fn get_with_body_rejected_when_on_request_registered() {
    let fake = Arc::new(Fake { regs: all_regs(true), ..Fake::default() });
    let h = harness(fake, Some(open_rules()));
    let r = parse(&h.raw(b"GET / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nhi").await);
    assert_eq!(r.status, 400);
    assert_eq!(r.text(), "400 Bad Request: request body not allowed for GET in web hooks\n");
}

#[tokio::test]
async fn response_hook_rewrites_body() {
    let addr = upstream(echo(), None).await;
    let fake = Arc::new(Fake {
        regs: HookRegistrations {
            on_response: Some(BodyHookRegistration { body: true }),
            ..Default::default()
        },
        on_response: Some(Box::new(|mut head, body| {
            Box::pin(async move {
                let data = body.unwrap().read_to_end().await.unwrap();
                head.set_header("x-hooked", "1");
                let upper = String::from_utf8_lossy(&data).to_uppercase();
                Ok(ResponseDecision::Response { head, body: BodyChoice::Body(full_body(upper)) })
            })
        })),
        ..Fake::default()
    });
    let h = harness(fake, Some(open_rules()));
    let r = parse(
        &h.raw(format!("GET / HTTP/1.1\r\nHost: a.test:{}\r\n\r\n", addr.port()).as_bytes()).await,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), "CL=- AUTH=- BODY=");
    assert_eq!(r.header("x-hooked"), Some("1"));
    assert_eq!(r.header("content-length"), Some("17"));
}

#[tokio::test]
async fn response_hook_without_reading_streams_large_bodies() {
    let addr = upstream(
        handler(|_req| async move { Response::new(body(vec![b'q'; 4 * 1024 * 1024])) }),
        None,
    )
    .await;
    let fake = Arc::new(Fake {
        regs: HookRegistrations {
            on_response: Some(BodyHookRegistration { body: true }),
            ..Default::default()
        },
        ..Fake::default()
    });
    let mut cfg = config(Some(open_rules()), None);
    cfg.limits.max_response_body_bytes = 1024;
    let h = Harness::new(cfg, fake.clone());
    let r = parse(
        &h.raw(format!("GET / HTTP/1.1\r\nHost: a.test:{}\r\n\r\n", addr.port()).as_bytes()).await,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), 4 * 1024 * 1024);
    assert_eq!(fake.log().len(), 1);
}

#[tokio::test]
async fn response_hook_partial_read_is_replayed() {
    let addr =
        upstream(handler(|_req| async move { Response::new(body("0123456789")) }), None).await;
    let fake = Arc::new(Fake {
        regs: HookRegistrations {
            on_response: Some(BodyHookRegistration { body: true }),
            ..Default::default()
        },
        on_response: Some(Box::new(|_head, body| {
            Box::pin(async move {
                let first = body.unwrap().pull(4).await.unwrap().unwrap();
                assert_eq!(&first[..], b"0123");
                Ok(ResponseDecision::Continue)
            })
        })),
        ..Fake::default()
    });
    let h = harness(fake, Some(open_rules()));
    let r = parse(
        &h.raw(format!("GET / HTTP/1.1\r\nHost: a.test:{}\r\n\r\n", addr.port()).as_bytes()).await,
    );
    assert_eq!(r.text(), "0123456789");
    assert_eq!(r.header("content-length"), Some("10"));
}

#[tokio::test]
async fn response_hook_read_over_limit_is_502() {
    let addr =
        upstream(handler(|_req| async move { Response::new(body(vec![b'q'; 4096])) }), None).await;
    let fake = Arc::new(Fake {
        regs: HookRegistrations {
            on_response: Some(BodyHookRegistration { body: true }),
            ..Default::default()
        },
        on_response: Some(Box::new(|_head, body| {
            Box::pin(async move {
                match body.unwrap().read_to_end().await {
                    Ok(_) => Ok(ResponseDecision::Continue),
                    Err(gondolin_egress::PullError::Limit(b)) => Err(HookError::Blocked(b)),
                    Err(e) => Err(HookError::Failed(e.to_string())),
                }
            })
        })),
        ..Fake::default()
    });
    let mut cfg = config(Some(open_rules()), None);
    cfg.limits.max_response_body_bytes = 1024;
    let h = Harness::new(cfg, fake);
    let r = parse(
        &h.raw(format!("GET / HTTP/1.1\r\nHost: a.test:{}\r\n\r\n", addr.port()).as_bytes()).await,
    );
    assert_eq!(r.status, 502);
    assert_eq!(r.text(), "502 Bad Gateway: response body exceeds 1024 bytes\n");
}

#[tokio::test]
async fn websocket_prechecked_request_policy_runs_once() {
    let fake = Arc::new(Fake {
        regs: HookRegistrations { is_request_allowed: true, ..Default::default() },
        ..Fake::default()
    });
    let h = harness(fake.clone(), Some(open_rules()));
    // upstream refuses; we only care about policy calls
    let _ = h
        .raw(b"GET / HTTP/1.1\r\nHost: a.test:1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n")
        .await;
    assert_eq!(fake.log(), vec!["is_request_allowed GET -".to_string()]);
}

#[tokio::test]
async fn remote_hook_receives_original_tls_request_on_each_hop() {
    use gondolin_egress::{BoxFuture, ControllerLink, RemoteHooks};
    use gondolin_proto::net::{BodyChunk, BodyPull, HookCall, HookDecision};
    use tokio::io::AsyncWriteExt;

    #[derive(Default)]
    struct Capture(Mutex<Vec<HookCall>>);
    impl ControllerLink for Capture {
        fn hook_call<'a>(&'a self, call: HookCall) -> BoxFuture<'a, Result<HookDecision, String>> {
            self.0.lock().unwrap().push(call);
            Box::pin(async { Ok(HookDecision::Continue) })
        }
        fn body_pull<'a>(&'a self, _: BodyPull) -> BoxFuture<'a, Result<BodyChunk, String>> {
            unreachable!()
        }
        fn body_release(&self, _: u64) {}
    }

    let ca = TestCa::new("context test");
    let receiver = upstream(
        handler(|req| async move {
            if req.uri().path() == "/final" {
                Response::new(body("done"))
            } else {
                Response::builder().status(303).header("location", "/final").body(body("")).unwrap()
            }
        }),
        Some(ca.server_config(&["service.test"])),
    )
    .await;
    let calls = Arc::new(Capture::default());
    let regs = HookRegistrations {
        on_request: Some(BodyHookRegistration { body: true }),
        ..Default::default()
    };
    let remote = RemoteHooks::new(calls.clone(), regs);
    let mut cfg = config(Some(open_rules()), Some(&ca));
    cfg.request_context = true;
    let h = Harness::new(cfg, Arc::new(remote));
    let mut client = h.tls(&ca, "proxy.test").await;
    let target = format!("https://service.test:{}/a%2Fb?k=1&k=2", receiver.port());
    let request = format!(
        "POST {target} HTTP/1.1\r\nHost: proxy.test\r\nX-Test: one\r\nX-Test: two\r\nContent-Length: 3\r\n\r\nabc"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    assert_eq!(parse(&read_to_end(&mut client).await).text(), "done");
    let calls = calls.0.lock().unwrap();
    assert_eq!(calls.len(), 2);
    for (hop, call) in calls.iter().enumerate() {
        let ctx = call.original.as_ref().unwrap();
        assert_eq!(ctx.flow_id, 1);
        assert_eq!(ctx.sni.as_deref(), Some("proxy.test"));
        assert_eq!(ctx.destination_port, 443);
        assert_eq!((&*ctx.scheme, &*ctx.version, &*ctx.method), ("https", "HTTP/1.1", "POST"));
        assert_eq!(ctx.target, target);
        assert_eq!(
            ctx.headers,
            [
                ("host".into(), "proxy.test".into()),
                ("x-test".into(), "one".into()),
                ("x-test".into(), "two".into()),
                ("content-length".into(), "3".into())
            ]
        );
        assert_eq!(ctx.redirect_hop, hop as u32);
    }
    let head = calls[0].request.as_ref().unwrap();
    assert!(head.body.is_some());
    assert!(head.body_prefix.is_none());
    assert!(!head.body_complete);
    assert_eq!(calls[1].request.as_ref().unwrap().method, "GET");
}
