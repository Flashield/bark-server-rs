//! Local HTTPS HTTP/2 APNs stub: the configured `--apns-endpoint` stand-in.
//!
//! Per the spec's testing decision, the only APNs seam is the endpoint: this
//! stub terminates TLS (self-signed rcgen certificate, ALPN h2 like Apple's
//! servers) and mirrors the APNs provider API surface the server uses —
//! `POST /3/device/{token}`. Every request is recorded (protocol version,
//! headers, JSON payload) into a buffer the test reads directly; the canned
//! response is selected by the device token so each test targets its own
//! outcome without cross-talk:
//!
//! - token contains `unregistered`     → 410 `{"reason": "Unregistered"}`
//! - token contains `baddevicetoken`   → 400 `{"reason": "BadDeviceToken"}`
//! - token contains `internalerror`    → 500 `{"reason": "InternalServerError"}`
//! - token contains `toomanyrequests`  → 429 `{"reason": "TooManyRequests"}`
//! - token contains `notopic`          → 403 `{"reason": "DeviceTokenNotForTopic"}`
//! - anything else                     → 200 `{}` (accepted)
//!
//! No request ever leaves the machine — Apple's real endpoints are never
//! touched in tests.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::{free_port, tls_client};

/// One recorded APNs push request: the wire facts a test can assert on.
#[derive(Debug, Clone, Serialize)]
pub struct RecordedPush {
    /// Request path, e.g. `/3/device/PUSHTOKEN1`.
    pub path: String,
    /// Protocol version the client negotiated (`HTTP/2.0` for a real APNs
    /// client, which always speaks HTTP/2).
    pub http_version: String,
    pub content_type: String,
    /// Raw `authorization` header (`bearer <jwt>`).
    pub authorization: String,
    pub apns_topic: Option<String>,
    /// `apns-id` — upstream apns2 never sends it (no ApnsID set); recorded
    /// so tests can assert its absence.
    pub apns_id: Option<String>,
    pub apns_collapse_id: Option<String>,
    /// `apns-priority` — upstream never sets it (Priority 0 → header
    /// omitted); recorded so tests can assert its absence.
    pub apns_priority: Option<String>,
    /// Unix seconds as sent in `apns-expiration`.
    pub apns_expiration: Option<String>,
    pub apns_push_type: Option<String>,
    /// The JSON payload body.
    pub payload: Value,
}

/// Handle over a spawned stub: its base URL, the recording buffer, and the
/// shutdown controls.
pub struct ApnsStub {
    /// `https://127.0.0.1:<port>` — feed this to `config.apns_endpoint`.
    pub url: String,
    requests: Arc<Mutex<Vec<RecordedPush>>>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: JoinHandle<()>,
}

impl ApnsStub {
    /// Snapshot of every request received so far, oldest first.
    pub fn pushes(&self) -> Vec<RecordedPush> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn push_count(&self) -> usize {
        self.pushes().len()
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.handle.await;
    }
}

impl ApnsStub {
    /// Spawn a stub on an ephemeral local port with a self-signed certificate.
    pub async fn spawn() -> ApnsStub {
        // rustls needs a process-level provider; axum_server builds its
        // ServerConfig with the process default. Idempotent — a no-op when the
        // server under test already installed one.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let requests: Arc<Mutex<Vec<RecordedPush>>> = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/3/device/{token}", post(apns_device_push))
            .route("/_health", get(|| async { "ok" }))
            .with_state(requests.clone());

        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate self-signed stub certificate");
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            certified_key.cert.pem().into_bytes(),
            certified_key.signing_key.serialize_pem().into_bytes(),
        )
        .await
        .expect("build stub TLS config");

        let addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
        let url = format!("https://{addr}");

        let (tx, rx) = oneshot::channel::<()>();
        let axum_handle = axum_server::Handle::new();
        let axum_handle_for_watcher = axum_handle.clone();
        tokio::spawn(async move {
            let _ = rx.await;
            axum_handle_for_watcher.shutdown();
        });
        let handle = tokio::spawn(async move {
            axum_server::bind_rustls(addr, tls)
                .handle(axum_handle)
                .serve(app.into_make_service())
                .await
                .expect("APNs stub server error");
        });

        // Readiness: TLS + HTTP round-trip against the health route.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "APNs stub at {url} did not become ready in time"
            );
            match tls_client().get(format!("{url}/_health")).send().await {
                Ok(res) if res.status().is_success() => break,
                Ok(res) => eprintln!("apns_stub readiness: status {}", res.status()),
                Err(err) => eprintln!("apns_stub readiness: {err}"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        ApnsStub {
            url,
            requests,
            shutdown: Some(tx),
            handle,
        }
    }
}

async fn apns_device_push(
    State(requests): State<Arc<Mutex<Vec<RecordedPush>>>>,
    axum::extract::Path(token): axum::extract::Path<String>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .unwrap_or_default();
    let header_str = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let recorded = RecordedPush {
        path: parts.uri.path().to_string(),
        http_version: version_label(parts.version),
        content_type: header_str(header::CONTENT_TYPE.as_str()).unwrap_or_default(),
        authorization: header_str("authorization").unwrap_or_default(),
        apns_topic: header_str("apns-topic"),
        apns_id: header_str("apns-id"),
        apns_collapse_id: header_str("apns-collapse-id"),
        apns_priority: header_str("apns-priority"),
        apns_expiration: header_str("apns-expiration"),
        apns_push_type: header_str("apns-push-type"),
        payload: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    };
    requests
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(recorded);
    canned_response(&token)
}

/// The canned APNs response for a device token (see the module docs).
fn canned_response(token: &str) -> Response {
    let token = token.to_ascii_lowercase();
    let (status, reason) = if token.contains("unregistered") {
        (StatusCode::GONE, "Unregistered")
    } else if token.contains("baddevicetoken") {
        (StatusCode::BAD_REQUEST, "BadDeviceToken")
    } else if token.contains("internalerror") {
        (StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError")
    } else if token.contains("toomanyrequests") {
        (StatusCode::TOO_MANY_REQUESTS, "TooManyRequests")
    } else if token.contains("notopic") {
        (StatusCode::FORBIDDEN, "DeviceTokenNotForTopic")
    } else {
        return (StatusCode::OK, Json(json!({}))).into_response();
    };
    (status, Json(json!({ "reason": reason }))).into_response()
}

/// Label an HTTP version the way the wire calls it (http 1.x `Version` has
/// no `Display`).
fn version_label(version: axum::http::Version) -> String {
    match version {
        axum::http::Version::HTTP_09 => "HTTP/0.9",
        axum::http::Version::HTTP_10 => "HTTP/1.0",
        axum::http::Version::HTTP_11 => "HTTP/1.1",
        axum::http::Version::HTTP_2 => "HTTP/2.0",
        axum::http::Version::HTTP_3 => "HTTP/3.0",
        other => return format!("{other:?}"),
    }
    .to_string()
}
