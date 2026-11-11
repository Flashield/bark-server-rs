//! Ticket 08 acceptance: event bus + SSE realtime stream (bridge fan-out)
//! over the HTTP boundary. Pushes persist to the per-device message store,
//! then fan out to APNs (unchanged path, observed via the stub) and to every
//! live Realtime Stream on that Device (ADR-0001/0002/0006).
//!
//! Contract choices pinned here are documented in `src/events.rs` and
//! `src/api/sse.rs` and transcribed into `docs/protocol.md` by ticket 10.

mod common;

use std::time::Duration;

use common::apns_stub::ApnsStub;
use common::{TestServer, assert_envelope_no_data, client, ephemeral_config, server_header};
use serde_json::{Value, json};

/// Spawn a bark server with a 1s SSE keepalive (fast observable keepalives)
/// whose APNs endpoint is the local stub.
async fn spawn(stub: &ApnsStub) -> TestServer {
    let (mut config, dir) = ephemeral_config();
    config.apns_endpoint = stub.url.clone();
    config.apns_insecure_skip_tls_verify = true;
    config.sse_keepalive_secs = 1;
    TestServer::spawn(config, dir).await
}

/// Register a Device through the real route and return its Device Key.
async fn register_device(server: &TestServer, token: &str, device_type: &str) -> String {
    let mut body = json!({ "device_token": token });
    if !device_type.is_empty() {
        body["device_type"] = json!(device_type);
    }
    let res = client()
        .post(server.url("/register"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "register failed: {res:?}");
    let env: Value = res.json().await.unwrap();
    env["data"]["device_key"]
        .as_str()
        .expect("device key")
        .to_string()
}

/// POST /push with a JSON body, asserting the response is a 200 success.
async fn push_ok(server: &TestServer, body: Value) -> Value {
    let res = client()
        .post(server.url("/push"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "push {body} must succeed");
    res.json().await.unwrap()
}

/// GET /info, returning the parsed body.
async fn info(server: &TestServer) -> Value {
    let res = client().get(server.url("/info")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    res.json().await.unwrap()
}

// ---------------------------------------------------------------------------
// SSE plumbing: minting tokens and reading raw SSE frames over the boundary
// ---------------------------------------------------------------------------

/// Mint a Stream Token for `device_key` and return the full secret.
async fn mint_token(server: &TestServer, device_key: &str) -> String {
    let res = client()
        .post(server.url(&format!("/realtime/v1/devices/{device_key}/streams")))
        .header("X-Device-Key", device_key)
        .json(&json!({"client_label": "sse-test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "mint must succeed");
    let env: Value = res.json().await.unwrap();
    env["data"]["token"].as_str().expect("token").to_string()
}

/// An SSE-capable client: no total-request timeout (the stream is long-lived).
fn stream_client() -> reqwest::Client {
    reqwest::Client::builder().build().expect("stream client")
}

/// One parsed SSE frame (fields of a "block" terminated by a blank line).
#[derive(Debug, Default, PartialEq)]
struct SseFrame {
    comment: Option<String>,
    event: Option<String>,
    id: Option<String>,
    data: Vec<String>,
}

impl SseFrame {
    /// The data payload re-joined (single-line data → itself).
    fn data_text(&self) -> String {
        self.data.join("\n")
    }
}

/// Parse every complete frame out of a raw byte buffer, returning the frames
/// and the leftover partial bytes.
fn parse_frames(buf: &[u8]) -> (Vec<SseFrame>, Vec<u8>) {
    let text = String::from_utf8_lossy(buf).into_owned();
    let mut frames = Vec::new();
    let mut rest = &text[..];
    while let Some(pos) = rest.find("\n\n") {
        let (frame_text, tail) = rest.split_at(pos);
        let mut frame = SseFrame::default();
        for line in frame_text.split('\n') {
            if let Some(comment) = line.strip_prefix(':') {
                // SSE convention: one optional space after the colon is not
                // part of the value (axum writes ": connected").
                let value = comment.strip_prefix(' ').unwrap_or(comment);
                frame.comment = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("event: ") {
                frame.event = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("id: ") {
                frame.id = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("data: ") {
                frame.data.push(value.to_string());
            } else if line == "data:" {
                frame.data.push(String::new());
            }
        }
        frames.push(frame);
        rest = &tail[2..];
    }
    (frames, rest.as_bytes().to_vec())
}

/// A connected SSE stream: the raw response plus a byte buffer.
struct SseStream {
    res: reqwest::Response,
    buf: Vec<u8>,
    done: bool,
}

impl SseStream {
    /// Open the stream with `X-Stream-Token` auth and assert the response
    /// contract (status, headers) before returning it.
    async fn open(server: &TestServer, token: &str) -> Self {
        let res = stream_client()
            .get(server.url("/realtime/v1/stream"))
            .header("X-Stream-Token", token)
            .send()
            .await
            .expect("stream connect");
        assert_eq!(res.status(), 200, "valid token connects");
        assert_eq!(server_header(&res), "Bark", "SSE keeps the Bark header");
        let content_type = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .expect("content-type")
            .to_string();
        assert!(
            content_type.starts_with("text/event-stream"),
            "SSE content type, got {content_type:?}"
        );
        assert_eq!(
            res.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-cache"),
            "SSE must not be cached"
        );
        Self {
            res,
            buf: Vec::new(),
            done: false,
        }
    }

    /// Read frames until at least `count` are collected or the deadline
    /// passes (panics on timeout — tests must not hang).
    async fn read_frames(&mut self, count: usize, timeout: Duration) -> Vec<SseFrame> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut frames = Vec::new();
        while frames.len() < count {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                panic!(
                    "timed out waiting for {count} frames; have {}: {frames:?}",
                    frames.len()
                );
            }
            if self.done {
                panic!("stream ended after {frames:?} frames while waiting for {count}");
            }
            match tokio::time::timeout(remaining, self.res.chunk()).await {
                Err(_) => panic!("read deadline hit waiting for {count} frames; have {frames:?}"),
                Ok(Err(e)) => panic!("stream read error: {e}"),
                Ok(Ok(None)) => self.done = true,
                Ok(Ok(Some(bytes))) => self.buf.extend_from_slice(&bytes),
            }
            let (mut parsed, rest) = parse_frames(&self.buf);
            self.buf = rest;
            frames.append(&mut parsed);
        }
        frames
    }

    /// Whatever frames arrive within `timeout` — never panics on timeout.
    async fn try_read_frames(&mut self, timeout: Duration) -> Vec<SseFrame> {
        let mut frames = Vec::new();
        let _ = tokio::time::timeout(timeout, async {
            loop {
                if self.done {
                    return;
                }
                match self.res.chunk().await {
                    Err(_) | Ok(None) => {
                        self.done = true;
                        return;
                    }
                    Ok(Some(bytes)) => self.buf.extend_from_slice(&bytes),
                }
                let (mut parsed, rest) = parse_frames(&self.buf);
                self.buf = rest;
                frames.append(&mut parsed);
            }
        })
        .await;
        frames
    }

    /// The first `event: message` frame with its data parsed as JSON.
    async fn next_push_event(&mut self) -> (SseFrame, Value) {
        loop {
            let frames = self.read_frames(1, Duration::from_secs(10)).await;
            for frame in frames {
                if frame.event.as_deref() == Some("message") {
                    let data: Value =
                        serde_json::from_str(&frame.data_text()).expect("event data is JSON");
                    return (frame, data);
                }
            }
        }
    }
}

/// Assert the frame is the server's connected handshake comment.
fn assert_connected(frame: &SseFrame) {
    assert_eq!(
        frame.comment.as_deref(),
        Some("connected"),
        "first frame is the : connected comment: {frame:?}"
    );
    assert!(
        frame.data.is_empty() && frame.event.is_none() && frame.id.is_none(),
        "handshake carries no event fields: {frame:?}"
    );
}

/// Assert the frame is a keepalive comment (no event fields).
fn assert_keepalive(frame: &SseFrame) {
    assert_eq!(
        frame.comment.as_deref(),
        Some("keep-alive"),
        "keepalive is a comment line: {frame:?}"
    );
    assert!(
        frame.data.is_empty() && frame.event.is_none() && frame.id.is_none(),
        "keepalive carries no event fields: {frame:?}"
    );
}

// ---------------------------------------------------------------------------
// /info realtime statistics (additive fields, pre-agreed in the spec)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn info_reports_realtime_stats_on_fresh_server() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;

    let body = info(&server).await;
    let obj = body.as_object().expect("info is a JSON object");
    // The upstream fields stay untouched; the realtime stats are additive.
    for key in ["version", "build", "arch", "commit", "devices"] {
        assert!(obj.contains_key(key), "info keeps upstream field {key}");
    }
    assert_eq!(body["devices"], 0);
    // Additive realtime stats: minted Stream Tokens, live SSE connections,
    // and stored (pending) messages.
    assert_eq!(body["streams"], 0, "no Stream Tokens minted yet: {body}");
    assert_eq!(body["active_streams"], 0, "no live streams yet: {body}");
    assert_eq!(body["pending_messages"], 0, "no messages yet: {body}");
    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Persistence: every Push to a resolved Device lands in the message store
// before any delivery (ADR-0002), stream connected or not
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pushes_persist_without_any_connected_stream() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "PUSHTOKEN1", "ios").await;

    for n in 1..=3 {
        push_ok(&server, json!({"device_key": key, "body": format!("m{n}")})).await;
        let body = info(&server).await;
        assert_eq!(
            body["pending_messages"], n,
            "each push persists, even with no stream: {body}"
        );
    }
    // The APNs path is unchanged: the stub observed all three.
    assert_eq!(stub.push_count(), 3, "APNs still delivers");
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn stream_device_push_succeeds_without_apns() {
    // A Stream Device has no Device Token (ADR-0006): the realtime stream is
    // its only delivery path, so pushing to it succeeds and never touches
    // APNs — upstream's "device token invalid" error would make story 15
    // (system purely with desktop clients) impossible.
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;

    let body = push_ok(&server, json!({"device_key": key, "body": "hello desktop"})).await;
    assert_eq!(body["code"], 200, "stream-device push succeeds: {body}");
    assert_eq!(stub.push_count(), 0, "no APNs call for a token-less Device");

    let info_body = info(&server).await;
    assert_eq!(info_body["pending_messages"], 1, "the push persisted");
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn push_to_unknown_device_persists_nothing() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;

    let res = client()
        .post(server.url("/push"))
        .json(&json!({"device_key": "unknownDeviceKey000000", "body": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body = info(&server).await;
    assert_eq!(body["pending_messages"], 0, "no Device → nothing stored");
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn blanked_ios_token_push_answers_upstream_error_but_persists() {
    // Upstream device types keep upstream's response contract (ADR-0003):
    // an APNs-410-blanked token answers 400 "device token invalid". The
    // bridge model (ADR-0006) still mirrors the push to the Device's streams
    // and the store keeps it for replay — the response error only reports
    // the APNs path.
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "unregisteredToken1", "ios").await;

    // First push: APNs answers 410 Unregistered → upstream error, token blanked.
    let res = client()
        .post(server.url("/push"))
        .json(&json!({"device_key": key, "body": "first"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 410);

    // Second push: the token is now blank → upstream's 400.
    let res = client()
        .post(server.url("/push"))
        .json(&json!({"device_key": key, "body": "second"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["message"], "failed to get device token: device token invalid",
        "upstream error preserved: {body}"
    );

    let info_body = info(&server).await;
    assert_eq!(
        info_body["pending_messages"], 2,
        "both pushes were stored for the Device's streams/replay"
    );
    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// GET /realtime/v1/stream — Stream Token auth, connect, keepalives
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stream_requires_token() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;
    let _ = mint_token(&server, &key).await; // server has tokens; none presented

    let res = stream_client()
        .get(server.url("/realtime/v1/stream"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "no token → 401");
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 401, "stream token required");
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn stream_rejects_unknown_token() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;
    let _ = mint_token(&server, &key).await;

    for presented in [
        "st_totallyUnknown00000000000000000000000",
        "not-a-token",
        "",
    ] {
        let res = stream_client()
            .get(server.url("/realtime/v1/stream"))
            .header("X-Stream-Token", presented)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401, "unknown token {presented:?}");
        let body: Value = res.json().await.unwrap();
        assert_envelope_no_data(&body, 401, "stream token invalid");
    }
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn stream_rejects_revoked_token() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;
    let token = mint_token(&server, &key).await;

    // Revoke via the credential plane (list to find the id first).
    let res = client()
        .get(server.url(&format!("/realtime/v1/devices/{key}/streams")))
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    let env: Value = res.json().await.unwrap();
    let token_id = env["data"][0]["token_id"].as_str().unwrap().to_string();
    let res = client()
        .delete(server.url(&format!("/realtime/v1/devices/{key}/streams/{token_id}")))
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "revoke succeeded");

    let res = stream_client()
        .get(server.url("/realtime/v1/stream"))
        .header("X-Stream-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "revoked tokens cannot hold a stream");
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 401, "stream token invalid");
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn stream_rejects_other_methods() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;
    let token = mint_token(&server, &key).await;
    let url = server.url("/realtime/v1/stream");

    let res = client()
        .post(&url)
        .header("X-Stream-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 405, "stream is GET-only");
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 405, "Method Not Allowed");

    let res = client().delete(&url).send().await.unwrap();
    assert_eq!(res.status(), 405);
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn stream_connects_with_valid_token_and_handshakes() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;
    let token = mint_token(&server, &key).await;

    let mut stream = SseStream::open(&server, &token).await;
    let frames = stream.read_frames(1, Duration::from_secs(5)).await;
    assert_connected(&frames[0]);
    // The stream stays open awaiting pushes (no data yet after the handshake).
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn keepalives_are_observable() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;
    let token = mint_token(&server, &key).await;

    let mut stream = SseStream::open(&server, &token).await;
    let frames = stream.read_frames(1, Duration::from_secs(5)).await;
    assert_connected(&frames[0]);

    // No pushes arrive: the server must keep the connection alive with
    // comment lines at the configured interval (1s in this suite).
    let frames = stream.read_frames(2, Duration::from_secs(6)).await;
    for frame in &frames {
        assert_keepalive(frame);
    }
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn basic_auth_applies_to_stream_endpoint() {
    let stub = ApnsStub::spawn().await;
    let (mut config, dir) = ephemeral_config();
    config.apns_endpoint = stub.url.clone();
    config.apns_insecure_skip_tls_verify = true;
    config.sse_keepalive_secs = 1;
    config.basic_auth_user = "u".into();
    config.basic_auth_password = "p".into();
    let server = TestServer::spawn(config, dir).await;

    let key = register_device(&server, "", "stream").await; // /register is exempt

    // /realtime/v1 mint also sits behind Basic Auth when enabled.
    let res = client()
        .post(server.url(&format!("/realtime/v1/devices/{key}/streams")))
        .header("X-Device-Key", &key)
        .basic_auth("u", Some("p"))
        .json(&json!({"client_label": "sse-test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "mint behind basic auth");
    let env: Value = res.json().await.unwrap();
    let token = env["data"]["token"].as_str().unwrap().to_string();

    // No Basic Auth → 418 teapot before the Stream Token matters.
    let res = stream_client()
        .get(server.url("/realtime/v1/stream"))
        .header("X-Stream-Token", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 418, "basic auth gates the stream");
    assert_eq!(res.text().await.unwrap(), "I'm a teapot");

    // With Basic Auth, the valid token connects.
    let res = stream_client()
        .get(server.url("/realtime/v1/stream"))
        .header("X-Stream-Token", &token)
        .basic_auth("u", Some("p"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "basic auth + valid token → stream");
    drop(res);
    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Live fan-out: pushes reach every connected stream of the Device
// ---------------------------------------------------------------------------

/// Assert the event JSON carries exactly the full-Push fields.
fn assert_event_shape(data: &Value, device_key: &str) {
    let obj = data.as_object().expect("event data is a JSON object");
    let mut fields: Vec<&String> = obj.keys().collect();
    fields.sort();
    assert_eq!(
        fields,
        [
            "body",
            "created_at",
            "device_key",
            "ext_params",
            "id",
            "subtitle",
            "title",
        ],
        "event data must carry exactly the full Push: {data}"
    );
    assert_eq!(data["device_key"], device_key);
    assert!(data["id"].is_i64(), "monotonic id is an integer: {data}");
    assert!(
        data["created_at"].is_i64(),
        "created_at is an integer: {data}"
    );
}

#[tokio::test]
async fn pushes_fan_out_with_monotonic_ids_and_full_shape() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "PUSHTOKEN1", "ios").await;
    let token = mint_token(&server, &key).await;

    let mut stream = SseStream::open(&server, &token).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);

    // Push with the full parameter surface: title/subtitle/body, the id
    // param (collapse id AND custom key) and Ext Params (group, url).
    push_ok(
        &server,
        json!({
            "device_key": key,
            "title": "Flight",
            "subtitle": "SFO",
            "body": "Gate 7",
            "id": "flight-87",
            "group": "trips",
            "url": "https://example.com/boarding",
        }),
    )
    .await;

    let (frame, data) = stream.next_push_event().await;
    assert_eq!(frame.id.as_deref(), Some("1"), "first push has id 1");
    assert_eq!(frame.event.as_deref(), Some("message"));
    assert_event_shape(&data, &key);
    assert_eq!(data["id"], 1, "data id equals the SSE id line");
    assert_eq!(data["title"], "Flight");
    assert_eq!(data["subtitle"], "SFO");
    assert_eq!(data["body"], "Gate 7");
    assert_eq!(
        data["ext_params"],
        json!({
            "id": "flight-87",
            "group": "trips",
            "url": "https://example.com/boarding",
        }),
        "Ext Params ride inside the event body: {data}"
    );

    // Second push: monotonic id continues.
    push_ok(&server, json!({"device_key": key, "body": "second"})).await;
    let (frame, data) = stream.next_push_event().await;
    assert_eq!(frame.id.as_deref(), Some("2"));
    assert_eq!(data["id"], 2);
    assert_eq!(data["title"], "", "absent title stays empty");
    assert_eq!(data["body"], "second");
    assert_eq!(data["ext_params"], json!({}), "no params → empty object");

    // APNs still delivered alongside the stream fan-out.
    assert_eq!(stub.push_count(), 2, "stub observed both pushes");
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn stream_device_receives_its_pushes() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;
    let token = mint_token(&server, &key).await;

    let mut stream = SseStream::open(&server, &token).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);

    push_ok(&server, json!({"device_key": key, "body": "hello desktop"})).await;
    let (frame, data) = stream.next_push_event().await;
    assert_eq!(frame.id.as_deref(), Some("1"));
    assert_eq!(data["body"], "hello desktop");
    assert_eq!(stub.push_count(), 0, "stream Devices never touch APNs");
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn watchos_device_stream_receives_and_apns_uses_watch_topic() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "watchToken1", "watchos").await;
    let token = mint_token(&server, &key).await;

    let mut stream = SseStream::open(&server, &token).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);

    push_ok(&server, json!({"device_key": key, "body": "to the watch"})).await;
    let (_, data) = stream.next_push_event().await;
    assert_eq!(data["body"], "to the watch");

    // The APNs path is untouched: watch topic + the same payload.
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].apns_topic.as_deref(), Some("me.fin.bark.watch"));
    assert_eq!(pushes[0].path, "/3/device/watchToken1");
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn two_streams_each_get_every_event_in_order() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "PUSHTOKEN1", "ios").await;
    let token_a = mint_token(&server, &key).await;
    let token_b = mint_token(&server, &key).await;

    let mut stream_a = SseStream::open(&server, &token_a).await;
    let mut stream_b = SseStream::open(&server, &token_b).await;
    assert_connected(&stream_a.read_frames(1, Duration::from_secs(5)).await[0]);
    assert_connected(&stream_b.read_frames(1, Duration::from_secs(5)).await[0]);

    for n in 1..=3 {
        push_ok(&server, json!({"device_key": key, "body": format!("m{n}")})).await;
    }

    for (name, stream) in [("a", &mut stream_a), ("b", &mut stream_b)] {
        for n in 1..=3 {
            let (frame, data) = stream.next_push_event().await;
            assert_eq!(
                frame.id.as_deref(),
                Some(n.to_string().as_str()),
                "stream {name} event order"
            );
            assert_eq!(data["body"], format!("m{n}"), "stream {name} content");
        }
    }
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn two_concurrent_streams_and_concurrent_pushes_agree() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "PUSHTOKEN1", "ios").await;
    let token_a = mint_token(&server, &key).await;
    let token_b = mint_token(&server, &key).await;

    let mut stream_a = SseStream::open(&server, &token_a).await;
    let mut stream_b = SseStream::open(&server, &token_b).await;
    assert_connected(&stream_a.read_frames(1, Duration::from_secs(5)).await[0]);
    assert_connected(&stream_b.read_frames(1, Duration::from_secs(5)).await[0]);

    // Ten pushes fired concurrently: each stream must observe exactly the
    // monotonic id sequence 1..=10, in order (per-device FIFO).
    let pushes = (1..=10).map(|n| {
        let server = &server;
        let key = key.clone();
        async move {
            push_ok(server, json!({"device_key": key, "body": format!("c{n}")})).await;
        }
    });
    futures_util::future::join_all(pushes).await;

    for (name, stream) in [("a", &mut stream_a), ("b", &mut stream_b)] {
        let mut bodies = Vec::new();
        for expected_id in 1..=10 {
            let (frame, data) = stream.next_push_event().await;
            assert_eq!(
                frame.id.as_deref(),
                Some(expected_id.to_string().as_str()),
                "stream {name}: per-device FIFO, ids arrive 1..=10 in order"
            );
            bodies.push(data["body"].as_str().unwrap().to_string());
        }
        // Every push is present exactly once (complete, at-least-once
        // dedupable by id).
        let mut sorted = bodies.clone();
        sorted.sort();
        let mut expected: Vec<String> = (1..=10).map(|n| format!("c{n}")).collect();
        expected.sort(); // same lexicographic order ("c10" sorts before "c2")
        assert_eq!(
            sorted, expected,
            "stream {name}: no event lost or duplicated"
        );
    }
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn streams_are_isolated_per_device() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key_a = register_device(&server, "PUSHTOKEN1", "ios").await;
    let key_b = register_device(&server, "PUSHTOKEN2", "ios").await;
    let token_a = mint_token(&server, &key_a).await;

    let mut stream_a = SseStream::open(&server, &token_a).await;
    assert_connected(&stream_a.read_frames(1, Duration::from_secs(5)).await[0]);

    // Pushes to another Device must not reach a's stream.
    push_ok(&server, json!({"device_key": key_b, "body": "for b"})).await;
    let frames = stream_a.try_read_frames(Duration::from_secs(2)).await;
    assert!(
        frames
            .iter()
            .all(|f| f.event.is_none() && f.data.is_empty()),
        "no push events from another Device (keepalive comments only): {frames:?}"
    );

    // Pushes to a's Device do arrive.
    push_ok(&server, json!({"device_key": key_a, "body": "for a"})).await;
    let (frame, data) = stream_a.next_push_event().await;
    assert_eq!(
        frame.id.as_deref(),
        Some("1"),
        "b's push never consumed an id"
    );
    assert_eq!(data["body"], "for a");
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn late_stream_gets_only_new_events() {
    // No replay in this ticket (ADR-0002's replay half is ticket 08): a
    // stream opened after pushes sees only pushes from the handshake on,
    // and the monotonic ids continue — proving the store counts every push.
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;
    let token = mint_token(&server, &key).await;

    push_ok(&server, json!({"device_key": key, "body": "while away 1"})).await;
    push_ok(&server, json!({"device_key": key, "body": "while away 2"})).await;

    let mut stream = SseStream::open(&server, &token).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);

    push_ok(&server, json!({"device_key": key, "body": "live"})).await;
    let (frame, data) = stream.next_push_event().await;
    assert_eq!(
        frame.id.as_deref(),
        Some("3"),
        "ids continue across the gap"
    );
    assert_eq!(data["body"], "live", "no replay of the earlier pushes");

    // The two earlier pushes are nonetheless in the store for ticket 08.
    let body = info(&server).await;
    assert_eq!(body["pending_messages"], 3);
    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn active_streams_tracks_live_connections() {
    let stub = ApnsStub::spawn().await;
    let server = spawn(&stub).await;
    let key = register_device(&server, "", "stream").await;
    let token_a = mint_token(&server, &key).await;
    let token_b = mint_token(&server, &key).await;

    let mut stream_a = Some(SseStream::open(&server, &token_a).await);
    let stream_b = Some(SseStream::open(&server, &token_b).await);

    // Both connections eventually show as active.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let body = info(&server).await;
        if body["active_streams"] == 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "active_streams never reached 2: {body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Dropping one stream client decrements within the keepalive interval
    // (the next keepalive write notices the closed connection).
    drop(stream_a.take());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let body = info(&server).await;
        if body["active_streams"] == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "active_streams never dropped to 1: {body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    drop(stream_b);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let body = info(&server).await;
        if body["active_streams"] == 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "active_streams never dropped to 0: {body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    server.shutdown().await;
    stub.shutdown().await;
}
