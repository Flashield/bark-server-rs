//! SSE client machinery for the HTTP-seam suites: a raw frame parser and a
//! long-lived `reqwest` reader (extracted from ticket 07's `sse_seam.rs`, so
//! the replay suite drives the same wire format the live suite does).

#![allow(dead_code)] // helpers are shared per test-target, not all used everywhere

use std::time::Duration;

use super::{TestServer, server_header};
use serde_json::Value;

/// An SSE-capable client: no total-request timeout (the stream is long-lived).
pub fn stream_client() -> reqwest::Client {
    reqwest::Client::builder().build().expect("stream client")
}

/// One parsed SSE frame (fields of a "block" terminated by a blank line).
#[derive(Debug, Default, PartialEq)]
pub struct SseFrame {
    pub comment: Option<String>,
    pub event: Option<String>,
    pub id: Option<String>,
    pub data: Vec<String>,
}

impl SseFrame {
    /// The data payload re-joined (single-line data → itself).
    pub fn data_text(&self) -> String {
        self.data.join("\n")
    }
}

/// Parse every complete frame out of a raw byte buffer, returning the frames
/// and the leftover partial bytes.
pub fn parse_frames(buf: &[u8]) -> (Vec<SseFrame>, Vec<u8>) {
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
pub struct SseStream {
    pub res: reqwest::Response,
    buf: Vec<u8>,
    done: bool,
}

impl SseStream {
    /// Open the stream with `X-Stream-Token` auth and assert the response
    /// contract (status, headers) before returning it.
    pub async fn open(server: &TestServer, token: &str) -> Self {
        Self::open_with(server, token, None).await
    }

    /// [`SseStream::open`] with an optional `Last-Event-ID` header — the
    /// reconnect half of the store-and-forward contract (ADR-0002).
    pub async fn open_with(server: &TestServer, token: &str, last_event_id: Option<&str>) -> Self {
        let mut req = stream_client()
            .get(server.url("/realtime/v1/stream"))
            .header("X-Stream-Token", token);
        if let Some(id) = last_event_id {
            req = req.header("Last-Event-ID", id);
        }
        let res = req.send().await.expect("stream connect");
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
    pub async fn read_frames(&mut self, count: usize, timeout: Duration) -> Vec<SseFrame> {
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
    pub async fn try_read_frames(&mut self, timeout: Duration) -> Vec<SseFrame> {
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
    pub async fn next_push_event(&mut self) -> (SseFrame, Value) {
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
pub fn assert_connected(frame: &SseFrame) {
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
pub fn assert_keepalive(frame: &SseFrame) {
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

/// Assert the event JSON carries exactly the full-Push fields.
pub fn assert_event_shape(data: &Value, device_key: &str) {
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
