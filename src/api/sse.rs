//! The SSE realtime stream endpoint (ADR-0001/0006): the live-delivery half
//! of the store-and-forward contract (ADR-0002). One route:
//!
//! ## `GET /realtime/v1/stream` — hold a Realtime Stream
//!
//! Authenticates with a **Stream Token** (ticket 06's credential plane) and
//! holds an open Server-Sent Events connection carrying a mirror of every
//! Push to that token's Device. Contract choices pinned here (ticket 10
//! transcribes them into `docs/protocol.md`):
//!
//! # Credential presentation — `X-Stream-Token` header
//!
//! The Stream Token is presented in the **`X-Stream-Token` request header**,
//! byte-exact (`st_` + 43 base64url chars). This is deliberately consistent
//! with the credential plane's `X-Device-Key` pattern (api/realtime.rs): one
//! dedicated header per credential, no `Authorization` scheme parsing, no
//! query parameters (tokens in URLs leak into logs and proxies). Clients are
//! the project's own desktop/mobile apps, so the browser-EventSource
//! header limitation does not apply. Absent header → 401; unknown or
//! **revoked** token → 401 with the same message — the endpoint does not
//! distinguish the two (a rejection never becomes a token-validity oracle).
//! Operator Basic Auth still wraps this route (not in upstream's auth-free
//! list): with Basic Auth configured its 418 fires first.
//!
//! # Stream lifecycle
//!
//! The stream binds to the token's Device for the life of the connection.
//! The **first body bytes are a `: connected` comment** — a subscriber is
//! registered before those bytes are produced, so a client that has read the
//! handshake is guaranteed to receive every push published afterwards. Live
//! delivery only: events published before the handshake are not replayed
//! (that is ticket 08's `Last-Event-ID` replay off the message store).
//!
//! Any number of concurrent streams per Device is allowed (one broadcast
//! receiver each); streams on `ios`, `watchos` and `stream` Devices all
//! mirror their Device's pushes — the bridge model (ADR-0006).
//!
//! # Event format
//!
//! Each Push arrives as one SSE event:
//!
//! ```text
//! event: message
//! id: 7
//! data: {"id":7,"title":"Flight","subtitle":"SFO","body":"Gate 7","ext_params":{"group":"trips"},"device_key":"…22 chars…","created_at":1760000000}
//!
//! ```
//!
//! - `id:` is the per-device monotonic message id (decimal). Clients echo it
//!   back as `Last-Event-ID` on reconnect (ticket 08) and deduplicate with
//!   it (at-least-once delivery, ADR-0002 — no explicit ack).
//! - `data:` is the JSON serialization of [`crate::events::PushEvent`] (the
//!   "full Push": id, title, subtitle, body, Ext Params object, Device Key,
//!   created_at). The user-supplied `id`/`group`/… parameters ride inside
//!   `ext_params`; `sound` stays an APNs-payload concern.
//! - `event: message` is explicit so future event types (e.g. replay
//!   boundary markers) coexist under one stream.
//!
//! # Keepalives and disconnects
//!
//! While idle the server emits `: keep-alive` comment lines every
//! `--sse-keepalive-secs` (default 15s, 0 disables) — plain SSE comments a
//! proxy/NAT will not mistake for events. If a stream falls more than the
//! bus capacity behind (256 events), the channel reports lag and the server
//! **closes the stream** rather than skipping silently: the client
//! reconnects with `Last-Event-ID` and ticket 08's replay heals the gap.

use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::response::Response;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::{Stream, unfold};
use tokio::sync::broadcast::error::RecvError;

use crate::api::error_envelope;
use crate::events::PushEvent;
use crate::server::AppState;

/// The read credential header; see the module docs for the presentation
/// contract (mirrors api/realtime.rs's `X-Device-Key` pattern).
pub const STREAM_TOKEN_HEADER: &str = "X-Stream-Token";

/// `GET /realtime/v1/stream` — hold a Realtime Stream over SSE.
pub async fn stream_connect(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = headers
        .get(STREAM_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return error_envelope(StatusCode::UNAUTHORIZED, "stream token required");
    };
    let record = match state.store.stream_token_by_token(token) {
        // Revoked and unknown tokens reject identically (module docs).
        Ok(Some(record)) if !record.revoked => record,
        Ok(_) => return error_envelope(StatusCode::UNAUTHORIZED, "stream token invalid"),
        Err(e) => {
            return error_envelope(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("stream token lookup failed: {e}"),
            );
        }
    };

    // Subscribe before any response byte: from the `: connected` handshake on,
    // the client is guaranteed every published push (module docs).
    let receiver = state.events.subscribe(&record.device_key);
    let device_key = record.device_key.clone();
    let event_stream = push_event_stream(receiver, device_key, state.shutdown.clone());

    // Keepalives are opt-out via --sse-keepalive-secs 0 (KeepAlive::new()
    // itself always ticks, so 0 must skip the wrapper entirely).
    if state.config.sse_keepalive_secs > 0 {
        Sse::new(event_stream)
            .keep_alive(
                KeepAlive::new()
                    .interval(Duration::from_secs(state.config.sse_keepalive_secs))
                    .text("keep-alive"),
            )
            .into_response()
    } else {
        Sse::new(event_stream).into_response()
    }
}

/// The SSE body stream for one Realtime Stream: the `: connected` handshake
/// first (the subscriber is already registered), then one event per bus
/// delivery. Lag closes the stream (module docs); a server shutdown closes
/// it too, so graceful shutdown never waits on an idle stream forever.
fn push_event_stream(
    receiver: tokio::sync::broadcast::Receiver<std::sync::Arc<PushEvent>>,
    device_key: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> impl Stream<Item = Result<Event, std::convert::Infallible>> + Send + 'static {
    unfold(
        (receiver, true, shutdown),
        move |(mut receiver, mut connected, mut shutdown)| {
            let device_key = device_key.clone();
            async move {
                if connected {
                    connected = false;
                    return Some((
                        Ok(Event::default().comment("connected")),
                        (receiver, connected, shutdown),
                    ));
                }
                loop {
                    if *shutdown.borrow_and_update() {
                        return None;
                    }
                    tokio::select! {
                        // broadcast::Receiver::recv is cancellation-safe, so
                        // losing this select arm loses no event.
                        recv = receiver.recv() => {
                            return match recv {
                                Ok(event) => Some((
                                    Ok(push_event_to_sse(&event)),
                                    (receiver, connected, shutdown),
                                )),
                                // Lag: close the stream so the client
                                // reconnects and replays the gap from the
                                // store (ticket 08) instead of losing events.
                                Err(RecvError::Lagged(n)) => {
                                    tracing::warn!(
                                        device = %device_key,
                                        "stream fell {n} events behind; closing so the client can replay"
                                    );
                                    None
                                }
                                // The Device channel's sender lives in the
                                // bus registry for the process lifetime, so
                                // Closed is unreachable in practice.
                                Err(RecvError::Closed) => None,
                            };
                        }
                        _ = shutdown.changed() => continue, // re-check the flag
                    }
                }
            }
        },
    )
}

/// One bus event → one SSE event (`event: message`, `id: <monotonic>`,
/// `data: <PushEvent JSON>`; see the module docs).
fn push_event_to_sse(event: &PushEvent) -> Event {
    // serde_json stringifies without raw newlines, so the data is one line.
    Event::default()
        .event("message")
        .id(event.id.to_string())
        .data(serde_json::to_string(event).expect("PushEvent serializes to JSON"))
}
