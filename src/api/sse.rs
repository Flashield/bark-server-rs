//! The SSE realtime stream endpoint (ADR-0001/0006): the live-delivery AND
//! replay halves of the store-and-forward contract (ADR-0002). One route:
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
//! # Replay — the `Last-Event-ID` header (ticket 08)
//!
//! A client reconnecting after a gap echoes the last per-device monotonic
//! message id it processed back in the **standard SSE `Last-Event-ID`
//! request header**. The header is honored on **every** connect — there is
//! no first-connect/reconnect distinction server-side; a first connect may
//! carry it (e.g. a client restoring its cursor from local storage) and is
//! answered the same way. After auth, the server first **replays** every
//! retained message with id > Last-Event-ID (ascending id order, from the
//! message store's retention window — see `store::MessageRetention`), then
//! **hands off seamlessly to the live subscription**: the subscription is
//! registered inside the same per-Device publish lock the replay scan runs
//! under ([`crate::events::EventBus::subscribe_with_replay`]), so a push
//! published during the replay scan lands either in the replay list or on
//! the live stream — never both, never neither. No gap, no duplicate.
//!
//! Header values parse against `i64` with these pinings:
//!
//! - **absent or empty** → fresh subscription, no replay;
//! - **non-numeric** (including values beyond `i64` range) → treated as
//!   absent — WHATWG's EventSource leniently resets an unparseable last
//!   event id, and failing the connect would break auto-reconnect cycles
//!   for no benefit (ids are dedupe keys, not credentials);
//! - an id **older than everything retained** replays from the oldest
//!   retained message (the retention window is the floor, not an error);
//! - an id at or after the newest message replays nothing.
//!
//! There is deliberately **no `last_event_id` query parameter**: query
//! strings leak into access logs and proxies, the same reason Stream Tokens
//! are header-only, and this API's clients are native apps that set headers
//! freely. Ticket 10 records the choice in `docs/protocol.md`.
//!
//! Retention bounds what replay can return: messages are kept per Device
//! for a TTL (default 72h) up to a cap (default 1000), both configurable
//! (`--sse-message-ttl-secs` / `--sse-message-cap`), pruned lazily; pruned
//! ids are never replayed (at-least-once delivery, clients deduplicate by
//! id — no explicit ack, ADR-0002).
//!
//! # Stream lifecycle
//!
//! The stream binds to the token's Device for the life of the connection.
//! The **first body bytes are a `: connected` comment** — a subscriber is
//! registered before those bytes are produced, so a client that has read the
//! handshake is guaranteed to receive every push published afterwards (plus
//! everything retained before it when `Last-Event-ID` was presented).
//!
//! Any number of concurrent streams per Device is allowed (one broadcast
//! receiver each); streams on `ios`, `watchos` and `stream` Devices all
//! mirror their Device's pushes — the bridge model (ADR-0006).
//!
//! # Event format
//!
//! Each Push arrives as one SSE event (replayed and live pushes are
//! indistinguishable on the wire — same shape, same `id:` semantics):
//!
//! ```text
//! event: message
//! id: 7
//! data: {"id":7,"title":"Flight","subtitle":"SFO","body":"Gate 7","ext_params":{"group":"trips"},"device_key":"…22 chars…","created_at":1760000000}
//!
//! ```
//!
//! - `id:` is the per-device monotonic message id (decimal). Clients echo it
//!   back as `Last-Event-ID` on reconnect (see "Replay" above) and
//!   deduplicate with it (at-least-once delivery, ADR-0002 — no explicit
//!   ack).
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
//! reconnects with `Last-Event-ID` and replay heals the gap from the store.

use std::collections::VecDeque;
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

/// The standard SSE reconnect cursor header ("Replay" in the module docs).
pub const LAST_EVENT_ID_HEADER: &str = "Last-Event-ID";

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

    // Subscribe AND snapshot the replay window before any response byte,
    // both under the Device's publish lock (events.rs docs): from the
    // `: connected` handshake on, the client is guaranteed every published
    // push, and everything retained before the handshake was captured here.
    let last_event_id = parse_last_event_id(&headers);
    let (replay, receiver) = match state
        .events
        .subscribe_with_replay(&record.device_key, last_event_id)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            return error_envelope(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("message store failed: {e}"),
            );
        }
    };
    let device_key = record.device_key.clone();
    let event_stream = push_event_stream(receiver, replay, device_key, state.shutdown.clone());

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

/// Parse the `Last-Event-ID` header into a replay cursor ("Replay" in the
/// module docs): absent/empty/non-numeric all mean "fresh subscription".
fn parse_last_event_id(headers: &HeaderMap) -> Option<i64> {
    let raw = headers.get(LAST_EVENT_ID_HEADER)?.to_str().ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<i64>().ok()
}

/// The SSE body stream for one Realtime Stream: the `: connected` handshake
/// first (the subscriber is already registered), then the replay window —
/// the retained messages after `Last-Event-ID` captured under the publish
/// lock before any byte was written — then one event per bus delivery. Lag
/// closes the stream (module docs); a server shutdown closes it too, so
/// graceful shutdown never waits on an idle stream forever.
fn push_event_stream(
    receiver: tokio::sync::broadcast::Receiver<std::sync::Arc<PushEvent>>,
    replay: Vec<std::sync::Arc<PushEvent>>,
    device_key: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> impl Stream<Item = Result<Event, std::convert::Infallible>> + Send + 'static {
    unfold(
        (receiver, VecDeque::from(replay), true, shutdown),
        move |(mut receiver, mut replay, mut connected, mut shutdown)| {
            let device_key = device_key.clone();
            async move {
                if connected {
                    connected = false;
                    return Some((
                        Ok(Event::default().comment("connected")),
                        (receiver, replay, connected, shutdown),
                    ));
                }
                // Replay window first, in id order (subscription already
                // registered, so live events queue behind — events.rs docs).
                if let Some(event) = replay.pop_front() {
                    return Some((
                        Ok(push_event_to_sse(&event)),
                        (receiver, replay, connected, shutdown),
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
                                    (receiver, replay, connected, shutdown),
                                )),
                                // Lag: close the stream so the client
                                // reconnects and replays the gap from the
                                // store instead of losing events.
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
