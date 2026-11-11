//! Ticket 08 acceptance: Last-Event-ID replay + retention (TTL/cap) over the
//! HTTP boundary — the store-and-forward completion (ADR-0002). Reconnecting
//! Realtime Clients echo the last seen per-device monotonic id back as
//! `Last-Event-ID` and receive, in order, every retained message after it;
//! retention (per-device TTL + cap, configurable, lazily pruned) bounds what
//! replay can return, and pruned ids are never replayed.
//!
//! Contract choices pinned here are documented in `src/api/sse.rs`,
//! `src/events.rs` and `src/store/mod.rs` and transcribed into
//! `docs/protocol.md` by ticket 10.
//!
//! All Devices here are Stream Devices (`stream` type, ADR-0006): their only
//! delivery path is the realtime stream, so no APNs stub is needed and the
//! store/replay behavior is observable in isolation.

mod common;

use std::time::Duration;

use bark_server_rs::config::Config;
use common::TestServer;
use common::sse_client::{SseFrame, SseStream, assert_connected, assert_event_shape};
use common::{client, ephemeral_config};
use serde_json::{Value, json};

/// Spawn a bark server with fast observable keepalives; default retention
/// (tests that need other retention values pass an adjuster).
async fn spawn() -> TestServer {
    spawn_configured(|_| ()).await
}

/// [`spawn`] with full config control (retention values, …).
async fn spawn_configured(adjust: impl FnOnce(&mut Config)) -> TestServer {
    let (mut config, dir) = ephemeral_config();
    config.sse_keepalive_secs = 1;
    adjust(&mut config);
    TestServer::spawn(config, dir).await
}

/// Register a Stream Device (token-less, ADR-0006) and return its Device Key.
async fn register_stream_device(server: &TestServer) -> String {
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_type": "stream"}))
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

/// Mint a Stream Token for `device_key` and return the full secret.
async fn mint_token(server: &TestServer, device_key: &str) -> String {
    let res = client()
        .post(server.url(&format!("/realtime/v1/devices/{device_key}/streams")))
        .header("X-Device-Key", device_key)
        .json(&json!({"client_label": "replay-test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "mint must succeed");
    let env: Value = res.json().await.unwrap();
    env["data"]["token"].as_str().expect("token").to_string()
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

/// Push `count` messages to `device_key`, body `m<n>`, and assert the ids
/// assigned (sequential from 1 by the per-device monotonic counter).
async fn push_numbered(server: &TestServer, device_key: &str, count: usize) {
    for n in 1..=count {
        let env = push_ok(
            server,
            json!({"device_key": device_key, "body": format!("m{n}")}),
        )
        .await;
        assert_eq!(env["code"], 200, "push m{n} succeeded");
    }
}

/// Assert no `event: message` frame arrives within `timeout` (keepalive
/// comments are fine).
async fn assert_no_push_events(stream: &mut SseStream, timeout: Duration) {
    let frames = stream.try_read_frames(timeout).await;
    assert!(
        frames
            .iter()
            .all(|f| f.event.is_none() && f.data.is_empty()),
        "no push events expected, got: {frames:?}"
    );
}

/// Collect `count` `event: message` frames (data parsed as JSON), skipping
/// keepalive comments, giving up after `timeout`. Unlike
/// [`SseStream::next_push_event`], the overall deadline is hard: a run that
/// never receives its events fails instead of looping on keepalives forever.
async fn read_push_events(
    stream: &mut SseStream,
    count: usize,
    timeout: Duration,
) -> Vec<(SseFrame, Value)> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut events = Vec::new();
    while events.len() < count {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out collecting {count} push events; have {}",
            events.len()
        );
        let frames = stream
            .read_frames(1, remaining.min(Duration::from_secs(2)))
            .await;
        for frame in frames {
            if frame.event.as_deref() == Some("message") {
                let data: Value =
                    serde_json::from_str(&frame.data_text()).expect("event data is JSON");
                events.push((frame, data));
            }
        }
    }
    events
}

// ---------------------------------------------------------------------------
// Replay: reconnect with Last-Event-ID replays exactly the missed messages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reconnect_with_last_event_id_replays_exactly_the_missed_messages() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let token = mint_token(&server, &key).await;

    // Connect, receive one live push (id 1), disconnect.
    let mut stream = SseStream::open(&server, &token).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    push_ok(&server, json!({"device_key": key, "body": "live-1"})).await;
    let [(frame, data)] = read_push_events(&mut stream, 1, Duration::from_secs(10))
        .await
        .try_into()
        .unwrap();
    assert_eq!(frame.id.as_deref(), Some("1"));
    assert_eq!(data["body"], "live-1");
    assert_event_shape(&data, &key);
    drop(stream);

    // Pushes while away: no subscriber, the store retains them (ADR-0002).
    push_ok(&server, json!({"device_key": key, "body": "while-away-2"})).await;
    push_ok(&server, json!({"device_key": key, "body": "while-away-3"})).await;
    push_ok(&server, json!({"device_key": key, "body": "while-away-4"})).await;

    // Reconnect echoing the last seen id: exactly ids 2..=4 replay, in order,
    // as ordinary `event: message` frames indistinguishable from live ones.
    let mut stream = SseStream::open_with(&server, &token, Some("1")).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    let replayed = read_push_events(&mut stream, 3, Duration::from_secs(10)).await;
    for ((frame, data), (expected_id, expected_body)) in replayed.into_iter().zip([
        (2, "while-away-2"),
        (3, "while-away-3"),
        (4, "while-away-4"),
    ]) {
        assert_eq!(
            frame.id.as_deref(),
            Some(expected_id.to_string().as_str()),
            "replay order"
        );
        assert_eq!(frame.event.as_deref(), Some("message"));
        assert_eq!(data["id"], expected_id, "data id equals the SSE id line");
        assert_eq!(data["body"], expected_body);
        assert_event_shape(&data, &key);
    }

    // The replay hands off seamlessly to the live subscription: the next
    // push arrives exactly once (never replayed again).
    push_ok(&server, json!({"device_key": key, "body": "live-5"})).await;
    let [(frame, data)] = read_push_events(&mut stream, 1, Duration::from_secs(10))
        .await
        .try_into()
        .unwrap();
    assert_eq!(frame.id.as_deref(), Some("5"));
    assert_eq!(data["body"], "live-5");
    assert_no_push_events(&mut stream, Duration::from_secs(2)).await;
    drop(stream);

    // A full cycle again: disconnect after N, push N+1, reconnect with
    // Last-Event-ID=N → exactly N+1 replayed.
    let mut stream = SseStream::open_with(&server, &token, Some("5")).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    push_ok(&server, json!({"device_key": key, "body": "live-6"})).await;
    let [(frame, data)] = read_push_events(&mut stream, 1, Duration::from_secs(10))
        .await
        .try_into()
        .unwrap();
    assert_eq!(frame.id.as_deref(), Some("6"));
    assert_eq!(data["body"], "live-6");
    server.shutdown().await;
}

#[tokio::test]
async fn absent_and_empty_last_event_id_start_fresh() {
    // The acceptance contract: empty/absent Last-Event-ID behaves as a fresh
    // subscription (no replay) — also on a first connect, where there is no
    // "reconnect" at all.
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let token = mint_token(&server, &key).await;

    push_numbered(&server, &key, 2).await;

    // Absent header: no replay; ids continue from the store counter.
    let mut stream = SseStream::open(&server, &token).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    assert_no_push_events(&mut stream, Duration::from_secs(2)).await;
    push_ok(&server, json!({"device_key": key, "body": "live-3"})).await;
    let [(frame, data)] = read_push_events(&mut stream, 1, Duration::from_secs(10))
        .await
        .try_into()
        .unwrap();
    assert_eq!(
        frame.id.as_deref(),
        Some("3"),
        "ids continue across the gap"
    );
    assert_eq!(data["body"], "live-3");
    drop(stream);

    // Empty header value: same fresh-subscription behavior.
    let mut stream = SseStream::open_with(&server, &token, Some("")).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    assert_no_push_events(&mut stream, Duration::from_secs(2)).await;
    push_ok(&server, json!({"device_key": key, "body": "live-4"})).await;
    let [(frame, data)] = read_push_events(&mut stream, 1, Duration::from_secs(10))
        .await
        .try_into()
        .unwrap();
    assert_eq!(frame.id.as_deref(), Some("4"));
    assert_eq!(data["body"], "live-4");
    server.shutdown().await;
}

#[tokio::test]
async fn non_numeric_last_event_id_is_treated_as_absent() {
    // Contract choice (documented in api/sse.rs): a non-numeric
    // Last-Event-ID never fails the connect and never replays — the same
    // semantics as an absent header, matching WHATWG's lenient parse of the
    // last event id buffer. The stream then behaves normally.
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let token = mint_token(&server, &key).await;

    push_numbered(&server, &key, 2).await;

    for presented in ["not-a-number", "12.5", "-x"] {
        let mut stream = SseStream::open_with(&server, &token, Some(presented)).await;
        assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
        assert_no_push_events(&mut stream, Duration::from_secs(2)).await;
        drop(stream);
    }

    // The stream still delivers live events with continuing ids.
    let mut stream = SseStream::open_with(&server, &token, Some("garbage")).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    push_ok(&server, json!({"device_key": key, "body": "live-3"})).await;
    let [(frame, data)] = read_push_events(&mut stream, 1, Duration::from_secs(10))
        .await
        .try_into()
        .unwrap();
    assert_eq!(frame.id.as_deref(), Some("3"));
    assert_eq!(data["body"], "live-3");
    server.shutdown().await;
}

#[tokio::test]
async fn replay_never_gaps_or_duplicates_under_concurrent_publishes() {
    // The no-gap/no-duplicate guarantee, stressed: the replay scan races
    // concurrent publishes to the same Device. Every push must arrive
    // exactly once, and the concatenated replay+live sequence must be the
    // exact monotonic id order — whatever the interleaving.
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let token = mint_token(&server, &key).await;

    // 150 retained messages before any stream exists.
    push_numbered(&server, &key, 150).await;

    // Concurrently: connect asking to replay from the very beginning AND
    // publish 100 more messages. The replay scan and the live subscription
    // must tile without overlap: 150 pre-pushes were in the store before
    // the scan; each racing push lands either in the scan or on the live
    // subscription (never both, never neither).
    let connect = SseStream::open_with(&server, &token, Some("0"));
    let pushes = {
        let server = &server;
        let key = key.clone();
        async move {
            for n in 151..=250 {
                push_ok(server, json!({"device_key": key, "body": format!("m{n}")})).await;
            }
        }
    };
    let (mut stream, ()) = tokio::join!(connect, pushes);

    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);

    let events = read_push_events(&mut stream, 250, Duration::from_secs(60)).await;
    let mut seen = Vec::new();
    for ((frame, data), expected_id) in events.iter().zip(1..=250) {
        let got = frame.id.as_deref().unwrap_or("<none>").to_string();
        assert_eq!(
            got,
            expected_id.to_string(),
            "event {expected_id} of 250 must arrive in exact monotonic order"
        );
        assert_eq!(data["id"], expected_id);
        assert_eq!(data["body"], format!("m{expected_id}"), "no duplicates");
        seen.push(got);
    }
    assert_eq!(seen.len(), 250, "every id exactly once");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Retention: per-Device TTL + cap bound what replay can return (ADR-0002);
// pruning is lazy (insert-time) but the replay boundary must never show a
// pruned/expired message, and /info's pending_messages reflects the
// retained (replayable) count
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_messages_are_never_replayed_nor_counted() {
    // TTL 1s and the message expires with NO insert afterwards — the lazy
    // insert-time pruning never ran, so the replay scan and the /info count
    // must apply the TTL themselves: an expired-but-unpruned row is
    // invisible at the replay boundary.
    let server = spawn_configured(|c| c.sse_message_ttl_secs = 1).await;
    let key = register_stream_device(&server).await;
    let token = mint_token(&server, &key).await;

    push_ok(&server, json!({"device_key": key, "body": "will-expire"})).await;
    let body = info(&server).await;
    assert_eq!(body["pending_messages"], 1, "retained until it expires");
    tokio::time::sleep(Duration::from_millis(2100)).await; // TTL 1s → expired

    let body = info(&server).await;
    assert_eq!(
        body["pending_messages"], 0,
        "expired message is not retained (not replayable): {body}"
    );

    // Replay from the very beginning: the expired message never comes.
    let mut stream = SseStream::open_with(&server, &token, Some("0")).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    assert_no_push_events(&mut stream, Duration::from_secs(2)).await;

    // The stream still works: live pushes continue the id sequence (the
    // monotonic counter never regresses under pruning).
    push_ok(&server, json!({"device_key": key, "body": "live-2"})).await;
    let [(frame, data)] = read_push_events(&mut stream, 1, Duration::from_secs(10))
        .await
        .try_into()
        .unwrap();
    assert_eq!(frame.id.as_deref(), Some("2"));
    assert_eq!(data["body"], "live-2");
    server.shutdown().await;
}

#[tokio::test]
async fn ttl_prunes_expired_rows_on_insert() {
    // Insert-time lazy pruning: pushing a new message to the Device prunes
    // its expired rows under the same store lock — no sweeper involved.
    let server = spawn_configured(|c| c.sse_message_ttl_secs = 1).await;
    let key = register_stream_device(&server).await;

    push_ok(&server, json!({"device_key": key, "body": "m1"})).await;
    push_ok(&server, json!({"device_key": key, "body": "m2"})).await;
    let body = info(&server).await;
    assert_eq!(body["pending_messages"], 2, "both retained: {body}");

    tokio::time::sleep(Duration::from_millis(2100)).await; // TTL 1s → expired
    push_ok(&server, json!({"device_key": key, "body": "m3"})).await;
    let body = info(&server).await;
    assert_eq!(
        body["pending_messages"], 1,
        "the insert pruned m1 and m2, kept only the new m3: {body}"
    );

    // Replay boundary: only m3 is retained.
    let token = mint_token(&server, &key).await;
    let mut stream = SseStream::open_with(&server, &token, Some("0")).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    let events = read_push_events(&mut stream, 1, Duration::from_secs(10)).await;
    let [(frame, data)] = events.try_into().unwrap();
    assert_eq!(frame.id.as_deref(), Some("3"));
    assert_eq!(data["body"], "m3");
    assert_no_push_events(&mut stream, Duration::from_secs(2)).await;
    server.shutdown().await;
}

#[tokio::test]
async fn cap_drops_oldest_and_stale_id_replays_from_oldest_retained() {
    // Cap 3 with 5 pushes: the two oldest rows are dropped. A reconnect
    // whose Last-Event-ID predates the retained floor is not an error —
    // replay starts at the OLDEST RETAINED message (ADR-0002 acceptance).
    let server = spawn_configured(|c| c.sse_message_cap = 3).await;
    let key = register_stream_device(&server).await;
    let token = mint_token(&server, &key).await;

    push_numbered(&server, &key, 5).await;
    let body = info(&server).await;
    assert_eq!(
        body["pending_messages"], 3,
        "cap keeps only the newest 3 (ids 3,4,5): {body}"
    );

    let mut stream = SseStream::open_with(&server, &token, Some("2")).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    let replayed = read_push_events(&mut stream, 3, Duration::from_secs(10)).await;
    for ((frame, data), (expected_id, expected_body)) in
        replayed.into_iter().zip([(3, "m3"), (4, "m4"), (5, "m5")])
    {
        assert_eq!(
            frame.id.as_deref(),
            Some(expected_id.to_string().as_str()),
            "replay starts at the oldest retained message"
        );
        assert_eq!(data["body"], expected_body);
    }

    // Live continues from the store counter (ids never regress).
    push_ok(&server, json!({"device_key": key, "body": "live-6"})).await;
    let [(frame, data)] = read_push_events(&mut stream, 1, Duration::from_secs(10))
        .await
        .try_into()
        .unwrap();
    assert_eq!(frame.id.as_deref(), Some("6"));
    assert_eq!(data["body"], "live-6");
    server.shutdown().await;
}

#[tokio::test]
async fn zero_ttl_and_zero_cap_disable_retention() {
    // 0 on either knob disables that limit (documented parallel to
    // --sse-keepalive-secs 0): nothing is TTL-pruned, nothing is
    // cap-pruned — including messages well past the "would-be" TTL.
    let server = spawn_configured(|c| {
        c.sse_message_ttl_secs = 0;
        c.sse_message_cap = 0;
    })
    .await;
    let key = register_stream_device(&server).await;
    let token = mint_token(&server, &key).await;

    push_numbered(&server, &key, 5).await;
    tokio::time::sleep(Duration::from_millis(2100)).await; // past any 1s-ish TTL

    let body = info(&server).await;
    assert_eq!(body["pending_messages"], 5, "cap disabled: {body}");

    let mut stream = SseStream::open_with(&server, &token, Some("0")).await;
    assert_connected(&stream.read_frames(1, Duration::from_secs(5)).await[0]);
    let replayed = read_push_events(&mut stream, 5, Duration::from_secs(15)).await;
    for ((frame, data), expected_id) in replayed.iter().zip(1..=5) {
        assert_eq!(frame.id.as_deref(), Some(expected_id.to_string().as_str()));
        assert_eq!(data["body"], format!("m{expected_id}"));
    }
    server.shutdown().await;
}
