//! Ticket 07 acceptance: stream registration + Stream Tokens over the HTTP
//! boundary — the `stream` device type at `/register` (token-less, ADR-0006
//! additive extension) and the realtime credential plane under
//! `/realtime/v1` (mint / list / revoke Stream Tokens). The SSE endpoint
//! itself is the next ticket.
//!
//! Design decisions pinned here are documented in `src/api/realtime.rs` and
//! transcribed into `docs/protocol.md` by the protocol ticket.

mod common;

use bark_server_rs::config::Config;
use common::{TestServer, assert_envelope_no_data, client, ephemeral_config, server_header};
use serde_json::{Value, json};

/// Spawn a server for realtime-plane tests.
async fn spawn() -> TestServer {
    let (config, dir) = ephemeral_config();
    TestServer::spawn(config, dir).await
}

/// Spawn a server with Basic Auth enabled (u/p).
async fn spawn_auth() -> TestServer {
    let (mut config, dir) = ephemeral_config();
    config.basic_auth_user = "u".into();
    config.basic_auth_password = "p".into();
    TestServer::spawn(config, dir).await
}

fn config_with(data_dir: std::path::PathBuf) -> Config {
    Config {
        addr: format!("127.0.0.1:{}", common::free_port()),
        data_dir,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Upstream shortuuid default alphabet (see shortuuid.rs / register_seam.rs).
const BASE57: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The base64url (RFC 4648 §5, unpadded) alphabet used by Stream Tokens.
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Assert a stream registration success envelope and return the Device Key.
/// Stream Devices carry no Device Token: the response echoes `""`.
fn assert_stream_register(body: &Value) -> String {
    assert_eq!(body["code"], 200, "success envelope code: {body}");
    assert_eq!(body["message"], "success", "success message: {body}");
    let data = body
        .get("data")
        .and_then(Value::as_object)
        .expect("success envelope carries data object");
    let mut fields: Vec<&String> = data.keys().collect();
    fields.sort();
    assert_eq!(
        fields,
        ["device_key", "device_token", "device_type", "key"],
        "data must contain exactly key/device_key/device_token/device_type: {body}"
    );
    let key = body["data"]["key"].as_str().expect("key string");
    assert_eq!(key.len(), 22, "device key must be 22 chars: {key:?}");
    assert!(
        key.bytes().all(|c| BASE57.contains(&c)),
        "device key must use the base57 alphabet: {key:?}"
    );
    assert_eq!(body["data"]["device_key"], body["data"]["key"]);
    assert_eq!(
        body["data"]["device_token"], "",
        "stream devices have no Device Token: {body}"
    );
    assert_eq!(body["data"]["device_type"], "stream");
    key.to_string()
}

/// Register a Stream Device (no Device Token) and return its Device Key.
async fn register_stream_device(server: &TestServer) -> String {
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_type": "stream"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_stream_register(&body)
}

/// Register an ios Device with the given APNs token and return its key.
async fn register_ios_device(server: &TestServer, token: &str) -> String {
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": token}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    body["data"]["key"]
        .as_str()
        .expect("key string")
        .to_string()
}

/// Assert a mint/list/revoke success envelope and return its `data`.
fn assert_success_data(body: &Value) -> Value {
    assert_eq!(body["code"], 200, "success envelope code: {body}");
    assert_eq!(body["message"], "success", "success message: {body}");
    assert!(
        body["timestamp"].is_i64(),
        "envelope timestamp must be an integer: {body}"
    );
    body.get("data").cloned().expect("success carries data")
}

/// Assert a Stream Token's shape: `st_` + 43 unpadded base64url chars
/// (32 random bytes = 256 bits of entropy).
fn assert_token_shape(token: &str) {
    let secret = token
        .strip_prefix("st_")
        .unwrap_or_else(|| panic!("token must carry the st_ prefix: {token:?}"));
    assert_eq!(
        secret.len(),
        43,
        "token secret must be 43 base64url chars: {token:?}"
    );
    assert!(
        secret.bytes().all(|c| B64URL.contains(&c)),
        "token secret must be base64url: {token:?}"
    );
}

/// Mint a Stream Token for `device_key` (presenting the Device Key in the
/// `X-Device-Key` header — the agreed credential channel) with `body` as the
/// JSON request body. Asserts HTTP 200 + success envelope, returns data.
async fn mint(server: &TestServer, device_key: &str, body: Value) -> Value {
    let res = client()
        .post(server.url(&format!("/realtime/v1/devices/{device_key}/streams")))
        .header("X-Device-Key", device_key)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "mint must succeed: {body}");
    assert_eq!(server_header(&res), "Bark");
    let envelope: Value = res.json().await.unwrap();
    assert_success_data(&envelope)
}

/// Assert a mint/list-item data object carries exactly the documented fields.
fn assert_data_fields(data: &Value, expect_token: bool) {
    let obj = data.as_object().expect("data object");
    let mut fields: Vec<&String> = obj.keys().collect();
    fields.sort();
    let mut expected = vec![
        "client_label",
        "created_at",
        "device_key",
        "revoked",
        "token_hint",
        "token_id",
    ];
    if expect_token {
        expected.push("token");
    }
    expected.sort();
    assert_eq!(
        fields, expected,
        "documented data fields (expect_token={expect_token}): {data}"
    );
}

// ---------------------------------------------------------------------------
// `stream` device type at /register (token-less, ADR-0006 additive)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stream_type_registers_without_device_token() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_type": "stream"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();
    assert_stream_register(&body);
    server.shutdown().await;
}

#[tokio::test]
async fn stream_type_ignores_any_provided_device_token() {
    // A Stream Device has no Device Token (GLOSSARY.md); a provided one is
    // ignored and stored empty, so the response echoes "".
    let server = spawn().await;
    for payload in [
        json!({"device_token": "tokABC", "device_type": "stream"}),
        json!({"devicetoken": "oldAlias", "device_type": "stream"}),
    ] {
        let res = client()
            .post(server.url("/register"))
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "payload {payload}");
        let body: Value = res.json().await.unwrap();
        assert_stream_register(&body);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn stream_type_matches_case_insensitively() {
    let server = spawn().await;
    for provided in ["stream", "STREAM", "Stream", "sTrEaM"] {
        let res = client()
            .post(server.url("/register"))
            .json(&json!({"device_type": provided}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "type {provided:?} must be accepted");
        let body: Value = res.json().await.unwrap();
        assert_stream_register(&body);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn legacy_get_register_accepts_stream_type() {
    // The legacy query-bind compat route takes the same device types.
    let server = spawn().await;
    let res = client()
        .get(server.url("/register?device_type=stream"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_stream_register(&body);
    server.shutdown().await;
}

#[tokio::test]
async fn ios_and_watchos_still_require_device_token() {
    // The stream relaxation must not leak into the upstream types: their
    // validation stays byte-identical.
    let server = spawn().await;
    for device_type in ["ios", "watchos"] {
        let res = client()
            .post(server.url("/register"))
            .json(&json!({"device_type": device_type}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400, "type {device_type:?}");
        let body: Value = res.json().await.unwrap();
        assert_envelope_no_data(&body, 400, "device token is empty");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn unknown_device_types_still_rejected() {
    let server = spawn().await;
    for provided in ["android", "ANDROID", "streamx"] {
        let res = client()
            .post(server.url("/register"))
            .json(&json!({"device_token": "tok", "device_type": provided}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400, "type {provided:?}");
        let body: Value = res.json().await.unwrap();
        // Upstream quotes the value as provided, before lowercasing.
        assert_envelope_no_data(&body, 400, &format!("invalid device type: {provided}"));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn register_check_stays_token_based_for_stream_devices() {
    // `GET /register/{key}` is an upstream compat route keyed on Device Token
    // presence (bbolt blank-token semantics). Stream Devices have none, so it
    // answers the upstream blank-token error — documented; realtime clients
    // verify registration via the register response or /realtime/v1 instead.
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let res = client()
        .get(server.url(&format!("/register/{key}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 400, "device token invalid");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// POST /realtime/v1/devices/{device_key}/streams — mint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_on_stream_device_returns_full_token_once() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let data = mint(&server, &key, json!({"client_label": "macbook"})).await;
    assert_data_fields(&data, true);
    assert_eq!(data["device_key"], key);
    assert_eq!(data["client_label"], "macbook");
    assert_eq!(data["revoked"], false);
    let token = data["token"].as_str().expect("token string");
    assert_token_shape(token);
    let token_id = data["token_id"].as_str().expect("token_id string");
    assert_eq!(token_id.len(), 16, "token_id is 16 hex chars: {token_id:?}");
    assert!(
        token_id.bytes().all(|c| c.is_ascii_hexdigit()),
        "token_id must be hex: {token_id:?}"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let created = data["created_at"].as_i64().expect("created_at integer");
    assert!(
        (now - created).abs() <= 5,
        "created_at {created} not near now {now}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn mint_works_on_any_device_type_bridge_model() {
    // Streams attach to any existing Device (ADR-0006 bridge model): an ios
    // Device with an APNs token still mirrors pushes over SSE.
    let server = spawn().await;
    let key = register_ios_device(&server, "apnsToken1").await;
    let data = mint(&server, &key, json!({"client_label": "linux-box"})).await;
    assert_eq!(data["device_key"], key);
    assert_token_shape(data["token"].as_str().expect("token string"));
    server.shutdown().await;
}

#[tokio::test]
async fn mint_missing_device_key_header_is_401() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let res = client()
        .post(server.url(&format!("/realtime/v1/devices/{key}/streams")))
        .json(&json!({"client_label": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 401, "device key required");
    server.shutdown().await;
}

#[tokio::test]
async fn mint_empty_or_wrong_device_key_header_is_401() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    for presented in ["", "wrongKey123"] {
        let res = client()
            .post(server.url(&format!("/realtime/v1/devices/{key}/streams")))
            .header("X-Device-Key", presented)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401, "presented {presented:?}");
        let body: Value = res.json().await.unwrap();
        assert_envelope_no_data(&body, 401, "device key mismatch");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn mint_unknown_device_is_404() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/realtime/v1/devices/unknownDeviceKey000000/streams"))
        .header("X-Device-Key", "unknownDeviceKey000000")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 404, "device not found");
    server.shutdown().await;
}

#[tokio::test]
async fn mint_body_validation_errors() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let url = server.url(&format!("/realtime/v1/devices/{key}/streams"));

    // Not JSON at all.
    let res = client()
        .post(&url)
        .header("X-Device-Key", &key)
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "invalid JSON body",
    );

    // JSON but not an object.
    let res = client()
        .post(&url)
        .header("X-Device-Key", &key)
        .json(&json!([1, 2]))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "request body must be a JSON object",
    );

    // client_label of the wrong type.
    let res = client()
        .post(&url)
        .header("X-Device-Key", &key)
        .json(&json!({"client_label": 42}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "client_label must be a string",
    );

    // Overlong client_label (256 bytes is the documented cap).
    let res = client()
        .post(&url)
        .header("X-Device-Key", &key)
        .json(&json!({"client_label": "x".repeat(257)}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "client_label too long",
    );
    server.shutdown().await;
}

#[tokio::test]
async fn mint_label_is_optional_and_capped_exactly_at_256() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;

    // Missing label → default "".
    let data = mint(&server, &key, json!({})).await;
    assert_eq!(data["client_label"], "");

    // Unknown body fields are ignored, like upstream register.
    let data = mint(&server, &key, json!({"client_label": "a", "junk": [1]})).await;
    assert_eq!(data["client_label"], "a");

    // Exactly 256 bytes passes.
    let data = mint(&server, &key, json!({"client_label": "y".repeat(256)})).await;
    assert_eq!(data["client_label"], "y".repeat(256));
    server.shutdown().await;
}

#[tokio::test]
async fn mint_multiple_tokens_per_device_are_distinct() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let first = mint(&server, &key, json!({"client_label": "laptop"})).await;
    let second = mint(&server, &key, json!({"client_label": "desktop"})).await;
    assert_ne!(first["token"], second["token"], "tokens must be distinct");
    assert_ne!(
        first["token_id"], second["token_id"],
        "ids must be distinct"
    );
    assert_eq!(first["client_label"], "laptop");
    assert_eq!(second["client_label"], "desktop");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// GET /realtime/v1/devices/{device_key}/streams — list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_empty_for_device_without_tokens() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let res = client()
        .get(server.url(&format!("/realtime/v1/devices/{key}/streams")))
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();
    let data = assert_success_data(&body);
    assert_eq!(data, json!([]), "fresh device lists no tokens: {data}");
    server.shutdown().await;
}

#[tokio::test]
async fn list_returns_hints_never_full_tokens() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let first = mint(&server, &key, json!({"client_label": "laptop"})).await;
    let second = mint(&server, &key, json!({"client_label": "desktop"})).await;

    let res = client()
        .get(server.url(&format!("/realtime/v1/devices/{key}/streams")))
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let data = assert_success_data(&body);
    let items = data.as_array().expect("data is an array of summaries");
    assert_eq!(items.len(), 2, "both tokens listed: {data}");

    for (item, minted) in items.iter().zip([&first, &second]) {
        assert_data_fields(item, false); // no `token` field, ever
        let token = minted["token"].as_str().expect("minted token");
        let hint = item["token_hint"].as_str().expect("hint string");
        assert_eq!(
            hint,
            format!("{}...", &token[..12]),
            "hint is the first 12 chars of the full token plus an ellipsis"
        );
        assert_eq!(item["token_id"], minted["token_id"]);
        assert_eq!(item["client_label"], minted["client_label"]);
        assert_eq!(item["created_at"], minted["created_at"]);
        assert_eq!(item["revoked"], false);
        assert_eq!(item["device_key"], key);
    }
    // Creation order: the first minted token lists first.
    assert_eq!(items[0]["token_id"], first["token_id"]);
    server.shutdown().await;
}

#[tokio::test]
async fn list_is_scoped_to_the_path_device() {
    let server = spawn().await;
    let key_a = register_stream_device(&server).await;
    let key_b = register_stream_device(&server).await;
    mint(&server, &key_a, json!({"client_label": "only-on-a"})).await;

    let res = client()
        .get(server.url(&format!("/realtime/v1/devices/{key_b}/streams")))
        .header("X-Device-Key", &key_b)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        assert_success_data(&body),
        json!([]),
        "b sees none of a's tokens"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn list_error_branches() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;

    let res = client()
        .get(server.url(&format!("/realtime/v1/devices/{key}/streams")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        401,
        "device key required",
    );

    let res = client()
        .get(server.url(&format!("/realtime/v1/devices/{key}/streams")))
        .header("X-Device-Key", "other")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        401,
        "device key mismatch",
    );

    let res = client()
        .get(server.url("/realtime/v1/devices/unknownDeviceKey000000/streams"))
        .header("X-Device-Key", "unknownDeviceKey000000")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_envelope_no_data(&res.json::<Value>().await.unwrap(), 404, "device not found");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// DELETE /realtime/v1/devices/{device_key}/streams/{token_id} — revoke
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_marks_token_revoked_in_list() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let minted = mint(&server, &key, json!({"client_label": "laptop"})).await;
    let token_id = minted["token_id"].as_str().unwrap();

    let res = client()
        .delete(server.url(&format!("/realtime/v1/devices/{key}/streams/{token_id}")))
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();
    let data = assert_success_data(&body);
    assert_data_fields(&data, false);
    assert_eq!(data["token_id"], token_id);
    assert_eq!(data["client_label"], "laptop");
    assert_eq!(data["device_key"], key);
    assert_eq!(data["created_at"], minted["created_at"]);
    assert_eq!(data["revoked"], true);

    // The revocation is visible through the list — the state ticket 07's SSE
    // auth path consumes.
    let res = client()
        .get(server.url(&format!("/realtime/v1/devices/{key}/streams")))
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    let items = assert_success_data(&body).as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["revoked"], true,
        "revoked token shows revoked: {items:?}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn revoke_unknown_token_is_404() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let res = client()
        .delete(server.url(&format!(
            "/realtime/v1/devices/{key}/streams/0123456789abcdef"
        )))
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 404, "stream token not found");
    server.shutdown().await;
}

#[tokio::test]
async fn revoke_token_of_another_device_is_404() {
    // Token ids are scoped per Device: revoking under device B a token that
    // belongs to device A looks the same as an unknown token (no leak).
    let server = spawn().await;
    let key_a = register_stream_device(&server).await;
    let key_b = register_stream_device(&server).await;
    let minted = mint(&server, &key_a, json!({"client_label": "on-a"})).await;
    let token_id = minted["token_id"].as_str().unwrap();

    let res = client()
        .delete(server.url(&format!("/realtime/v1/devices/{key_b}/streams/{token_id}")))
        .header("X-Device-Key", &key_b)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        404,
        "stream token not found",
    );

    // A's token is untouched.
    let res = client()
        .get(server.url(&format!("/realtime/v1/devices/{key_a}/streams")))
        .header("X-Device-Key", &key_a)
        .send()
        .await
        .unwrap();
    let items = assert_success_data(&res.json::<Value>().await.unwrap())
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(
        items[0]["revoked"], false,
        "cross-device revoke must not apply"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn revoke_already_revoked_token_is_409() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let minted = mint(&server, &key, json!({})).await;
    let token_id = minted["token_id"].as_str().unwrap();
    let url = server.url(&format!("/realtime/v1/devices/{key}/streams/{token_id}"));

    let res = client()
        .delete(&url)
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "first revoke succeeds");

    let res = client()
        .delete(&url)
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409, "second revoke conflicts");
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        409,
        "stream token already revoked",
    );
    server.shutdown().await;
}

#[tokio::test]
async fn revoke_error_branches() {
    let server = spawn().await;
    let key = register_stream_device(&server).await;
    let url = server.url(&format!(
        "/realtime/v1/devices/{key}/streams/0123456789abcdef"
    ));

    // Missing header → 401 before anything else.
    let res = client().delete(&url).send().await.unwrap();
    assert_eq!(res.status(), 401);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        401,
        "device key required",
    );

    // Wrong header → 401.
    let res = client()
        .delete(&url)
        .header("X-Device-Key", "x")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        401,
        "device key mismatch",
    );

    // Unknown device → 404 (auth checks pass, device does not exist).
    let res = client()
        .delete(server.url("/realtime/v1/devices/unknownDeviceKey000000/streams/0123456789abcdef"))
        .header("X-Device-Key", "unknownDeviceKey000000")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_envelope_no_data(&res.json::<Value>().await.unwrap(), 404, "device not found");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Operators' Basic Auth still wraps the realtime plane
// ---------------------------------------------------------------------------

#[tokio::test]
async fn basic_auth_applies_to_realtime_routes() {
    // /realtime/v1 is not in upstream's auth-free list (/ping, /register,
    // /healthz): with Basic Auth configured, the teapot fires before the
    // Device Key check; correct Basic Auth credentials let the handler run.
    let server = spawn_auth().await;
    let key = register_stream_device(&server).await; // /register is exempt
    let url = server.url(&format!("/realtime/v1/devices/{key}/streams"));

    let res = client().post(&url).json(&json!({})).send().await.unwrap();
    assert_eq!(res.status(), 418, "no basic auth → teapot");
    assert_eq!(res.text().await.unwrap(), "I'm a teapot");

    // Correct Basic Auth but no Device Key header: the request reaches the
    // handler, whose own auth check fires.
    let res = client()
        .post(&url)
        .basic_auth("u", Some("p"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        401,
        "past basic auth, Device Key check applies"
    );
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        401,
        "device key required",
    );

    // Full chain: Basic Auth + Device Key header → mint succeeds.
    let res = client()
        .post(&url)
        .header("X-Device-Key", &key)
        .basic_auth("u", Some("p"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "basic auth + device key → mint");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Persistence: tokens and revocations survive a server restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stream_tokens_survive_restart() {
    let dir = tempfile::tempdir().expect("temp dir");
    let server = TestServer::spawn_with_data_dir(config_with(dir.path().to_path_buf())).await;
    let key = register_stream_device(&server).await;
    let minted = mint(&server, &key, json!({"client_label": "persist"})).await;
    let token_id = minted["token_id"].as_str().unwrap().to_string();
    let url = server.url(&format!("/realtime/v1/devices/{key}/streams/{token_id}"));
    client()
        .delete(&url)
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    server.shutdown().await;

    let server = TestServer::spawn_with_data_dir(config_with(dir.path().to_path_buf())).await;
    let res = client()
        .get(server.url(&format!("/realtime/v1/devices/{key}/streams")))
        .header("X-Device-Key", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let items = assert_success_data(&res.json::<Value>().await.unwrap())
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(items.len(), 1, "token persisted across restart: {items:?}");
    assert_eq!(items[0]["token_id"], token_id);
    assert_eq!(items[0]["client_label"], "persist");
    assert_eq!(
        items[0]["revoked"], true,
        "revocation persisted across restart"
    );
    server.shutdown().await;
}
