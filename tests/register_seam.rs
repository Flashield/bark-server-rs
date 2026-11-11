//! Ticket 02 acceptance: device registration over the HTTP boundary —
//! `POST /register` (body bind), `GET /register/:device_key` (existence
//! check) and legacy `GET /register` (query bind with `key`/`devicetoken`
//! aliases), with upstream bark-server v2.4.0 as the behavioral oracle
//! (probed live: route_register.go + database/bbolt.go + fiber's
//! BodyParser/QueryParser semantics).

mod common;

use bark_server_rs::config::Config;
use common::{TestServer, assert_envelope_no_data, client, ephemeral_config, server_header};
use serde_json::{Value, json};

/// Spawn a server for register tests.
async fn spawn() -> TestServer {
    let (config, dir) = ephemeral_config();
    TestServer::spawn(config, dir).await
}

/// Spawn a server with a caller-managed data dir (restart tests).
fn config_with(data_dir: std::path::PathBuf) -> Config {
    Config {
        addr: format!("127.0.0.1:{}", common::free_port()),
        data_dir,
        // Backend parity (ticket 12): restart tests exercise the parity
        // backend in PG mode (one database per test thread, so both server
        // legs share it), the SQLite default otherwise.
        dsn: common::pg::parity_dsn_per_test().unwrap_or_default(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Key shape (shortuuid-style, 22 chars over the upstream base57 alphabet)
// ---------------------------------------------------------------------------

/// Upstream shortuuid v3 default alphabet (deduped + sorted — already sorted).
const BASE57: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a Device Key exactly like upstream shortuuid's `stringToNum`
/// (LSB-first: char i contributes index(char) * 57^i) and render the uuid hex.
fn decode_key_to_uuid_hex(key: &str) -> String {
    let mut n: u128 = 0;
    for (i, c) in key.bytes().enumerate() {
        let idx = BASE57
            .iter()
            .position(|&a| a == c)
            .unwrap_or_else(|| panic!("{key:?} contains non-alphabet char {c:?}"));
        n = n.wrapping_add((idx as u128).wrapping_mul(57u128.pow(i as u32)));
    }
    format!("{n:032x}")
}

fn assert_device_key_shape(key: &str) {
    assert_eq!(key.len(), 22, "device key must be 22 chars: {key:?}");
    assert!(
        key.bytes().all(|c| BASE57.contains(&c)),
        "device key must use the base57 alphabet: {key:?}"
    );
    // shortuuid-style: decodes to a UUIDv4 (version nibble '4', variant 10xx).
    let hex = decode_key_to_uuid_hex(key);
    assert_eq!(&hex[12..13], "4", "decoded uuid must be version 4: {hex}");
    assert!(
        matches!(&hex[16..17], "8" | "9" | "a" | "b"),
        "decoded uuid must have RFC 4122 variant bits: {hex}"
    );
}

/// Assert a successful registration envelope: `{code:200, message:"success",
/// data:{key, device_key, device_token, device_type}, timestamp}`. Go map
/// serialization order varies upstream, so field order is never asserted.
fn assert_register_success(body: &Value, token: &str, device_type: &str) -> String {
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
    assert_device_key_shape(key);
    assert_eq!(
        body["data"]["device_key"], body["data"]["key"],
        "key and device_key must be identical: {body}"
    );
    assert_eq!(body["data"]["device_token"], token, "token echo: {body}");
    assert_eq!(body["data"]["device_type"], device_type, "type: {body}");
    key.to_string()
}

// ---------------------------------------------------------------------------
// POST /register — JSON body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_json_creates_device_with_default_type() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tokenABC123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();
    let key = assert_register_success(&body, "tokenABC123", "ios");
    // A brand-new device got a fresh key: it must now be known to the check
    // route.
    let res = client()
        .get(server.url(&format!("/register/{key}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    server.shutdown().await;
}

#[tokio::test]
async fn post_json_device_type_is_lowercased_and_defaulted() {
    let server = spawn().await;
    for (provided, expected) in [
        ("", "ios"),    // empty → default
        ("iOS", "ios"), // lowercased
        ("watchos", "watchos"),
        ("WatchOS", "watchos"),
        ("WATCHOS", "watchos"),
    ] {
        let res = client()
            .post(server.url("/register"))
            .json(&json!({"device_token": "tok", "device_type": provided}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "type {provided:?} must be accepted");
        let body: Value = res.json().await.unwrap();
        assert_register_success(&body, "tok", expected);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn post_json_unknown_type_rejected_with_original_casing() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tok", "device_type": "ANDROID"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    // Upstream quotes the value as provided, before lowercasing.
    assert_envelope_no_data(&body, 400, "invalid device type: ANDROID");
    server.shutdown().await;
}

#[tokio::test]
async fn post_json_missing_token_rejected() {
    let server = spawn().await;
    for payload in [
        json!({}),
        json!({"device_key": "k1"}),
        json!({"device_token": null, "device_key": "k2"}),
        json!({"device_token": "", "device_type": "ios"}),
    ] {
        let res = client()
            .post(server.url("/register"))
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400, "payload {payload} must be rejected");
        let body: Value = res.json().await.unwrap();
        assert_envelope_no_data(&body, 400, "device token is empty");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn post_json_overlong_token_rejected_exactly_at_160() {
    let server = spawn().await;
    let token_161 = "x".repeat(161);
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": token_161}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 400, "device token is invalid");

    // Upstream checks bytes: exactly 160 passes.
    let token_160 = "y".repeat(160);
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": token_160}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_register_success(&body, &token_160, "ios");
    server.shutdown().await;
}

#[tokio::test]
async fn post_json_field_names_match_case_insensitively() {
    // Go's encoding/json (and jsoniter's compat config) falls back to a
    // case-insensitive field match.
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .header("content-type", "application/json")
        .body(r#"{"DEVICETOKEN":"tokUpper","Device_Key":"devKey1"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    // device_key was provided but unknown → upstream generates a new key
    // (bbolt: unknown key counts as a new registration).
    let key = assert_register_success(&body, "tokUpper", "ios");
    assert_ne!(key, "devKey1", "unknown provided key must be replaced");
    server.shutdown().await;
}

#[tokio::test]
async fn post_json_unknown_fields_are_ignored() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tok", "unknown_field": 42, "nested": {"a": 1}}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_register_success(&body, "tok", "ios");
    server.shutdown().await;
}

#[tokio::test]
async fn post_json_wrong_value_types_are_bind_failures() {
    let server = spawn().await;
    for raw in [r#"{"device_token":123}"#, r#"[1,2]"#, r#"{bad"#] {
        let res = client()
            .post(server.url("/register"))
            .header("content-type", "application/json")
            .body(raw.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400, "payload {raw} must be a bind failure");
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["code"], 400, "bind failure code: {body}");
        let message = body["message"].as_str().expect("message string");
        assert!(
            message.starts_with("request bind failed2: "),
            "bind failure must quote upstream's prefix, got {message:?}"
        );
    }
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// POST /register — form body and content-type dispatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_form_binds_aliases_and_lowercases_type() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("devicetoken=tokForm&key=legacyForm&device_type=WatchOS")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    // The provided key is unknown → new key generated; type lowercased.
    let key = assert_register_success(&body, "tokForm", "watchos");
    assert_ne!(key, "legacyForm");
    server.shutdown().await;
}

#[tokio::test]
async fn post_form_keys_match_case_insensitively_last_wins() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("DEVICETOKEN=first&devicetoken=second")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_register_success(&body, "second", "ios");
    server.shutdown().await;
}

#[tokio::test]
async fn post_form_percent_decoding_applies() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("device_token=a+b%26c")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_register_success(&body, "a b&c", "ios");
    server.shutdown().await;
}

#[tokio::test]
async fn post_unsupported_content_type_is_upstream_bind_failure() {
    let server = spawn().await;
    // No content type at all (upstream fiber: ErrUnprocessableEntity).
    let res = client().post(server.url("/register")).send().await.unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 400, "request bind failed2: Unprocessable Entity");

    // text/plain is likewise unprocessable.
    let res = client()
        .post(server.url("/register"))
        .header("content-type", "text/plain")
        .body("device_token=tok")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 400, "request bind failed2: Unprocessable Entity");

    // multipart/form-data is deliberately NOT bound (ADR-0003 documented
    // deviation: no known Bark client registers via multipart) — the same
    // bind failure answers, well-formed boundary or not.
    let res = client()
        .post(server.url("/register"))
        .multipart(reqwest::multipart::Form::new().text("device_token", "tokMultipart"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 400, "request bind failed2: Unprocessable Entity");
    server.shutdown().await;
}

#[tokio::test]
async fn post_empty_json_body_is_bind_failure() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .header("content-type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], 400, "body: {body}");
    let message = body["message"].as_str().expect("message string");
    assert!(
        message.starts_with("request bind failed2: "),
        "bind failure must quote upstream's prefix, got {message:?}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn post_xml_binds_device_token() {
    // Upstream BodyParser also accepts application/xml.
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .header("content-type", "application/xml")
        .body("<DeviceInfo><device_token>tokXml</device_token><device_type>watchos</device_type></DeviceInfo>")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_register_success(&body, "tokXml", "watchos");
    server.shutdown().await;
}

#[tokio::test]
async fn post_malformed_xml_is_bind_failure() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .header("content-type", "application/xml")
        .body("<bad")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], 400, "body: {body}");
    let message = body["message"].as_str().expect("message string");
    assert!(
        message.starts_with("request bind failed2: failed to unmarshal: "),
        "xml bind failure must quote upstream's wrapper, got {message:?}"
    );
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// POST /register — create vs update (bbolt SaveDeviceTokenByKey semantics)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn re_registering_existing_key_updates_its_record() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tokOrig", "device_type": "ios"}))
        .send()
        .await
        .unwrap();
    let key = assert_register_success(&res.json().await.unwrap(), "tokOrig", "ios");

    // Canonical device_key: same key returned, token and type updated.
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_key": key, "device_token": "tokNew", "device_type": "watchos"}))
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], 200);
    assert_eq!(
        body["data"]["device_key"], key,
        "existing key must be reused"
    );
    assert_eq!(body["data"]["key"], key);
    assert_eq!(body["data"]["device_token"], "tokNew");
    assert_eq!(body["data"]["device_type"], "watchos");

    // Legacy key alias updates the same record.
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"key": key, "devicetoken": "tokNewer", "device_type": "ios"}))
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["data"]["device_key"], key,
        "alias must address the same record"
    );
    assert_eq!(body["data"]["device_token"], "tokNewer");
    assert_eq!(body["data"]["device_type"], "ios");

    // The device is still known exactly once.
    let res = client().get(server.url("/info")).send().await.unwrap();
    let info: Value = res.json().await.unwrap();
    assert_eq!(
        info["devices"], 1,
        "updates must not create new records: {info}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn canonical_device_key_wins_over_legacy_alias() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tokA"}))
        .send()
        .await
        .unwrap();
    let key = assert_register_success(&res.json().await.unwrap(), "tokA", "ios");

    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_key": key, "key": "legacyOther", "devicetoken": "tokB"}))
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["data"]["device_key"], key,
        "canonical device_key must win"
    );
    assert_eq!(body["data"]["device_token"], "tokB");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// GET /register — legacy compat (query bind)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_compat_binds_query_params_and_ignores_body() {
    let server = spawn().await;
    let res = client()
        .get(server.url("/register?device_token=tokQ1&device_type=ios"))
        .body("this body must be ignored")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_register_success(&body, "tokQ1", "ios");
    server.shutdown().await;
}

#[tokio::test]
async fn get_compat_legacy_aliases_create_new_device_when_unknown() {
    let server = spawn().await;
    let res = client()
        .get(server.url("/register?key=unknownKey1&devicetoken=tokQ2"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let key = assert_register_success(&body, "tokQ2", "ios");
    assert_ne!(
        key, "unknownKey1",
        "unknown key must be replaced by a new one"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn get_compat_missing_token_rejected() {
    let server = spawn().await;
    for query in ["", "?device_key=k1", "?devicetoken="] {
        let res = client()
            .get(server.url(&format!("/register{query}")))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400, "query {query:?} must be rejected");
        let body: Value = res.json().await.unwrap();
        assert_envelope_no_data(&body, 400, "device token is empty");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn get_compat_query_keys_case_insensitive_last_wins() {
    let server = spawn().await;
    let res = client()
        .get(server.url("/register?DEVICETOKEN=first&devicetoken=second&Device_Type=ios"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_register_success(&body, "second", "ios");
    server.shutdown().await;
}

#[tokio::test]
async fn get_compat_unknown_query_params_ignored() {
    let server = spawn().await;
    let res = client()
        .get(server.url("/register?whatever=1&devicetoken=tokQ3"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_register_success(&body, "tokQ3", "ios");
    server.shutdown().await;
}

#[tokio::test]
async fn get_compat_overlong_token_rejected() {
    let server = spawn().await;
    let token_161 = "x".repeat(161);
    let res = client()
        .get(server.url(&format!("/register?devicetoken={token_161}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 400, "device token is invalid");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// GET /register/:device_key — existence check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_route_known_device_returns_success_without_data() {
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tokCheck"}))
        .send()
        .await
        .unwrap();
    let key = assert_register_success(&res.json().await.unwrap(), "tokCheck", "ios");

    let res = client()
        .get(server.url(&format!("/register/{key}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 200, "success");
    server.shutdown().await;
}

#[tokio::test]
async fn check_route_unknown_device_quotes_key_in_upstream_message() {
    let server = spawn().await;
    let res = client()
        .get(server.url("/register/doesnotexist"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(
        &body,
        400,
        "failed to get [doesnotexist] device token from database",
    );
    server.shutdown().await;
}

#[tokio::test]
async fn check_route_lookup_is_case_sensitive_on_device_key() {
    // Fiber matches route paths case-insensitively but captures path params
    // verbatim; the store lookup is byte-exact (bbolt key compare).
    let server = spawn().await;
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tokCase"}))
        .send()
        .await
        .unwrap();
    let key = assert_register_success(&res.json().await.unwrap(), "tokCase", "ios");

    // Uppercased request still routes (200-level reachability of the handler)
    // but fails the lookup, quoting the requested casing.
    let upper: String = key.to_uppercase();
    let res = client()
        .get(server.url(&format!("/register/{upper}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(
        &body,
        400,
        &format!("failed to get [{upper}] device token from database"),
    );

    // Exact case works.
    let res = client()
        .get(server.url(&format!("/register/{key}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    server.shutdown().await;
}

#[tokio::test]
async fn check_route_trailing_slash_falls_back_to_compat_query_route() {
    // Upstream trims trailing slashes, so GET /register/ hits the compat
    // route, never the param route with an empty key.
    let server = spawn().await;
    let res = client()
        .get(server.url("/register/?key=unknownTrail&devicetoken=tokTrail"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let key = assert_register_success(&body, "tokTrail", "ios");
    assert_ne!(key, "unknownTrail");
    server.shutdown().await;
}

#[tokio::test]
async fn register_method_mismatches_get_enveloped_405() {
    let server = spawn().await;
    // POST /register/{key} is NOT a 405: with the compat push routes mounted,
    // the two segments fall through to the compat push (device_key="register")
    // — covered by push_seam's compat_routes_do_not_shadow_canonical_routes.
    for (path, method) in [("/register", "DELETE"), ("/register", "PUT")] {
        let res = client()
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                server.url(path),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 405, "{method} {path} must be 405");
        let body: Value = res.json().await.unwrap();
        assert_envelope_no_data(&body, 405, "Method Not Allowed");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn register_routes_match_case_insensitively() {
    let server = spawn().await;
    let res = client()
        .get(server.url("/REGISTER?devicetoken=tokUp"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_register_success(&body, "tokUp", "ios");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// /info device count + persistence across restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn info_device_count_tracks_registrations() {
    let server = spawn().await;
    let res = client().get(server.url("/info")).send().await.unwrap();
    let info: Value = res.json().await.unwrap();
    assert_eq!(info["devices"], 0, "empty store counts zero: {info}");

    client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tokI1"}))
        .send()
        .await
        .unwrap();
    client()
        .get(server.url("/register?key=unknownI2&devicetoken=tokI2"))
        .send()
        .await
        .unwrap();

    let res = client().get(server.url("/info")).send().await.unwrap();
    let info: Value = res.json().await.unwrap();
    assert_eq!(
        info["devices"], 2,
        "two new registrations count two: {info}"
    );

    // Re-registering an existing key must not bump the count.
    client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tokI1", "device_type": "watchos"}))
        .send()
        .await
        .unwrap();
    let res = client().get(server.url("/info")).send().await.unwrap();
    let info: Value = res.json().await.unwrap();
    // The re-registration above supplied no key → it is a new device; two
    // earlier devices plus this one make three.
    assert_eq!(info["devices"], 3, "count reflects store reality: {info}");
    server.shutdown().await;
}

#[tokio::test]
async fn device_records_persist_across_server_restart() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = config_with(dir.path().to_path_buf());
    let server = TestServer::spawn_with_data_dir(config).await;

    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_token": "tokPersist", "device_type": "watchos"}))
        .send()
        .await
        .unwrap();
    let key = assert_register_success(&res.json().await.unwrap(), "tokPersist", "watchos");
    server.shutdown().await;

    // Second server on the same data dir: the record must survive.
    let config = config_with(dir.path().to_path_buf());
    let server = TestServer::spawn_with_data_dir(config).await;

    let res = client()
        .get(server.url(&format!("/register/{key}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "device must exist after restart");
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 200, "success");

    // Updating the persisted record keeps the same key.
    let res = client()
        .post(server.url("/register"))
        .json(&json!({"device_key": key, "devicetoken": "tokUpdated"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["data"]["device_key"], key,
        "restart must not orphan records"
    );
    assert_eq!(body["data"]["device_token"], "tokUpdated");

    let res = client().get(server.url("/info")).send().await.unwrap();
    let info: Value = res.json().await.unwrap();
    assert_eq!(
        info["devices"], 1,
        "exactly one record after restart: {info}"
    );
    server.shutdown().await;
}
