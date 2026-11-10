//! Ticket 04 acceptance: push core + APNs delivery loop over the HTTP
//! boundary. The behavioral oracle is upstream bark-server v2.4.0
//! (route_push.go V2 JSON path + apns/apns.go payload construction); the
//! APNs endpoint is a local HTTPS HTTP/2 stub (tests/common/apns_stub.rs) —
//! no request ever reaches Apple.

mod common;

use base64::Engine as _;
use common::apns_stub::ApnsStub;
use common::{TestServer, assert_envelope_no_data, client, ephemeral_config};
use serde_json::{Value, json};

/// Spawn a bark server whose APNs endpoint is the local stub.
async fn spawn_with_stub(stub: &ApnsStub) -> TestServer {
    let (mut config, dir) = ephemeral_config();
    config.apns_endpoint = stub.url.clone();
    config.apns_insecure_skip_tls_verify = true;
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

/// POST /push with a JSON body.
async fn push_json(server: &TestServer, body: Value) -> reqwest::Response {
    client()
        .post(server.url("/push"))
        .json(&body)
        .send()
        .await
        .unwrap()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Assert the recorded authorization header is an upstream-shaped APNs
/// provider token: `bearer <jwt>` with the embedded upstream credentials
/// (ADR-0004), and an ES256 signature that verifies against the key.
fn verify_apns_jwt(authorization: &str) {
    let bearer = authorization
        .strip_prefix("bearer ")
        .expect("authorization must be `bearer <jwt>` (lowercase, like apns2)");
    let mut parts = bearer.split('.');
    let header_b64 = parts.next().expect("jwt header");
    let claims_b64 = parts.next().expect("jwt claims");
    let sig_b64 = parts.next().expect("jwt signature");
    assert!(parts.next().is_none(), "jwt must have exactly 3 segments");

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header: Value =
        serde_json::from_slice(&b64.decode(header_b64).expect("header b64")).expect("header json");
    assert_eq!(header["alg"], "ES256", "APNs JWT alg: {header}");
    assert_eq!(header["kid"], "LH4T9V5U4R", "APNs JWT key id: {header}");

    let claims: Value =
        serde_json::from_slice(&b64.decode(claims_b64).expect("claims b64")).expect("claims json");
    assert_eq!(claims["iss"], "5U8LBRXG3A", "APNs JWT team id: {claims}");
    let iat = claims["iat"].as_i64().expect("iat integer");
    assert!((now_unix() - iat).abs() <= 120, "jwt iat {iat} not fresh");

    // Cryptographic check: the ES256 signature verifies against the embedded
    // upstream key (p256 is the independent verification oracle).
    let sig = p256::ecdsa::Signature::from_slice(&b64.decode(sig_b64).expect("sig b64"))
        .expect("ES256 signature is 64-byte r||s");
    use p256::ecdsa::signature::Verifier;
    use p256::elliptic_curve::pkcs8::DecodePrivateKey;
    let signing_key =
        p256::ecdsa::SigningKey::from_pkcs8_pem(bark_server_rs::apns::APNS_PRIVATE_KEY_PEM)
            .expect("embedded p8 parses");
    p256::ecdsa::VerifyingKey::from(&signing_key)
        .verify(format!("{header_b64}.{claims_b64}").as_bytes(), &sig)
        .expect("APNs JWT signature must verify against the embedded key");
}

// ---------------------------------------------------------------------------
// Slice 1: JSON push happy path — payload/header parity to the APNs endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn json_push_delivers_upstream_payload_and_headers() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "PUSHTOKEN1", "ios").await;

    let res = push_json(
        &server,
        json!({
            "device_key": key,
            "title": "Flight",
            "subtitle": "SFO",
            "body": "Gate 7",
            "id": "flight-87",
            "group": "trips",
        }),
    )
    .await;
    assert_eq!(res.status(), 200, "push must succeed");
    assert_envelope_no_data(&res.json::<Value>().await.unwrap(), 200, "success");

    let pushes = stub.pushes();
    assert_eq!(
        pushes.len(),
        1,
        "exactly one APNs request must have been delivered"
    );
    let p = &pushes[0];
    assert_eq!(p.path, "/3/device/PUSHTOKEN1", "APNs provider URL path");
    assert_eq!(
        p.http_version, "HTTP/2.0",
        "APNs delivery must speak HTTP/2 (Apple requires h2)"
    );
    assert_eq!(
        p.content_type, "application/json; charset=utf-8",
        "content-type parity with apns2"
    );

    // Token (JWT) auth with the embedded upstream credentials.
    verify_apns_jwt(&p.authorization);

    // Topic by device type, push type, collapse id, expiration.
    assert_eq!(p.apns_topic.as_deref(), Some("me.fin.bark"));
    assert_eq!(p.apns_push_type.as_deref(), Some("alert"));
    assert_eq!(
        p.apns_collapse_id.as_deref(),
        Some("flight-87"),
        "id doubles as apns-collapse-id"
    );
    let expiration: i64 = p
        .apns_expiration
        .as_deref()
        .expect("apns-expiration must be set")
        .parse()
        .expect("expiration unix seconds");
    let expected = now_unix() + 24 * 3600;
    assert!(
        (expected - expiration).abs() <= 60,
        "apns-expiration must be now+24h: got {expiration}"
    );
    assert!(
        p.apns_priority.is_none(),
        "upstream never sets apns-priority (Priority 0 omits the header)"
    );
    assert!(p.apns_id.is_none(), "upstream never sets apns-id");

    // Payload: always mutable-content, hardcoded category, default sound,
    // alert dictionary, group → thread-id + custom key, id → custom key.
    let aps = &p.payload["aps"];
    assert_eq!(aps["mutable-content"], 1, "mutable-content always 1");
    assert_eq!(
        aps["category"], "myNotificationCategory",
        "hardcoded category parity"
    );
    // Upstream default: sound "1107" (unsuffixed — ".caf" is only appended
    // to a sound parameter provided by the request).
    assert_eq!(aps["sound"], "1107", "default sound 1107");
    assert_eq!(aps["alert"]["title"], "Flight");
    assert_eq!(aps["alert"]["subtitle"], "SFO");
    assert_eq!(aps["alert"]["body"], "Gate 7");
    assert_eq!(aps["thread-id"], "trips", "group → aps.thread-id");
    assert_eq!(p.payload["group"], "trips", "group → root custom key");
    assert_eq!(p.payload["id"], "flight-87", "id → root custom key");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn watchos_device_pushes_to_watch_topic() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "WATCHTOKEN1", "watchos").await;

    let res = push_json(&server, json!({ "device_key": key, "body": "tick" })).await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].path, "/3/device/WATCHTOKEN1");
    assert_eq!(
        pushes[0].apns_topic.as_deref(),
        Some("me.fin.bark.watch"),
        "watchos devices route to the watch topic"
    );

    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 2: parameter precedence (query > body) and the string-param switch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_args_override_json_body_with_lowercased_keys() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "PUSHTOKEN2", "ios").await;

    // Body values lose to the query args; query keys are lowercased
    // ("TITLE" in the body, "title" in the query — the query wins).
    let res = client()
        .post(server.url(&format!(
            "/push?device_key={key}&body=from-query&title=FromQuery&sound=chime"
        )))
        .json(&json!({
            "device_key": "wrong-key",
            "body": "from-body",
            "TITLE": "FromBody",
            "sound": "unused",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(
        pushes[0].path, "/3/device/PUSHTOKEN2",
        "query device_key overrides the body"
    );
    let aps = &pushes[0].payload["aps"];
    assert_eq!(aps["alert"]["body"], "from-query");
    assert_eq!(aps["alert"]["title"], "FromQuery");
    assert_eq!(aps["sound"], "chime.caf", "query sound wins and gets .caf");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn string_param_switch_sound_and_casing() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "PUSHTOKEN3", "ios").await;

    // A provided sound gets ".caf" unless already suffixed; "ID" (any case)
    // dual-writes the collapse id and the lowercased custom key.
    let res = push_json(
        &server,
        json!({
            "device_key": key,
            "body": "b",
            "sound": "tone.caf",
            "ID": "collapse-9",
        }),
    )
    .await;
    assert_eq!(res.status(), 200);

    // Second push: unsuffixed sound.
    let res = push_json(
        &server,
        json!({ "device_key": key, "body": "b", "sound": "tone" }),
    )
    .await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 2);
    assert_eq!(
        pushes[0].payload["aps"]["sound"], "tone.caf",
        "suffixed sound kept as-is"
    );
    assert_eq!(
        pushes[0].apns_collapse_id.as_deref(),
        Some("collapse-9"),
        "id (any case) → apns-collapse-id"
    );
    assert_eq!(
        pushes[0].payload["id"], "collapse-9",
        "id → lowercased custom key"
    );
    assert_eq!(
        pushes[1].payload["aps"]["sound"], "tone.caf",
        "unsuffixed sound gets .caf"
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn delete_marker_switches_to_silent_background_push() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "PUSHTOKEN4", "ios").await;

    let res = push_json(
        &server,
        json!({
            "device_key": key,
            "delete": "1",
            "body": "ignored",
            "title": "ignored",
            "group": "g1",
        }),
    )
    .await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    let p = &pushes[0];
    assert_eq!(
        p.apns_push_type.as_deref(),
        Some("background"),
        "delete=1 → background push type"
    );
    assert!(p.apns_collapse_id.is_none(), "no id → no apns-collapse-id");
    let aps = &p.payload["aps"];
    let aps_keys: Vec<&String> = aps.as_object().unwrap().keys().collect();
    assert_eq!(
        aps_keys,
        ["content-available", "mutable-content"],
        "silent push payload carries only content-available + mutable-content"
    );
    assert!(aps.get("alert").is_none(), "delete pushes carry no alert");
    assert!(aps.get("sound").is_none());
    assert!(aps.get("category").is_none());
    assert!(
        aps.get("thread-id").is_none(),
        "delete branch sets no thread-id"
    );
    // Ext Params still pass through as root custom keys.
    assert_eq!(p.payload["delete"], "1");
    assert_eq!(p.payload["group"], "g1");

    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 3: Ext Params passthrough and the Empty Message fallback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ext_params_lowercase_keys_and_stringify_values() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "PUSHTOKEN5", "ios").await;

    let res = push_json(
        &server,
        json!({
            "device_key": key,
            "body": "b",
            "ICON": "i.png",
            "Url": "https://example.com",
            "badge-count": 3,
            "level": 10.5,
            "silent": true,
            "tags": [1, "a"],
            "timestamp": 1794353102,
        }),
    )
    .await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    let payload = &pushes[0].payload;
    assert_eq!(payload["icon"], "i.png", "keys lowercased");
    assert_eq!(payload["url"], "https://example.com");
    assert_eq!(payload["badge-count"], "3", "numbers stringified");
    assert_eq!(payload["level"], "10.5");
    assert_eq!(payload["silent"], "true", "bools stringified");
    assert_eq!(payload["tags"], "[1 a]", "arrays rendered like Go %v");
    // Go %v renders float64 like strconv 'g' -1: 1e6 and beyond goes to
    // exponent notation (verified against the Go oracle).
    assert_eq!(payload["timestamp"], "1.794353102e+09");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn map_values_merge_into_ext_params() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "PUSHTOKEN6", "ios").await;

    let res = push_json(
        &server,
        json!({
            "device_key": key,
            "body": "b",
            "custom-map": { "A": 1, "b": "x", "nested": { "z": true } },
        }),
    )
    .await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    let payload = &pushes[0].payload;
    assert!(
        payload.get("custom-map").is_none(),
        "the map value itself must not appear as a param"
    );
    assert_eq!(payload["a"], "1", "merged map entries stringified");
    assert_eq!(payload["b"], "x");
    assert_eq!(
        payload["nested"], "map[z:true]",
        "nested maps rendered like Go %v"
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn empty_alert_becomes_empty_message() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "PUSHTOKEN7", "ios").await;

    // Fully empty alert → "Empty Message" body.
    let res = push_json(&server, json!({ "device_key": key })).await;
    assert_eq!(res.status(), 200);

    // A non-empty title keeps the alert as-is — no body key at all (Go
    // omitempty on the alert fields).
    let res = push_json(&server, json!({ "device_key": key, "title": "Only" })).await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 2);
    let empty_alert = &pushes[0].payload["aps"]["alert"];
    assert_eq!(
        empty_alert["body"], "Empty Message",
        "empty alert must fall back to Empty Message"
    );
    assert!(empty_alert.get("title").is_none());
    assert!(empty_alert.get("subtitle").is_none());
    let title_alert = &pushes[1].payload["aps"]["alert"];
    assert_eq!(title_alert["title"], "Only");
    assert!(
        title_alert.get("body").is_none(),
        "title-only alert must not carry a body key"
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn non_string_body_param_passes_through_and_alert_stays_empty() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "PUSHTOKEN8", "ios").await;

    // A non-string "body" is not the body field: it lands in Ext Params
    // (original key case) and the alert falls back to Empty Message.
    let res = push_json(&server, json!({ "device_key": key, "body": 123 })).await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(
        pushes[0].payload["body"], "123",
        "non-string body → stringified ext param"
    );
    assert_eq!(pushes[0].payload["aps"]["alert"]["body"], "Empty Message");

    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 4: error mapping, token cleanup, transport failures
// ---------------------------------------------------------------------------

/// GET /register/{key} body (used to observe the Device Token state through
/// the same HTTP seam).
async fn register_check(server: &TestServer, key: &str) -> reqwest::Response {
    client()
        .get(server.url(&format!("/register/{key}")))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn apns_410_blanks_device_token_and_next_push_fails() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "UNREGISTERED-TOKEN", "ios").await;

    let res = push_json(&server, json!({ "device_key": key, "body": "b" })).await;
    assert_eq!(res.status(), 410, "APNs status surfaces");
    assert_envelope_no_data(&res.json::<Value>().await.unwrap(), 410, "Unregistered");

    // The Device Token is blanked and persisted.
    let check = register_check(&server, &key).await;
    assert_eq!(check.status(), 400);
    assert_envelope_no_data(
        &check.json::<Value>().await.unwrap(),
        400,
        "device token invalid",
    );

    // The next push fails with the blank-token error and never reaches APNs.
    let res = push_json(&server, json!({ "device_key": key, "body": "b" })).await;
    assert_eq!(res.status(), 400);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["code"], 400);
    assert_eq!(
        env["message"],
        "failed to get device token: device token invalid"
    );
    assert_eq!(
        stub.push_count(),
        1,
        "the blank-token push must not reach the APNs endpoint"
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn apns_400_bad_device_token_blanks_device_token() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "BADDEVICETOKEN-TOKEN", "ios").await;

    let res = push_json(&server, json!({ "device_key": key, "body": "b" })).await;
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(&res.json::<Value>().await.unwrap(), 400, "BadDeviceToken");

    // Blanked like the 410 path.
    let check = register_check(&server, &key).await;
    assert_eq!(check.status(), 400, "token blanked after BadDeviceToken");
    let res = push_json(&server, json!({ "device_key": key, "body": "b" })).await;
    let env: Value = res.json().await.unwrap();
    assert_eq!(
        env["message"],
        "failed to get device token: device token invalid"
    );
    assert_eq!(stub.push_count(), 1);

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn apns_non_200_other_statuses_surface_without_cleanup() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "TOOMANYREQUESTS-TOKEN", "ios").await;

    let res = push_json(&server, json!({ "device_key": key, "body": "b" })).await;
    assert_eq!(res.status(), 429);
    assert_envelope_no_data(&res.json::<Value>().await.unwrap(), 429, "TooManyRequests");

    // Token NOT blanked: the next push reaches the stub again.
    let res = push_json(&server, json!({ "device_key": key, "body": "b" })).await;
    assert_eq!(res.status(), 429);
    assert_eq!(stub.push_count(), 2);

    // Apple-side 500 with its reason surfaces the same way.
    let key500 = register_device(&server, "INTERNALERROR-TOKEN", "ios").await;
    let res = push_json(&server, json!({ "device_key": key500, "body": "b" })).await;
    assert_eq!(res.status(), 500);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["code"], 500);
    assert_eq!(env["message"], "InternalServerError");
    assert_eq!(stub.push_count(), 3);

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn transport_failure_maps_to_500_push_failed() {
    // A port that refuses connections: the transport error path.
    let dead_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let (mut config, dir) = ephemeral_config();
    config.apns_endpoint = format!("https://127.0.0.1:{dead_port}");
    config.apns_insecure_skip_tls_verify = true;
    let server = TestServer::spawn(config, dir).await;
    let key = register_device(&server, "DEADEND-TOKEN", "ios").await;

    let res = push_json(&server, json!({ "device_key": key, "body": "b" })).await;
    assert_eq!(res.status(), 500);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["code"], 500);
    let message = env["message"].as_str().unwrap();
    assert!(
        message.starts_with("push failed: "),
        "transport failures answer upstream's push failed wrapper: {message}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn unknown_or_missing_device_key_fails_like_upstream() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;

    let res = push_json(&server, json!({ "device_key": "nosuchkey", "body": "b" })).await;
    assert_eq!(res.status(), 400);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["code"], 400);
    assert_eq!(
        env["message"],
        "failed to get device token: failed to get [nosuchkey] device token from database"
    );
    assert_eq!(stub.push_count(), 0, "nothing delivered");

    let res = push_json(&server, json!({ "body": "b" })).await;
    assert_eq!(res.status(), 400);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["message"], "device key is empty");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn device_keys_invalid_type_fails_and_batch_is_deferred() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "BATCHTOKEN1", "ios").await;

    // Non-string/array device_keys is a hard 400 (upstream V2 core).
    let res = push_json(&server, json!({ "device_key": key, "device_keys": 123 })).await;
    assert_eq!(res.status(), 400);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["message"], "invalid type for device_keys");
    assert_eq!(stub.push_count(), 0);

    // Batch fan-out (device_keys non-empty) is ticket 04's scope; it must
    // not silently degrade into a single push.
    let res = push_json(&server, json!({ "device_keys": [key], "body": "b" })).await;
    assert_eq!(res.status(), 400);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["message"], "batch push is not implemented yet");
    assert_eq!(stub.push_count(), 0);

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn non_json_content_type_and_wrong_method_fail() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;

    // V1 form collection arrives with ticket 04; for now form posts fail
    // with the bind-failure envelope instead of pretending.
    let res = client()
        .post(server.url("/push"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("device_key=x&body=b")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["code"], 400);
    assert_eq!(stub.push_count(), 0);

    // Upstream registers /push for POST only.
    let res = client().get(server.url("/push")).send().await.unwrap();
    assert_eq!(res.status(), 405);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["message"], "Method Not Allowed");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn provider_token_is_cached_across_pushes() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "CACHED-TOKEN", "ios").await;

    for _ in 0..2 {
        let res = push_json(&server, json!({ "device_key": key, "body": "b" })).await;
        assert_eq!(res.status(), 200);
    }
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 2);
    assert_eq!(
        pushes[0].authorization, pushes[1].authorization,
        "the ES256 provider token must be cached within its validity window"
    );
    verify_apns_jwt(&pushes[0].authorization);

    server.shutdown().await;
    stub.shutdown().await;
}
