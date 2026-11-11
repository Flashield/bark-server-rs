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
async fn device_keys_invalid_type_fails_hard() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "BATCHTOKEN1", "ios").await;

    // Non-string/array device_keys is a hard 400 (upstream V2 core).
    let res = push_json(&server, json!({ "device_key": key, "device_keys": 123 })).await;
    assert_eq!(res.status(), 400);
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["message"], "invalid type for device_keys");
    assert_eq!(stub.push_count(), 0);

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn non_json_content_type_fails_like_upstream_v1_collection() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;

    // V1 collection (ticket 04): a form post without a known device key fails
    // like upstream's push() device lookup.
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
    assert_eq!(
        env["message"],
        "failed to get device token: failed to get [x] device token from database"
    );
    assert_eq!(stub.push_count(), 0);

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

// ---------------------------------------------------------------------------
// Slice 1: compat routes — the legacy path-style push surface
// ---------------------------------------------------------------------------

/// GET a compat route (raw path so percent-escapes stay on the wire).
async fn compat_get(server: &TestServer, path: &str) -> reqwest::Response {
    client().get(server.url(path)).send().await.unwrap()
}

/// Assert the single recorded APNs payload has the given alert fields.
fn assert_alert(
    pushes: &[common::apns_stub::RecordedPush],
    title: &str,
    subtitle: &str,
    body: &str,
) {
    assert_eq!(pushes.len(), 1, "exactly one delivery expected");
    let alert = &pushes[0].payload["aps"]["alert"];
    if !title.is_empty() {
        assert_eq!(alert["title"], title);
    }
    if !subtitle.is_empty() {
        assert_eq!(alert["subtitle"], subtitle);
    }
    assert_eq!(alert["body"], body, "alert: {}", pushes[0].payload);
}

#[tokio::test]
async fn compat_route_shapes_extract_segments() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "COMPATTOKEN1", "ios").await;

    // GET /{device_key} — one segment pushes an empty alert (Empty Message).
    let res = compat_get(&server, &format!("/{key}")).await;
    assert_eq!(res.status(), 200, "GET /:device_key must push");
    assert_envelope_no_data(&res.json::<Value>().await.unwrap(), 200, "success");

    // POST /{device_key} with a form body — query-free V1.
    let res = client()
        .post(server.url(&format!("/{key}")))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("body=FromForm")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // GET /{device_key}/{body}
    let res = compat_get(&server, &format!("/{key}/OnlyBody")).await;
    assert_eq!(res.status(), 200);

    // GET /{device_key}/{title}/{body}
    let res = compat_get(&server, &format!("/{key}/Title/Body")).await;
    assert_eq!(res.status(), 200);

    // GET /{device_key}/{title}/{subtitle}/{body}
    let res = compat_get(&server, &format!("/{key}/Title/Subtitle/Body")).await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 5, "every compat shape delivered once");
    assert_eq!(pushes[0].path, "/3/device/COMPATTOKEN1");
    assert_eq!(pushes[0].payload["aps"]["alert"]["body"], "Empty Message");
    assert_eq!(pushes[1].payload["aps"]["alert"]["body"], "FromForm");
    assert_eq!(pushes[2].payload["aps"]["alert"]["body"], "OnlyBody");
    assert_eq!(pushes[3].payload["aps"]["alert"]["title"], "Title");
    assert_eq!(pushes[3].payload["aps"]["alert"]["body"], "Body");
    assert_eq!(pushes[4].payload["aps"]["alert"]["title"], "Title");
    assert_eq!(pushes[4].payload["aps"]["alert"]["subtitle"], "Subtitle");
    assert_eq!(pushes[4].payload["aps"]["alert"]["body"], "Body");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn compat_url_segments_are_query_unescaped_but_device_key_stays_raw() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "COMPATTOKEN2", "ios").await;

    // %20 → space, %2B → literal +, raw + → space, %25 → %.
    let res = compat_get(&server, &format!("/{key}/Hello%20World/A%2BB")).await;
    assert_eq!(res.status(), 200);
    let res = compat_get(&server, &format!("/{key}/a+b/100%25")).await;
    assert_eq!(res.status(), 200);

    // The device_key param is NOT unescaped (upstream extractUrlPathParams
    // unescapes subtitle/title/body only) — the raw key reaches the lookup.
    let res = compat_get(&server, "/a%3Cb").await;
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "failed to get device token: failed to get [a%3Cb] device token from database",
    );

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 2);
    assert_alert(&pushes[0..1], "Hello World", "", "A+B");
    assert_alert(&pushes[1..2], "a b", "", "100%");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn compat_bad_url_escape_is_400_with_upstream_message() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "COMPATTOKEN3", "ios").await;

    // url.QueryUnescape failure → 400 "url path parse failed: ..." with the
    // escape truncated to at most 3 bytes, like Go's EscapeError.
    for (path, escape) in [
        (format!("/{key}/%zz"), "%zz"),
        (format!("/{key}/100%"), "%"),
        (format!("/{key}/%z"), "%z"),
    ] {
        let res = compat_get(&server, &path).await;
        assert_eq!(res.status(), 400, "bad escape {escape} must fail: {path}");
        assert_envelope_no_data(
            &res.json::<Value>().await.unwrap(),
            400,
            &format!("url path parse failed: invalid URL escape \"{escape}\""),
        );
    }
    assert_eq!(stub.push_count(), 0, "failed unescapes never deliver");

    // Subtitle is unescaped (and checked) before title.
    let res = compat_get(&server, &format!("/{key}/%zz/%yy/ok")).await;
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "url path parse failed: invalid URL escape \"%yy\"",
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn more_than_four_path_segments_is_404() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;

    // Five segments: beyond the deepest compat route → fiber's Cannot 404.
    let res = compat_get(&server, "/a/b/c/d/e").await;
    assert_eq!(res.status(), 404);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        404,
        "Cannot GET /a/b/c/d/e",
    );

    // Same for POST, and with a trailing slash quoted verbatim.
    let res = client()
        .post(server.url("/a/b/c/d/e"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        404,
        "Cannot POST /a/b/c/d/e",
    );
    let res = compat_get(&server, "/a/b/c/d/e/").await;
    assert_eq!(res.status(), 404);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        404,
        "Cannot GET /a/b/c/d/e/",
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn get_push_resolves_as_compat_push() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;

    // Upstream registers /push for POST only; GET falls through to the compat
    // route GET /:device_key with device_key="push".
    let res = compat_get(&server, "/push").await;
    assert_eq!(res.status(), 400, "GET /push must resolve as a compat push");
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "failed to get device token: failed to get [push] device token from database",
    );

    // The param keeps the original casing (fiber slices params from the raw
    // path even when matching is case-insensitive).
    let res = compat_get(&server, "/PUSH").await;
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "failed to get device token: failed to get [PUSH] device token from database",
    );

    // HEAD is auto-served by the compat GET (fiber registers HEAD alongside
    // every GET route).
    let res = client().head(server.url("/push")).send().await.unwrap();
    assert_eq!(res.status(), 400, "HEAD /push resolves as compat push");

    assert_eq!(stub.push_count(), 0, "unknown device keys never deliver");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn unmatched_one_segment_paths_resolve_as_compat_push() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;

    // With the compat routes mounted, any unmatched 1-4 segment path is a
    // push attempt (upstream behavior), not a 404.
    let res = compat_get(&server, "/nonexistent").await;
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "failed to get device token: failed to get [nonexistent] device token from database",
    );

    let res = compat_get(&server, "/a/b/c").await;
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "failed to get device token: failed to get [a] device token from database",
    );

    // Methods other than GET/POST on compat paths are 405 (the path exists
    // under other methods), like upstream fiber's methodExist.
    for method in ["PUT", "DELETE", "PATCH", "OPTIONS"] {
        let res = client()
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                server.url("/a/b/c"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 405, "{method} on a compat path must be 405");
        assert_envelope_no_data(
            &res.json::<Value>().await.unwrap(),
            405,
            "Method Not Allowed",
        );
    }

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn compat_routes_do_not_shadow_canonical_routes() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let _key = register_device(&server, "COMPATTOKEN4", "ios").await;

    // Static routes keep winning over the parametric compat mounts.
    let res = compat_get(&server, "/ping").await;
    assert_eq!(res.status(), 200);
    assert_envelope_no_data(&res.json::<Value>().await.unwrap(), 200, "pong");

    // GET /register/{key} stays the register existence check (its error
    // message has no "failed to get device token:" wrapper).
    let res = compat_get(&server, "/register/unknownkey").await;
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "failed to get [unknownkey] device token from database",
    );

    // GET /register stays the legacy compat registration.
    let res = compat_get(&server, "/register?devicetoken=COMPATREGTOKEN").await;
    assert_eq!(
        res.status(),
        200,
        "GET /register must remain compat register"
    );

    // POST /register/{key} falls through to the compat push (the canonical
    // register route owns POST /register only) — probed against upstream:
    // the two segments map to device_key="register", body=...
    let res = client()
        .post(server.url("/register/somebody"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_envelope_no_data(
        &res.json::<Value>().await.unwrap(),
        400,
        "failed to get device token: failed to get [register] device token from database",
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn compat_json_dispatch_keeps_path_params_highest() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "COMPATTOKEN5", "ios").await;

    // JSON content type on a compat path → V2 bind, with the path params
    // overriding the body (path > query > body precedence).
    let res = client()
        .post(server.url(&format!("/{key}/PathBody")))
        .header("Content-Type", "application/json")
        .body(json!({ "body": "FromBody", "title": "FromJson" }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_alert(&pushes[0..1], "FromJson", "", "PathBody");

    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 2: V1 collection order — query → form → multipart → path
// ---------------------------------------------------------------------------

/// POST a form body to a path with a query string.
async fn post_form(server: &TestServer, path: &str, body: &str) -> reqwest::Response {
    client()
        .post(server.url(path))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn v1_form_overrides_query() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "V1TOKEN1", "ios").await;

    // Form args are collected after the query args, so the form value wins;
    // form keys are lowercased like query keys ("TITLE" overrides too).
    let res = post_form(
        &server,
        &format!("/{key}?body=QueryBody&title=QueryTitle&sound=Chime"),
        "body=FormBody&TITLE=FormTitle",
    )
    .await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_alert(&pushes[0..1], "FormTitle", "", "FormBody");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn v1_form_body_is_collected_on_get_too() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "V1TOKEN2", "ios").await;

    // fasthttp parses POST args from the body whenever the content type is
    // form-urlencoded — the method does not matter.
    let res = client()
        .get(server.url(&format!("/{key}")))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("body=GetFormBody")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_alert(&pushes[0..1], "", "", "GetFormBody");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn v1_multipart_first_value_wins_and_keys_keep_case() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "V1TOKEN3", "ios").await;

    // Duplicate multipart field: first value wins (upstream reads val[0]).
    let res = client()
        .post(server.url(&format!("/{key}")))
        .multipart(
            reqwest::multipart::Form::new()
                .text("body", "first")
                .text("body", "second"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_alert(&pushes[0..1], "", "", "first");

    // Multipart keys are NOT lowercased: "TITLE" lands as a distinct param
    // that the push core still resolves to the title field (its switch
    // compares lowercased keys). Collected after the query, it overrides it.
    let res = client()
        .post(server.url(&format!("/{key}?title=FromQuery")))
        .multipart(reqwest::multipart::Form::new().text("TITLE", "FromMultipart"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 2);
    // Title-only alert: no body key (Go omitempty; the Empty Message
    // fallback fires only when title/subtitle/body are all empty).
    let alert = &pushes[1].payload["aps"]["alert"];
    assert_eq!(alert["title"], "FromMultipart", "multipart TITLE wins");
    assert!(
        alert.get("body").is_none(),
        "title-only alert carries no body: {}",
        pushes[1].payload
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn v1_multipart_files_are_not_params_and_bad_boundaries_are_skipped() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "V1TOKEN4", "ios").await;

    // A file part is collected into form.File upstream, never form.Value —
    // only the text parts become params.
    let part = reqwest::multipart::Part::bytes(b"file-bytes")
        .file_name("data.txt")
        .mime_str("text/plain")
        .unwrap();
    let res = client()
        .post(server.url(&format!("/{key}")))
        .multipart(
            reqwest::multipart::Form::new()
                .text("body", "TextPart")
                .part("upload", part),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_alert(&pushes[0..1], "", "", "TextPart");
    assert!(
        pushes[0].payload.get("upload").is_none(),
        "file parts must not become params: {}",
        pushes[0].payload
    );

    // multipart/form-data without a boundary: fasthtml fails to parse the
    // form and the V1 collection silently skips it (no crash, no params).
    let res = client()
        .post(server.url(&format!("/{key}")))
        .header("Content-Type", "multipart/form-data")
        .body("not-actually-multipart")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "no boundary: V1 proceeds without params");
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 2);
    assert_eq!(pushes[1].payload["aps"]["alert"]["body"], "Empty Message");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn v1_path_params_override_everything() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "V1TOKEN5", "ios").await;

    // Path > multipart > form > query: the /{key}/{body} segment wins even
    // though every other source provides a body.
    let res = post_form(
        &server,
        &format!("/{key}/PathBody?body=QueryBody"),
        "body=FormBody",
    )
    .await;
    assert_eq!(res.status(), 200);
    let res = client()
        .post(server.url(&format!("/{key}/PathBody")))
        .multipart(reqwest::multipart::Form::new().text("body", "MultipartBody"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 2);
    assert_alert(&pushes[0..1], "", "", "PathBody");
    assert_alert(&pushes[1..2], "", "", "PathBody");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn v1_device_keys_stay_an_ext_param() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "V1TOKEN6", "ios").await;

    // V1 never expands device_keys: a single push to the path/query/device
    // key happens, and the raw string rides along as an Ext Param.
    let res = post_form(
        &server,
        &format!("/{key}"),
        &format!("device_keys={key},other&body=V1Batch"),
    )
    .await;
    assert_eq!(res.status(), 200);

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1, "exactly one push, no batch expansion");
    assert_eq!(pushes[0].path, "/3/device/V1TOKEN6");
    assert_eq!(
        pushes[0].payload["device_keys"],
        format!("{key},other"),
        "raw device_keys value as a root custom key"
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn v1_content_types_that_are_not_form_or_multipart() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "V1TOKEN7", "ios").await;

    // text/plain with a JSON-looking body: V1 dispatch, body never parsed,
    // empty alert → Empty Message.
    let res = client()
        .post(server.url(&format!("/{key}")))
        .header("Content-Type", "text/plain")
        .body(r#"{"body":"NotJson"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].payload["aps"]["alert"]["body"], "Empty Message");

    // No content type at all: V1, query params still collected.
    let res = client()
        .post(server.url(&format!("/{key}?body=NoCtype")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 2);
    assert_eq!(pushes[1].payload["aps"]["alert"]["body"], "NoCtype");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn v2_json_dispatch_variants_stay_v2() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "V2TOKEN1", "ios").await;

    // Uppercase, vendor-specific (+json), and parameterized vendor types all
    // dispatch to V2 upstream (fiber lowercases + normalizes first).
    for ctype in [
        "APPLICATION/JSON",
        "application/vnd.x+json",
        "application/vnd.x+json; charset=utf-8",
        "application/json; charset=utf-8",
    ] {
        let res = client()
            .post(server.url(&format!("/{key}")))
            .header("Content-Type", ctype)
            .body(json!({ "body": format!("V2 via {ctype}"), "title": "T" }).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "ctype {ctype} must dispatch to V2");
    }

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 4);
    for (i, ctype) in [
        "APPLICATION/JSON",
        "application/vnd.x+json",
        "application/vnd.x+json; charset=utf-8",
        "application/json; charset=utf-8",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            pushes[i].payload["aps"]["alert"]["body"],
            format!("V2 via {ctype}"),
            "JSON body must be parsed for {ctype}"
        );
    }

    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 3: batch push — device_keys, cap, per-item results, fan-out
// ---------------------------------------------------------------------------

/// Assert a batch response envelope and return the per-item results.
async fn assert_batch(res: reqwest::Response) -> Vec<Value> {
    assert_eq!(res.status(), 200, "batch responses answer HTTP 200");
    let env: Value = res.json().await.unwrap();
    assert_eq!(env["code"], 200, "envelope code: {env}");
    assert_eq!(env["message"], "success", "envelope message: {env}");
    assert!(
        env["timestamp"].is_i64(),
        "envelope timestamp must be an integer: {env}"
    );
    env["data"]
        .as_array()
        .cloned()
        .expect("batch envelope must carry a data array")
}

#[tokio::test]
async fn batch_comma_string_form_produces_per_item_results() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "BATCHTOKEN2", "ios").await;

    let res = push_json(
        &server,
        json!({ "device_keys": format!("{key},nosuch"), "body": "BatchStr", "title": "T" }),
    )
    .await;
    let items = assert_batch(res).await;
    assert_eq!(items.len(), 2);

    // Success item: {code, device_key} — no message key.
    assert_eq!(items[0]["code"], 200);
    assert_eq!(items[0]["device_key"], key);
    assert!(
        items[0].get("message").is_none(),
        "the message key exists only on failures: {}",
        items[0]
    );
    // Failure item: {message, code, device_key}.
    assert_eq!(items[1]["code"], 400);
    assert_eq!(items[1]["device_key"], "nosuch");
    assert_eq!(
        items[1]["message"],
        "failed to get device token: failed to get [nosuch] device token from database"
    );

    // Both items delivered (the good one reached APNs; the bad one could not).
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].path, "/3/device/BATCHTOKEN2");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn batch_array_form_stringifies_elements() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "BATCHTOKEN3", "ios").await;

    // Array elements go through fmt.Sprint: 123 → "123".
    let res = push_json(
        &server,
        json!({ "device_keys": [key, 123], "body": "BatchArr" }),
    )
    .await;
    let items = assert_batch(res).await;
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["device_key"], key);
    assert_eq!(items[0]["code"], 200);
    assert_eq!(items[1]["device_key"], "123", "number → fmt.Sprint");
    assert_eq!(
        items[1]["message"],
        "failed to get device token: failed to get [123] device token from database"
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn batch_empty_array_falls_back_to_single_push() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "BATCHTOKEN4", "ios").await;

    // count == 0 → the single-push path: plain success envelope, no data.
    let res = push_json(
        &server,
        json!({ "device_keys": [], "device_key": key, "body": "EmptyArr" }),
    )
    .await;
    assert_eq!(res.status(), 200);
    let env: Value = res.json().await.unwrap();
    assert_envelope_no_data(&env, 200, "success");

    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].payload["aps"]["alert"]["body"], "EmptyArr");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn batch_empty_string_is_a_batch_of_one_empty_key() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let _key = register_device(&server, "BATCHTOKEN5", "ios").await;

    // strings.Split("", ",") yields [""], so this is a one-item batch whose
    // push fails with "device key is empty" — not the single-push path.
    let res = push_json(&server, json!({ "device_keys": "", "body": "EmptyStr" })).await;
    let items = assert_batch(res).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["device_key"], "");
    assert_eq!(items[0]["code"], 400);
    assert_eq!(items[0]["message"], "device key is empty");
    assert_eq!(stub.push_count(), 0);

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn batch_also_runs_on_compat_paths_and_from_query() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "BATCHTOKEN6", "ios").await;

    // JSON content type on a compat path: V2 dispatch → batch works there.
    let res = client()
        .post(server.url(&format!("/{key}")))
        .header("Content-Type", "application/json")
        .body(json!({ "device_keys": [key, "nope"], "body": "CompatBatch" }).to_string())
        .send()
        .await
        .unwrap();
    let items = assert_batch(res).await;
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["code"], 200);
    assert_eq!(items[1]["code"], 400);

    // Query-merged device_keys (keys lowercased) batch the same way.
    let res = client()
        .post(server.url(&format!("/push?device_keys={key},nope2")))
        .header("Content-Type", "application/json")
        .body(json!({ "body": "QueryBatch" }).to_string())
        .send()
        .await
        .unwrap();
    let items = assert_batch(res).await;
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["device_key"], key);
    assert_eq!(items[1]["device_key"], "nope2");
    assert_eq!(
        items[1]["message"],
        "failed to get device token: failed to get [nope2] device token from database"
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn batch_fans_out_concurrently_to_the_apns_endpoint() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let mut keys = Vec::new();
    for token in ["FANOUT1", "FANOUT2", "FANOUT3", "FANOUT4"] {
        keys.push(register_device(&server, token, "ios").await);
    }

    let res = push_json(
        &server,
        json!({ "device_keys": keys, "body": "Fanout", "title": "F" }),
    )
    .await;
    let items = assert_batch(res).await;
    assert_eq!(items.len(), 4);
    for item in &items {
        assert_eq!(item["code"], 200, "all items succeed: {item}");
    }

    // Every item reached the APNs endpoint (the fan-out is concurrent).
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 4);
    let tokens: Vec<&str> = pushes.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(
        tokens,
        [
            "/3/device/FANOUT1",
            "/3/device/FANOUT2",
            "/3/device/FANOUT3",
            "/3/device/FANOUT4",
        ],
        "per-item device tokens in input order"
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn batch_count_cap_is_enforced_via_flag() {
    let stub = ApnsStub::spawn().await;
    let (mut config, dir) = ephemeral_config();
    config.apns_endpoint = stub.url.clone();
    config.apns_insecure_skip_tls_verify = true;
    config.max_batch_push_count = 3;
    let server = TestServer::spawn(config, dir).await;
    let key = register_device(&server, "CAPTOKEN1", "ios").await;

    // At the cap: allowed.
    let res = push_json(
        &server,
        json!({ "device_keys": [key, key, key], "body": "Ok3" }),
    )
    .await;
    assert_batch(res).await;

    // Over the cap: 400 quoting the limit, for array and string forms alike.
    for device_keys in [json!([key, key, key, key]), json!("a,b,c,d")] {
        let res = push_json(
            &server,
            json!({ "device_keys": device_keys, "body": "Over" }),
        )
        .await;
        assert_eq!(res.status(), 400);
        assert_envelope_no_data(
            &res.json::<Value>().await.unwrap(),
            400,
            "batch push count exceeds the maximum limit: 3",
        );
    }

    // The cap never affects a single push.
    let res = push_json(&server, json!({ "device_key": key, "body": "Single" })).await;
    assert_eq!(res.status(), 200);
    let env: Value = res.json().await.unwrap();
    assert_envelope_no_data(&env, 200, "success");

    server.shutdown().await;
    stub.shutdown().await;
}
