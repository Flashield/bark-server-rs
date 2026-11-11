//! Ticket 01 acceptance: the ops surface (`/`, `/ping`, `/healthz`, `/info`),
//! universal envelope, `Server: Bark`, route-matching flags, SQLite placement,
//! and url-prefix behavior — all asserted against a real server over HTTP,
//! with upstream bark-server v2.4.0 as the behavioral oracle.

mod common;

use bark_server_rs::config::Config;
use common::{TestServer, assert_envelope_no_data, client, ephemeral_config, server_header};
use serde_json::Value;

async fn spawn() -> TestServer {
    let (config, dir) = ephemeral_config();
    TestServer::spawn(config, dir).await
}

#[tokio::test]
async fn ping_returns_upstream_envelope() {
    let server = spawn().await;
    let res = client().get(server.url("/ping")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 200, "pong");
    server.shutdown().await;
}

#[tokio::test]
async fn healthz_returns_plain_ok() {
    let server = spawn().await;
    let res = client().get(server.url("/healthz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    let content_type = res.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(
        content_type.starts_with("text/plain"),
        "healthz must be plain text, got {content_type}"
    );
    assert_eq!(res.text().await.unwrap(), "ok");
    server.shutdown().await;
}

#[tokio::test]
async fn root_returns_plain_ok() {
    // Upstream registers GET / in the misc group returning "ok".
    let server = spawn().await;
    let res = client().get(server.url("/")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    assert_eq!(res.text().await.unwrap(), "ok");
    server.shutdown().await;
}

#[tokio::test]
async fn info_reports_version_build_arch_commit_and_store_device_count() {
    let server = spawn().await;
    let res = client().get(server.url("/info")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();

    // Upstream /info returns a bare JSON map (not the envelope).
    assert!(body.get("code").is_none(), "info is not enveloped: {body}");
    assert!(
        body["version"].is_string() && !body["version"].as_str().unwrap().is_empty(),
        "version must be a non-empty string: {body}"
    );
    assert!(body["build"].is_string(), "build must be a string: {body}");
    assert!(
        body["commit"].is_string(),
        "commit must be a string: {body}"
    );
    let arch = body["arch"].as_str().expect("arch string");
    assert!(
        arch.contains('/'),
        "arch must be GOOS/GOARCH shaped: {arch}"
    );
    assert_eq!(
        body["devices"], 0,
        "device count must come from the empty store"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn head_requests_are_served_like_upstream() {
    // Upstream (fiber) answers HEAD /ping with 200.
    let server = spawn().await;
    let res = client().head(server.url("/ping")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    server.shutdown().await;
}

#[tokio::test]
async fn routes_match_case_insensitively_by_default() {
    let server = spawn().await;
    for path in ["/PING", "/PiNg", "/HEALTHZ", "/INFO"] {
        let res = client().get(server.url(path)).send().await.unwrap();
        assert_eq!(res.status(), 200, "{path} must match case-insensitively");
    }
    server.shutdown().await;
}

/// Guard for `STATIC_SEGMENTS` (src/api/mod.rs): route matching canonicalizes
/// only the static segments listed there, so a route registered in the router
/// but missing from that list still answers at its canonical spelling yet
/// 404s the moment a client deviates in case or adds a trailing slash — the
/// silent production breakage this test turns into a CI failure by walking
/// EVERY documented route (docs/protocol.md) through both tolerances.
///
/// Statuses are the handlers' own: a missing `STATIC_SEGMENTS` entry shows up
/// as the router's enveloped 404, never as one of these.
#[tokio::test]
async fn every_documented_route_matches_case_insensitively_and_tolerates_trailing_slashes() {
    let server = spawn().await;

    // One stream Device drives the parametric routes (pushes to a stream
    // Device succeed without APNs; token mint/revoke need X-Device-Key).
    let key = {
        let res = client()
            .post(server.url("/register"))
            .json(&serde_json::json!({"device_type": "stream"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        res.json::<Value>().await.unwrap()["data"]["key"]
            .as_str()
            .expect("key string")
            .to_string()
    };
    let mint = |path: String| {
        let url = server.url(&path);
        let key = key.clone();
        async move {
            client()
                .post(url)
                .header("X-Device-Key", &key)
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap()
        }
    };
    let mint_token_id = |path: String| {
        let url = server.url(&path);
        let key = key.clone();
        async move {
            client()
                .post(url)
                .header("X-Device-Key", &key)
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()["data"]["token_id"]
                .as_str()
                .expect("token_id string")
                .to_string()
        }
    };
    let revoke = |path: String| {
        let url = server.url(&path);
        let key = key.clone();
        async move {
            client()
                .delete(url)
                .header("X-Device-Key", &key)
                .send()
                .await
                .unwrap()
        }
    };
    let initialize = |path: &str| {
        let url = server.url(path);
        async move {
            client()
                .post(url)
                .header("content-type", "application/json")
                .body(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"guard","version":"0"}}}"#,
                )
                .send()
                .await
                .unwrap()
        }
    };

    // --- case-insensitive static segments (every documented route) ---
    for (path, expected) in [
        // GET /ping
        ("/PING", 200),
        // GET /healthz
        ("/HEALTHZ", 200),
        // GET /info
        ("/INFO", 200),
    ] {
        let res = client().get(server.url(path)).send().await.unwrap();
        assert_eq!(res.status(), expected, "GET {path} must route");
    }
    // GET /register (legacy query bind)
    let res = client()
        .get(server.url("/REGISTER?devicetoken=tokStaticGuard"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "GET /REGISTER must route");
    // POST /register (body bind)
    let res = client()
        .post(server.url("/REGISTER"))
        .json(&serde_json::json!({"device_type": "stream"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "POST /REGISTER must route");
    // POST /push (V2; stream Device → no APNs)
    let res = client()
        .post(server.url("/PUSH"))
        .json(&serde_json::json!({"device_key": key, "body": "guard"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "POST /PUSH must route");
    // POST /realtime/v1/devices/{key}/streams (mint)
    let res = mint(format!("/Realtime/V1/Devices/{key}/Streams")).await;
    assert_eq!(
        res.status(),
        200,
        "POST /Realtime/V1/Devices/{{key}}/Streams must route"
    );
    let first_token = mint_token_id(format!("/realtime/v1/devices/{key}/streams")).await;
    // DELETE /realtime/v1/devices/{key}/streams/{token_id} (revoke)
    let res = revoke(format!("/Realtime/V1/Devices/{key}/Streams/{first_token}")).await;
    assert_eq!(
        res.status(),
        200,
        "DELETE …/Streams/{{token_id}} must route"
    );
    // GET /realtime/v1/stream — a bad token reaches the SSE handler's 401
    // (a missing STATIC_SEGMENTS entry would be a 404 instead).
    let res = client()
        .get(server.url("/Realtime/V1/Stream"))
        .header("X-Stream-Token", "st_notarealtoken")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "GET /Realtime/V1/Stream must route");
    // POST /mcp and POST /mcp/{device_key} (initialize)
    let res = initialize("/MCP").await;
    assert_eq!(res.status(), 200, "POST /MCP must route");
    let res = initialize(&format!("/MCP/{key}")).await;
    assert_eq!(res.status(), 200, "POST /MCP/{{device_key}} must route");

    // --- trailing-slash tolerance (every documented route) ---
    for path in ["/ping/", "/healthz/", "/info/"] {
        let res = client().get(server.url(path)).send().await.unwrap();
        assert_eq!(res.status(), 200, "GET {path} must route");
    }
    let res = client()
        .get(server.url("/register/?devicetoken=tokStaticGuardTrail"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "GET /register/ must route");
    let res = client()
        .post(server.url("/push/"))
        .json(&serde_json::json!({"device_key": key, "body": "guard"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "POST /push/ must route");
    let second_token = mint_token_id(format!("/realtime/v1/devices/{key}/streams/")).await;
    let res = mint(format!("/realtime/v1/devices/{key}/streams/")).await;
    assert_eq!(res.status(), 200, "POST …/streams/ must route");
    let res = revoke(format!(
        "/realtime/v1/devices/{key}/streams/{second_token}/"
    ))
    .await;
    assert_eq!(
        res.status(),
        200,
        "DELETE …/streams/{{token_id}}/ must route"
    );
    let res = client()
        .get(server.url("/realtime/v1/stream/"))
        .header("X-Stream-Token", "st_notarealtoken")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "GET /realtime/v1/stream/ must route");
    let res = initialize("/mcp/").await;
    assert_eq!(res.status(), 200, "POST /mcp/ must route");
    let res = initialize(&format!("/mcp/{key}/")).await;
    assert_eq!(res.status(), 200, "POST /mcp/{{device_key}}/ must route");

    server.shutdown().await;
}

#[tokio::test]
async fn routes_tolerate_trailing_slashes_by_default() {
    // Upstream trims ALL trailing slashes when strict routing is off.
    let server = spawn().await;
    for path in ["/ping/", "/ping///", "/healthz/", "/info/"] {
        let res = client().get(server.url(path)).send().await.unwrap();
        assert_eq!(res.status(), 200, "{path} must tolerate trailing slash");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn case_sensitive_flag_restores_strict_matching() {
    let (mut config, dir) = ephemeral_config();
    config.case_sensitive = true;
    let server = TestServer::spawn(config, dir).await;

    // Static routes stop matching case-insensitively; five-segment paths stay
    // unmatched (the compat routes only cover up to four segments).
    let miss = client()
        .get(server.url("/PING/a/b/c/d"))
        .send()
        .await
        .unwrap();
    assert_eq!(miss.status(), 404);
    let body: Value = miss.json().await.unwrap();
    assert_envelope_no_data(&body, 404, "Cannot GET /PING/a/b/c/d");

    let hit = client().get(server.url("/ping")).send().await.unwrap();
    assert_eq!(hit.status(), 200);
    server.shutdown().await;
}

#[tokio::test]
async fn strict_routing_flag_disables_trailing_slash_tolerance() {
    let (mut config, dir) = ephemeral_config();
    config.strict_routing = true;
    let server = TestServer::spawn(config, dir).await;

    let miss = client().get(server.url("/ping/")).send().await.unwrap();
    assert_eq!(miss.status(), 404);
    let body: Value = miss.json().await.unwrap();
    assert_envelope_no_data(&body, 404, "Cannot GET /ping/");

    let hit = client().get(server.url("/ping")).send().await.unwrap();
    assert_eq!(hit.status(), 200);
    server.shutdown().await;
}

#[tokio::test]
async fn unmatched_routes_get_enveloped_404() {
    // The compat routes (ticket 04) claim every 1-4 segment path, so the
    // enveloped 404 remains only for five or more segments — with the
    // original path in the message, like fiber's pathOriginal.
    let server = spawn().await;
    let res = client().get(server.url("/a/b/c/d/e")).send().await.unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 404, "Cannot GET /a/b/c/d/e");
    server.shutdown().await;
}

#[tokio::test]
async fn percent_encoded_paths_pass_through_to_compat_push() {
    // One-segment paths resolve as compat pushes with the raw (un-decoded)
    // device key — verified against the upstream Go server.
    let server = spawn().await;
    let res = client().get(server.url("/a%3Cb")).send().await.unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(
        &body,
        400,
        "failed to get device token: failed to get [a%3Cb] device token from database",
    );
    server.shutdown().await;
}

#[tokio::test]
async fn method_mismatch_gets_enveloped_405() {
    let server = spawn().await;
    for (path, method) in [
        ("/ping", "POST"),
        ("/info", "PUT"),
        ("/", "DELETE"),
        ("/healthz", "POST"),
    ] {
        let res = client()
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                server.url(path),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 405, "{method} {path} must be 405");
        assert_eq!(
            res.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(server_header(&res), "Bark");
        let body: Value = res.json().await.unwrap();
        assert_envelope_no_data(&body, 405, "Method Not Allowed");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn url_prefix_mounts_all_routes() {
    let (mut config, dir) = ephemeral_config();
    config.url_prefix = "/bark".into();
    let server = TestServer::spawn(config, dir).await;

    let res = client().get(server.url("/ping")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 200, "pong");

    // Trailing slash and prefix root behave like upstream's group.
    let res = client().get(server.url("/ping/")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let res = client().get(server.url("/")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "ok");

    // Outside the prefix: enveloped 404 with the original path. This hits
    // the raw base URL, bypassing the prefix.
    let res = client()
        .get(format!("{}/ping", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 404, "Cannot GET /ping");
    server.shutdown().await;
}

#[tokio::test]
async fn sqlite_store_file_is_created_under_data_dir() {
    let (mut config, dir) = ephemeral_config();
    // The SQLite file is this test's subject: it pins the default backend
    // and must not follow PG parity mode (ticket 12).
    config.dsn = String::new();
    let data_dir = config.data_dir.clone();
    let server = TestServer::spawn(config, dir).await;

    // The store file exists while the server is live and /ping works with it.
    assert!(
        data_dir.join("bark.db").exists(),
        "sqlite file must be created under {:?}",
        data_dir
    );
    let res = client().get(server.url("/ping")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    server.shutdown().await;
}

#[tokio::test]
async fn data_dir_is_created_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("deeply/nested/data");
    let config = Config {
        addr: format!("127.0.0.1:{}", common::free_port()),
        data_dir: nested.clone(),
        ..Default::default()
    };
    let server = TestServer::spawn(config, dir).await;
    assert!(nested.join("bark.db").exists());
    server.shutdown().await;
}
