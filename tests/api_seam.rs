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
