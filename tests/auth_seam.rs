//! Ticket 05 acceptance: Basic Auth parity with upstream `route_auth.go` +
//! fiber's basicauth middleware, asserted against a real server over HTTP.
//!
//! Every behavior below was verified against the live Go bark-server v2.4.0
//! binary (the behavioral oracle): enable condition, fiber's `/+` middleware
//! coverage (bare root escapes auth), byte-prefix exemptions on the raw path,
//! and the 418 teapot failure shape (no WWW-Authenticate, `Server: Bark`).

mod common;

use bark_server_rs::config::Config;
use common::{TestServer, assert_envelope_no_data, client, ephemeral_config, server_header};

/// Config with basic auth credentials set, on an ephemeral port/store.
fn config_with_auth(url_prefix: &str, user: &str, password: &str) -> (Config, tempfile::TempDir) {
    let (mut config, dir) = ephemeral_config();
    config.url_prefix = url_prefix.into();
    config.basic_auth_user = user.into();
    config.basic_auth_password = password.into();
    (config, dir)
}

async fn spawn_auth(url_prefix: &str, user: &str, password: &str) -> TestServer {
    let (config, dir) = config_with_auth(url_prefix, user, password);
    TestServer::spawn(config, dir).await
}

// ---------------------------------------------------------------------------
// Enable / disable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn both_flags_empty_disables_auth_entirely() {
    let server = spawn_auth("/", "", "").await;
    let res = client().get(server.url("/info")).send().await.unwrap();
    assert_eq!(res.status(), 200, "no auth demanded without credentials");
    server.shutdown().await;
}

#[tokio::test]
async fn user_and_password_protect_non_exempt_routes() {
    let server = spawn_auth("/", "u", "p").await;
    let http = client();

    let denied = http.get(server.url("/info")).send().await.unwrap();
    assert_eq!(denied.status(), 418, "/info must demand auth");

    let wrong = http
        .get(server.url("/info"))
        .basic_auth("u", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 418, "wrong password must be rejected");

    let wrong_user = http
        .get(server.url("/info"))
        .basic_auth("someone", Some("p"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_user.status(), 418, "wrong username must be rejected");

    let ok = http
        .get(server.url("/info"))
        .basic_auth("u", Some("p"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200, "correct credentials must proceed");
    server.shutdown().await;
}

#[tokio::test]
async fn user_flag_alone_enables_auth_with_empty_password() {
    let server = spawn_auth("/", "u", "").await;
    let http = client();

    let denied = http.get(server.url("/info")).send().await.unwrap();
    assert_eq!(denied.status(), 418, "user alone must enable auth");

    let ok = http
        .get(server.url("/info"))
        // base64("u:") — empty password must be accepted like upstream's
        // single-entry Users map {u: ""}.
        .header("Authorization", "Basic dTo=")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200, "empty password must match");

    let wrong = http
        .get(server.url("/info"))
        .basic_auth("u", Some("x"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 418);

    let other = http
        .get(server.url("/info"))
        // base64(":x") — username must match too.
        .header("Authorization", "Basic Ong=")
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 418);
    server.shutdown().await;
}

#[tokio::test]
async fn password_flag_alone_enables_auth_with_empty_user() {
    let server = spawn_auth("/", "", "p").await;
    let http = client();

    let denied = http.get(server.url("/info")).send().await.unwrap();
    assert_eq!(denied.status(), 418, "password alone must enable auth");

    let ok = http
        .get(server.url("/info"))
        // base64(":p") — empty username must be accepted.
        .header("Authorization", "Basic OnA=")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200, "empty username must match");

    let wrong = http
        .get(server.url("/info"))
        // base64("u:p") — a non-empty username must be rejected.
        .header("Authorization", "Basic dTpw")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 418);
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Failure shape: 418 teapot (not 401)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failed_auth_returns_418_teapot_shape() {
    let server = spawn_auth("/", "u", "p").await;
    let res = client().get(server.url("/info")).send().await.unwrap();
    assert_eq!(res.status(), 418);
    assert_eq!(server_header(&res), "Bark", "teapot keeps the Bark header");
    let content_type = res.headers().get("content-type").unwrap().to_str().unwrap();
    assert_eq!(
        content_type, "text/plain; charset=utf-8",
        "teapot body is plain text like upstream SendString"
    );
    assert!(
        res.headers().get("www-authenticate").is_none(),
        "upstream's custom Unauthorized handler sends no WWW-Authenticate challenge"
    );
    assert_eq!(res.text().await.unwrap(), "I'm a teapot");
    server.shutdown().await;
}

#[tokio::test]
async fn auth_sits_in_front_of_unmatched_paths() {
    // Upstream: middleware matches before routing, so an unknown path 418s
    // instead of 404 when unauthenticated.
    let server = spawn_auth("/", "u", "p").await;
    let res = client()
        .get(server.url("/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 418, "unmatched paths must hit auth first");
    let res = client()
        .post(server.url("/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 418, "coverage is method-independent");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Exemptions: /ping, /register, /healthz prefixes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exempt_routes_pass_without_credentials() {
    let server = spawn_auth("/", "u", "p").await;
    let http = client();

    let ping = http.get(server.url("/ping")).send().await.unwrap();
    assert_eq!(ping.status(), 200, "/ping must be auth-free");
    let body: serde_json::Value = ping.json().await.unwrap();
    assert_envelope_no_data(&body, 200, "pong");

    let healthz = http.get(server.url("/healthz")).send().await.unwrap();
    assert_eq!(healthz.status(), 200, "/healthz must be auth-free");
    assert_eq!(healthz.text().await.unwrap(), "ok");

    // /register is itself an exempt route: without credentials it reaches
    // the register handler, which answers the upstream bind validation
    // (400 "device token is empty") — crucially NOT the 418 teapot.
    let register = http.get(server.url("/register")).send().await.unwrap();
    assert_eq!(register.status(), 400, "/register must be exempt, not 418");
    let body: serde_json::Value = register.json().await.unwrap();
    assert_envelope_no_data(&body, 400, "device token is empty");
    server.shutdown().await;
}

#[tokio::test]
async fn exemption_is_a_byte_prefix_on_the_raw_path() {
    // Upstream: strings.HasPrefix(c.Path(), prefix) — byte prefix, raw path,
    // so /pingpong and /ping/2 pass without auth and land on the compat push
    // routes (ticket 04), while /PING does not.
    let server = spawn_auth("/", "u", "p").await;
    let http = client();

    let pingpong = http.get(server.url("/pingpong")).send().await.unwrap();
    assert_eq!(
        pingpong.status(),
        400,
        "byte-prefix exemption, then compat push"
    );
    let body: serde_json::Value = pingpong.json().await.unwrap();
    assert_envelope_no_data(
        &body,
        400,
        "failed to get device token: failed to get [pingpong] device token from database",
    );

    let ping2 = http.get(server.url("/ping/2")).send().await.unwrap();
    assert_eq!(
        ping2.status(),
        400,
        "byte-prefix exemption, then compat push"
    );
    let body: serde_json::Value = ping2.json().await.unwrap();
    assert_envelope_no_data(
        &body,
        400,
        "failed to get device token: failed to get [ping] device token from database",
    );

    let pingpong_case = http.get(server.url("/PINGPONG")).send().await.unwrap();
    assert_eq!(
        pingpong_case.status(),
        418,
        "prefix match is case-sensitive"
    );

    let encoded = http.get(server.url("/p%69ng")).send().await.unwrap();
    assert_eq!(
        encoded.status(),
        418,
        "prefix match sees the raw percent-encoded path"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn exempt_paths_pass_even_with_wrong_credentials() {
    // Upstream checks exemptions inside the Unauthorized handler, so bad
    // credentials on an exempt path still proceed.
    let server = spawn_auth("/", "u", "p").await;
    let res = client()
        .get(server.url("/ping"))
        .basic_auth("u", Some("nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "exemption outranks bad credentials");
    let body: serde_json::Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 200, "pong");
    server.shutdown().await;
}

#[tokio::test]
async fn bare_root_escapes_auth_like_upstream() {
    // Upstream mounts the middleware with fiber's Use("/+"), whose `+` is a
    // required greedy parameter: the bare root "/" (any all-slash path) is
    // not covered and answers "ok" without credentials. Verified against the
    // Go binary; mirrored for compatibility (ADR-0003).
    let server = spawn_auth("/", "u", "p").await;
    let res = client().get(server.url("/")).send().await.unwrap();
    assert_eq!(res.status(), 200, "bare root stays auth-free upstream");
    assert_eq!(res.text().await.unwrap(), "ok");
    server.shutdown().await;
}

#[tokio::test]
async fn basic_auth_header_parsing_mirrors_fiber() {
    let server = spawn_auth("/", "u", "p").await;
    let http = client();
    let url = server.url("/info");

    let lower_scheme = http
        .get(&url)
        .header("Authorization", "basic dTpw")
        .send()
        .await
        .unwrap();
    assert_eq!(
        lower_scheme.status(),
        200,
        "scheme match is case-insensitive"
    );

    let bearer = http
        .get(&url)
        .header("Authorization", "Bearer xyz")
        .send()
        .await
        .unwrap();
    assert_eq!(bearer.status(), 418, "non-basic schemes are rejected");

    let bad_base64 = http
        .get(&url)
        .header("Authorization", "Basic !!!not-base64!!!")
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad_base64.status(),
        418,
        "undecodable credentials are rejected"
    );

    let no_colon = http
        .get(&url)
        // base64("up") — no colon separator.
        .header("Authorization", "Basic dXA=")
        .send()
        .await
        .unwrap();
    assert_eq!(
        no_colon.status(),
        418,
        "credentials without a colon are rejected"
    );

    let bare_scheme = http
        .get(&url)
        .header("Authorization", "Basic")
        .send()
        .await
        .unwrap();
    assert_eq!(
        bare_scheme.status(),
        418,
        "bare scheme without payload is rejected"
    );
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// Non-root --url-prefix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_under_non_root_url_prefix() {
    let server = spawn_auth("/bark", "u", "p").await;
    let http = client();

    // Protected inside the prefix.
    let denied = http.get(server.url("/info")).send().await.unwrap();
    assert_eq!(denied.status(), 418, "/bark/info must demand auth");
    let ok = http
        .get(server.url("/info"))
        .basic_auth("u", Some("p"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200, "correct credentials must proceed");

    // Exemptions are joined with the prefix.
    let ping = http.get(server.url("/ping")).send().await.unwrap();
    assert_eq!(ping.status(), 200, "/bark/ping must be exempt");
    // The exempt register route answers under the prefix (400 from the
    // register handler's bind validation — not the 418 teapot).
    let register = http.get(server.url("/register")).send().await.unwrap();
    assert_eq!(register.status(), 400, "/bark/register exempt, not 418");
    let healthzz = http.get(server.url("/healthzz")).send().await.unwrap();
    assert_eq!(
        healthzz.status(),
        400,
        "joined byte-prefix exemption lands on the compat push"
    );
    let pingpong = http.get(server.url("/pingpong")).send().await.unwrap();
    assert_eq!(
        pingpong.status(),
        400,
        "joined byte-prefix exemption lands on the compat push"
    );

    // Raw-path case sensitivity still applies under the prefix.
    let case = http.get(server.url("/PING")).send().await.unwrap();
    assert_eq!(
        case.status(),
        418,
        "/bark/PING is not the raw exemption prefix"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn paths_outside_url_prefix_are_not_auth_covered() {
    // Upstream mounts the middleware on the url-prefix group: outside the
    // prefix there is no auth challenge, just the plain 404 (verified against
    // the Go binary).
    let server = spawn_auth("/bark", "u", "p").await;
    let http = client();

    let outside = http
        .get(format!("{}/info", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        outside.status(),
        404,
        "outside the prefix: no 418, just 404"
    );
    let body: serde_json::Value = outside.json().await.unwrap();
    assert_envelope_no_data(&body, 404, "Cannot GET /info");

    // The prefix root itself (/bark, /bark/) is not covered by "/prefix/+"
    // either and answers "ok" without credentials.
    let prefix_root = http.get(server.url("/")).send().await.unwrap();
    assert_eq!(prefix_root.status(), 200, "/bark stays auth-free upstream");
    assert_eq!(prefix_root.text().await.unwrap(), "ok");
    server.shutdown().await;
}

#[tokio::test]
async fn head_requests_require_auth_like_upstream() {
    let server = spawn_auth("/", "u", "p").await;
    let res = client().head(server.url("/info")).send().await.unwrap();
    assert_eq!(res.status(), 418, "HEAD is covered like any method");
    server.shutdown().await;
}
