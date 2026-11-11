//! Ticket 09 acceptance: MCP endpoints (`/mcp`, `/mcp/:device_key`) over the
//! HTTP boundary. The behavioral oracle is upstream bark-server v2.4.0
//! (`route_mcp.go`, mark3labs/mcp-go v1.1.0 StreamableHTTPServer with
//! streaming disabled) — every test speaks MCP JSON-RPC over HTTP with
//! reqwest against the real server, and the APNs endpoint is the local
//! HTTPS HTTP/2 stub (tests/common/apns_stub.rs): no request ever reaches
//! Apple.

mod common;

use common::apns_stub::ApnsStub;
use common::{TestServer, client, ephemeral_config};
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

/// POST one JSON-RPC message to an MCP endpoint.
async fn mcp_post(
    server: &TestServer,
    path: &str,
    session: Option<&str>,
    body: Value,
) -> reqwest::Response {
    let mut req = client()
        .post(server.url(path))
        .header("Content-Type", "application/json");
    if let Some(session) = session {
        req = req.header("Mcp-Session-Id", session);
    }
    req.json(&body).send().await.unwrap()
}

/// The initialize handshake: returns the session id from the response header
/// and the parsed result.
async fn initialize(server: &TestServer, path: &str) -> (String, Value) {
    let res = mcp_post(
        server,
        path,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-seam-test", "version": "0"}
            }
        }),
    )
    .await;
    assert_eq!(res.status(), 200, "initialize failed: {res:?}");
    let session = res
        .headers()
        .get("Mcp-Session-Id")
        .map(|v| v.to_str().unwrap().to_string())
        .expect("initialize must return an Mcp-Session-Id header");
    let body: Value = res.json().await.unwrap();
    (session, body["result"].clone())
}

async fn tools_list(server: &TestServer, path: &str, session: &str) -> Value {
    let res = mcp_post(
        server,
        path,
        Some(session),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    assert_eq!(res.status(), 200, "tools/list failed: {res:?}");
    let body: Value = res.json().await.unwrap();
    body["result"].clone()
}

async fn tools_call(
    server: &TestServer,
    path: &str,
    session: &str,
    name: &str,
    args: Value,
) -> Value {
    let res = mcp_post(
        server,
        path,
        Some(session),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": name, "arguments": args}
        }),
    )
    .await;
    assert_eq!(res.status(), 200, "tools/call failed: {res:?}");
    let body: Value = res.json().await.unwrap();
    body["result"].clone()
}

// ---------------------------------------------------------------------------
// Slice 1: generic /mcp — handshake, tool discovery, notify via the Push core
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generic_endpoint_full_handshake_and_push() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let key = register_device(&server, "PUSHTOKEN1", "ios").await;

    // initialize → session id + upstream server identity/capabilities.
    let (session, init) = initialize(&server, "/mcp").await;
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert_eq!(init["capabilities"], json!({"tools": {}}));
    assert_eq!(
        init["serverInfo"],
        json!({"name": "Bark MCP Server", "version": bark_server_rs::VERSION})
    );
    assert!(
        session.starts_with("mcp-session-"),
        "session id must carry the upstream prefix: {session}"
    );

    // tools/list → exactly the upstream notify tool (generic variant: the
    // required device_key argument).
    let listed = tools_list(&server, "/mcp", &session).await;
    assert_eq!(listed, json!({"tools": [notify_tool_generic()]}));

    // tools/call → notify routes through the same Push core as HTTP pushes.
    let result = tools_call(
        &server,
        "/mcp",
        &session,
        "notify",
        json!({
            "device_key": key,
            "title": "Reminder",
            "body": "Stand up",
            "level": "timeSensitive",
            "volume": 5,
        }),
    )
    .await;
    assert_eq!(
        result,
        json!({"content": [{"type": "text", "text": "Notification sent successfully"}]}),
        "successful notify must return the upstream text result: {result}"
    );

    // The push reached the APNs stub with the requested fields.
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 1, "exactly one APNs delivery");
    let p = &pushes[0];
    assert_eq!(p.path, "/3/device/PUSHTOKEN1");
    assert_eq!(p.apns_topic.as_deref(), Some("me.fin.bark"));
    assert_eq!(p.apns_push_type.as_deref(), Some("alert"));
    let alert = &p.payload["aps"]["alert"];
    assert_eq!(alert["title"], "Reminder");
    assert_eq!(alert["body"], "Stand up");
    // level and volume travel as Ext Params custom payload keys, stringified
    // with Go `%v` exactly like HTTP pushes (a JSON number → "5").
    assert_eq!(p.payload["level"], "timeSensitive");
    assert_eq!(p.payload["volume"], "5");
    assert_eq!(
        p.payload["aps"]["mutable-content"], 1,
        "always mutable-content"
    );
    assert_eq!(p.payload["aps"]["sound"], "1107", "default sound");

    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 2: /mcp/:device_key — path-bound device key, overwriting args
// ---------------------------------------------------------------------------
#[tokio::test]
async fn specific_endpoint_binds_path_device_key_over_args() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let path_key = register_device(&server, "PUSHTOKEN1", "ios").await;
    let other_key = register_device(&server, "PUSHTOKEN2", "ios").await;

    // initialize → the specific server identity.
    let (session, init) = initialize(&server, &format!("/mcp/{path_key}")).await;
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert_eq!(
        init["serverInfo"]["name"], "Bark MCP Server (Specific)",
        "the path-bound endpoint runs its own server instance"
    );

    // tools/list → the common parameter table WITHOUT device_key.
    let listed = tools_list(&server, &format!("/mcp/{path_key}"), &session).await;
    assert_eq!(listed, json!({"tools": [notify_tool_specific()]}));

    // tools/call without a device_key argument → the path key is used.
    let result = tools_call(
        &server,
        &format!("/mcp/{path_key}"),
        &session,
        "notify",
        json!({"title": "From path", "body": "no args key"}),
    )
    .await;
    assert_eq!(
        result,
        json!({"content": [{"type": "text", "text": "Notification sent successfully"}]}),
        "path key alone must suffice: {result}"
    );

    // A conflicting device_key argument is OVERWRITTEN by the path key.
    let result = tools_call(
        &server,
        &format!("/mcp/{path_key}"),
        &session,
        "notify",
        json!({
            "device_key": other_key,
            "title": "Conflict",
            "body": "path must win",
        }),
    )
    .await;
    assert_eq!(
        result["isError"],
        Value::Null,
        "no error expected: {result}"
    );
    assert_eq!(
        result["content"][0]["text"],
        "Notification sent successfully"
    );

    // Both pushes reached the stub on the PATH-bound device.
    let pushes = stub.pushes();
    assert_eq!(pushes.len(), 2, "exactly two APNs deliveries");
    assert_eq!(pushes[0].path, "/3/device/PUSHTOKEN1");
    assert_eq!(pushes[1].path, "/3/device/PUSHTOKEN1", "path key wins");
    assert_eq!(pushes[0].payload["aps"]["alert"]["title"], "From path");
    assert_eq!(pushes[1].payload["aps"]["alert"]["title"], "Conflict");

    server.shutdown().await;
    stub.shutdown().await;
}

/// The generic endpoint's notify tool, exactly as mcp-go serializes upstream
/// `getCommonToolOpts()` + the required device_key string (map keys in Go's
/// sorted marshaling order).
fn notify_tool_generic() -> Value {
    let mut tool = notify_tool_common();
    tool["inputSchema"]["properties"]["device_key"] =
        json!({"type": "string", "description": "Device Key"});
    tool["inputSchema"]["required"] = json!(["device_key"]);
    tool
}

/// The path-bound endpoint's notify tool: the common parameter table without
/// the device_key argument (`required` marshals as `[]`).
fn notify_tool_specific() -> Value {
    notify_tool_common()
}

/// Upstream `getCommonToolOpts()` as mcp-go serializes it.
fn notify_tool_common() -> Value {
    json!({
        "name": "notify",
        "description": "Send a notification to a device via Bark",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Notification title"},
                "subtitle": {"type": "string", "description": "Notification subtitle"},
                "body": {"type": "string", "description": "Notification content"},
                "markdown": {"type": "string", "description": "Basic Markdown notification content. Overrides body."},
                "level": {
                    "type": "string",
                    "description": "Notification level",
                    "enum": ["critical", "active", "timeSensitive", "passive"],
                },
                "volume": {
                    "type": "number",
                    "description": "Alert volume for important notification",
                    "default": 5,
                    "minimum": 0,
                    "maximum": 10,
                },
                "badge": {"type": "number", "description": "Badge number"},
                "call": {"type": "string", "description": "Set to '1' to repeat the notification ringtone"},
                "sound": {"type": "string", "description": "Notification sound"},
                "icon": {"type": "string", "description": "Notification icon URL"},
                "image": {"type": "string", "description": "Notification image URL"},
                "group": {"type": "string", "description": "Notification group"},
                "isArchive": {"type": "string", "description": "Set to '1' to save the notification or any other value to skip saving"},
                "ttl": {"type": "number", "description": "Time to live in seconds for archived messages; expired items are automatically deleted"},
                "url": {"type": "string", "description": "Click action URL"},
                "copy": {"type": "string", "description": "Text to copy on copy action"},
            },
            "required": [],
        },
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": true,
            "idempotentHint": false,
            "openWorldHint": true,
        },
    })
}

// ---------------------------------------------------------------------------
// Slice 3: tool error results with upstream-matching texts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn notify_error_results_match_upstream_texts() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let (session, _) = initialize(&server, "/mcp").await;

    // Missing device_key (empty arguments object).
    let result = tools_call(&server, "/mcp", &session, "notify", json!({})).await;
    assert_eq!(
        result,
        json!({"content": [{"type": "text", "text": "device_key is required"}], "isError": true}),
        "missing device_key must be the upstream error result"
    );

    // A non-string device_key argument is ignored (Go type assertion).
    let result = tools_call(
        &server,
        "/mcp",
        &session,
        "notify",
        json!({"device_key": 42}),
    )
    .await;
    assert_eq!(result["content"][0]["text"], "device_key is required");

    // Unknown device key → the push core error, wrapped in the upstream text.
    let result = tools_call(
        &server,
        "/mcp",
        &session,
        "notify",
        json!({"device_key": "nope"}),
    )
    .await;
    assert_eq!(
        result["content"][0]["text"],
        "Failed to send notification: failed to get device token: failed to get [nope] device token from database (code 400)",
    );
    assert_eq!(result["isError"], true);
    assert_eq!(stub.push_count(), 0, "nothing reached APNs");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn invalid_argument_shapes_match_upstream_text() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let (session, _) = initialize(&server, "/mcp").await;

    // Absent, null, and non-object arguments all fail the upstream
    // `map[string]any` type assertion.
    for arguments in [json!(null), json!(42), json!("text"), json!([1, 2])] {
        let res = mcp_post(
            &server,
            "/mcp",
            Some(&session),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "notify", "arguments": arguments}
            }),
        )
        .await;
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        assert_eq!(
            body["result"],
            json!({"content": [{"type": "text", "text": "Invalid arguments format"}], "isError": true}),
            "arguments {arguments} must yield the upstream format error"
        );
    }
    assert_eq!(stub.push_count(), 0);

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn unknown_tool_is_a_jsonrpc_error() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let (session, _) = initialize(&server, "/mcp").await;

    let res = mcp_post(
        &server,
        "/mcp",
        Some(&session),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "nope"}}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "error": {"code": -32602, "message": "tool 'nope' not found: tool not found"},
        })
    );

    // A missing tool name behaves like an empty one.
    let res = mcp_post(
        &server,
        "/mcp",
        Some(&session),
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {}}),
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["error"],
        json!({"code": -32602, "message": "tool '' not found: tool not found"}),
    );

    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 4: transport semantics of the non-streaming Streamable HTTP endpoint
// ---------------------------------------------------------------------------

/// The raw response body as a String plus status (for plain-text errors).
async fn mcp_post_raw(
    server: &TestServer,
    path: &str,
    method: reqwest::Method,
    session: Option<&str>,
    content_type: Option<&str>,
    body: Option<String>,
) -> reqwest::Response {
    let mut req = client().request(method, server.url(path));
    if let Some(ct) = content_type {
        req = req.header("Content-Type", ct);
    }
    if let Some(session) = session {
        req = req.header("Mcp-Session-Id", session);
    }
    match body {
        Some(text) => req.body(text).send().await.unwrap(),
        None => req.send().await.unwrap(),
    }
}

#[tokio::test]
async fn transport_semantics_match_upstream() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let (session, _) = initialize(&server, "/mcp").await;

    // notifications/initialized (no id) → 202 Accepted, empty body.
    let res = mcp_post(
        &server,
        "/mcp",
        Some(&session),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(res.status(), 202);
    assert_eq!(
        res.bytes().await.unwrap(),
        b"" as &[u8],
        "202 must be empty"
    );

    // ping → {}.
    let res = mcp_post(
        &server,
        "/mcp",
        Some(&session),
        json!({"jsonrpc": "2.0", "id": 9, "method": "ping"}),
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"jsonrpc": "2.0", "id": 9, "result": {}}));

    // Non-initialize POST without a session header → 404 plain text.
    let res = mcp_post(
        &server,
        "/mcp",
        None,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    assert_eq!(res.status(), 404);
    assert_eq!(res.text().await.unwrap(), "Invalid session ID\n");

    // A malformed session id → same 404.
    let res = mcp_post(
        &server,
        "/mcp",
        Some("garbage"),
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    assert_eq!(res.status(), 404);
    assert_eq!(res.text().await.unwrap(), "Invalid session ID\n");

    // GET → 405 (streaming disabled), DELETE → 200 then the session is gone.
    let res = mcp_post_raw(&server, "/mcp", reqwest::Method::GET, None, None, None).await;
    assert_eq!(res.status(), 405);
    assert_eq!(
        res.text().await.unwrap(),
        "Streaming is disabled on this server\n"
    );

    let res = mcp_post_raw(
        &server,
        "/mcp",
        reqwest::Method::DELETE,
        Some(&session),
        None,
        None,
    )
    .await;
    assert_eq!(res.status(), 200);
    let res = mcp_post(
        &server,
        "/mcp",
        Some(&session),
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    assert_eq!(res.status(), 404);
    assert_eq!(res.text().await.unwrap(), "Session terminated\n");

    // HEAD → 200 empty; PUT → net/http's plain-text 404.
    let res = mcp_post_raw(&server, "/mcp", reqwest::Method::HEAD, None, None, None).await;
    assert_eq!(res.status(), 200);
    let res = mcp_post_raw(&server, "/mcp", reqwest::Method::PUT, None, None, None).await;
    assert_eq!(res.status(), 404);
    assert_eq!(res.text().await.unwrap(), "404 page not found\n");

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn post_body_validation_and_jsonrpc_dispatch_errors() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;
    let (session, _) = initialize(&server, "/mcp").await;

    // Wrong content type → 400 plain text.
    let res = mcp_post_raw(
        &server,
        "/mcp",
        reqwest::Method::POST,
        Some(&session),
        Some("text/plain"),
        Some("{}".into()),
    )
    .await;
    assert_eq!(res.status(), 400);
    assert_eq!(
        res.text().await.unwrap(),
        "Invalid content type: must be 'application/json'\n"
    );

    // A content type with parameters is fine (mime.ParseMediaType).
    let res = mcp_post_raw(
        &server,
        "/mcp",
        reqwest::Method::POST,
        Some(&session),
        Some("application/json; charset=utf-8"),
        Some(json!({"jsonrpc": "2.0", "id": 9, "method": "ping"}).to_string()),
    )
    .await;
    assert_eq!(res.status(), 200, "charset parameter must be accepted");

    // Not JSON at all → 400 with the parse-error JSON-RPC envelope.
    let res = mcp_post_raw(
        &server,
        "/mcp",
        reqwest::Method::POST,
        Some(&session),
        Some("application/json"),
        Some("this is not json".into()),
    )
    .await;
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {"code": -32700, "message": "request body is not valid json"},
        })
    );

    // Valid JSON but not an object (an array) → same parse error.
    let res = mcp_post_raw(
        &server,
        "/mcp",
        reqwest::Method::POST,
        Some(&session),
        Some("application/json"),
        Some("[1,2]".into()),
    )
    .await;
    assert_eq!(res.status(), 400);

    // Unknown method → JSON-RPC -32601 with the upstream message.
    let res = mcp_post(
        &server,
        "/mcp",
        Some(&session),
        json!({"jsonrpc": "2.0", "id": 5, "method": "resources/list"}),
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "error": {"code": -32601, "message": "Method resources/list not found"},
        })
    );

    // Wrong JSON-RPC version → -32600.
    let res = mcp_post(
        &server,
        "/mcp",
        Some(&session),
        json!({"jsonrpc": "1.0", "id": 6, "method": "ping"}),
    )
    .await;
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["error"],
        json!({"code": -32600, "message": "Invalid JSON-RPC version"})
    );

    server.shutdown().await;
    stub.shutdown().await;
}

#[tokio::test]
async fn initialize_negotiates_protocol_versions_like_mcp_go() {
    let stub = ApnsStub::spawn().await;
    let server = spawn_with_stub(&stub).await;

    async fn init_with_version(server: &TestServer, version: Value) -> String {
        let mut params = json!({"capabilities": {}, "clientInfo": {"name": "t", "version": "0"}});
        if !version.is_null() {
            params["protocolVersion"] = version;
        }
        let res = mcp_post(
            server,
            "/mcp",
            None,
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}),
        )
        .await;
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        body["result"]["protocolVersion"]
            .as_str()
            .unwrap()
            .to_string()
    }

    // Known legacy versions are echoed.
    assert_eq!(
        init_with_version(&server, json!("2025-03-26")).await,
        "2025-03-26"
    );
    assert_eq!(
        init_with_version(&server, json!("2025-06-18")).await,
        "2025-06-18"
    );
    assert_eq!(
        init_with_version(&server, json!("2025-11-25")).await,
        "2025-11-25"
    );
    // Unknown versions fall back to the latest legacy one.
    assert_eq!(
        init_with_version(&server, json!("1999-01-01")).await,
        "2025-11-25"
    );
    // Absent version assumes 2025-03-26.
    assert_eq!(init_with_version(&server, Value::Null).await, "2025-03-26");

    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 5: session idle TTL closes stale sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_idle_ttl_closes_stale_sessions() {
    let stub = ApnsStub::spawn().await;
    let (mut config, dir) = ephemeral_config();
    config.apns_endpoint = stub.url.clone();
    config.apns_insecure_skip_tls_verify = true;
    config.mcp_session_idle_ttl = std::time::Duration::from_secs(1);
    let server = TestServer::spawn(config, dir).await;

    let (session, _) = initialize(&server, "/mcp").await;

    // Activity refreshes the idle timer: two requests spaced at 0.6s both
    // succeed even though the TTL is 1s.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let listed = tools_list(&server, "/mcp", &session).await;
    assert_eq!(listed["tools"][0]["name"], "notify");
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let listed = tools_list(&server, "/mcp", &session).await;
    assert_eq!(
        listed["tools"][0]["name"], "notify",
        "touched session stays alive"
    );

    // Idle past the TTL → the stale session is closed.
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    let res = mcp_post(
        &server,
        "/mcp",
        Some(&session),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    assert_eq!(res.status(), 404, "stale session must be closed");
    assert_eq!(res.text().await.unwrap(), "Invalid session ID\n");

    // A fresh initialize starts a new working session afterwards.
    let (fresh, init) = initialize(&server, "/mcp").await;
    assert_eq!(init["serverInfo"]["name"], "Bark MCP Server");
    let listed = tools_list(&server, "/mcp", &fresh).await;
    assert_eq!(listed["tools"][0]["name"], "notify");

    server.shutdown().await;
    stub.shutdown().await;
}

// ---------------------------------------------------------------------------
// Slice 6: Basic Auth covers the MCP endpoints automatically
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mcp_endpoints_require_basic_auth_when_enabled() {
    let stub = ApnsStub::spawn().await;
    let (mut config, dir) = ephemeral_config();
    config.apns_endpoint = stub.url.clone();
    config.apns_insecure_skip_tls_verify = true;
    config.basic_auth_user = "u".into();
    config.basic_auth_password = "p".into();
    let server = TestServer::spawn(config, dir).await;

    // Unauthenticated initialize → 418 teapot, like every covered route.
    let res = mcp_post(
        &server,
        "/mcp",
        None,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
    )
    .await;
    assert_eq!(res.status(), 418);
    assert_eq!(res.text().await.unwrap(), "I'm a teapot");

    // Wrong credentials → same teapot, on both endpoints.
    let res = client()
        .post(server.url("/mcp/whatever"))
        .header("Content-Type", "application/json")
        .basic_auth("u", Some("wrong"))
        .body(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 418);

    // With credentials the full handshake works on the path-bound endpoint.
    let res = client()
        .post(server.url("/mcp/key"))
        .header("Content-Type", "application/json")
        .basic_auth("u", Some("p"))
        .body(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let session = res
        .headers()
        .get("Mcp-Session-Id")
        .expect("session header")
        .to_str()
        .unwrap()
        .to_string();
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["result"]["serverInfo"]["name"],
        "Bark MCP Server (Specific)"
    );

    let res = client()
        .post(server.url("/mcp/key"))
        .header("Content-Type", "application/json")
        .header("Mcp-Session-Id", &session)
        .basic_auth("u", Some("p"))
        .body(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["result"]["tools"][0]["name"], "notify");

    server.shutdown().await;
    stub.shutdown().await;
}
