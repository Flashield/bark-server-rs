//! MCP tool server: the `/mcp` (generic) and `/mcp/:device_key` (path-bound)
//! Streamable-HTTP endpoints exposing the single `notify` tool, mirroring
//! upstream `route_mcp.go` (bark-server v2.4.0, mark3labs/mcp-go v1.1.0).
//!
//! Upstream surface: two `StreamableHTTPServer` instances registered for ALL
//! HTTP methods, `WithDisableStreaming(true)` (GET answers 405), a 10-minute
//! idle session TTL, `WithToolCapabilities(false)` and `WithRecovery`. The
//! `notify` tool mirrors upstream's exact parameter table and result texts,
//! resolves `device_key` (tool args first, path overwrites), requires it, and
//! routes through the same Push core as HTTP pushes
//! ([`crate::api::push::push_core`]).
//!
//! Wire protocol (hand-rolled instead of an MCP SDK crate — the upstream
//! surface is deliberately non-streaming and small, and exact text/schema
//! parity with mcp-go v1.1.0 rules the implementation):
//!
//! - POST `application/json` bodies carry JSON-RPC 2.0 messages; responses
//!   are single `application/json` bodies (HTTP 200), never SSE streams;
//! - `initialize` mints a `mcp-session-<uuid>` session, echoed in the
//!   `Mcp-Session-Id` response header; every other POST must carry that
//!   header with a well-formed id of a live session — plain-text 404s mirror
//!   mcp-go (`Invalid session ID` / `Session terminated`);
//! - notifications (no `id`) and client responses with empty results answer
//!   `202 Accepted`; client-to-server responses (sampling answers) answer the
//!   upstream plain-text errors — bark never issues server-initiated requests;
//! - JSON-RPC dispatch: `initialize` (version negotiation per mcp-go
//!   `NegotiateLegacyVersion`), `ping`, `tools/list`, `tools/call`, anything
//!   else → `-32601` `Method <m> not found`; unknown tools → `-32602`
//!   `tool '<n>' not found: tool not found`; bodies that are not JSON objects
//!   → HTTP 400 `-32700` `request body is not valid json`;
//! - GET answers 405 `Streaming is disabled on this server`, DELETE
//!   terminates the session (200), HEAD answers an empty 200, and every other
//!   method answers net/http's plain-text `404 page not found`.
//!
//! Session TTL: sessions are tracked with a last-activity timestamp; a
//! request carrying an id idle beyond the TTL answers 404 `Invalid session
//! ID` and a background sweeper (interval `max(ttl/2, 1s)`, like mcp-go)
//! reclaims the state. This makes the upstream TTL observable: mcp-go's
//! default stateless manager only validates id *format* (any well-formed id
//! is accepted and never expires) — here issued sessions expire, which is the
//! MCP-spec behavior (clients re-initialize on 404) and keeps the acceptance
//! contract "session idle TTL closes stale sessions" testable. Two further
//! deliberate deviations, both noted here for completeness: mcp-go's DNS
//! rebinding protection (loopback connections presenting a non-localhost
//! `Host`) is not mirrored — bark-server is a network service and the check
//! would need connection-local addresses plumbed through the whole app — and
//! the `2026-07-28` stateless protocol era is not served (real clients still
//! speak the initialize-based legacy flow; `NegotiateLegacyVersion` caps
//! protocol versions at `2025-11-25`).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use axum::extract::{Path, Request, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use crate::api::push::push_core;
use crate::server::AppState;

/// Upstream `mcpSessionIdleTTL`.
pub const SESSION_IDLE_TTL: Duration = Duration::from_secs(10 * 60);

/// mcp-go's `idPrefix` for streamable-HTTP session ids.
const SESSION_ID_PREFIX: &str = "mcp-session-";

/// Protocol versions this server negotiates (mcp-go v1.1.0 legacy set).
const LEGACY_PROTOCOL_VERSIONS: &[&str] = &["2025-03-26", "2025-06-18", "2025-11-25"];

/// JSON-RPC 2.0 error codes (mcp-go `mcp.PARSE_ERROR` etc.).
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const MCP_SESSION_ID_HEADER: HeaderName = HeaderName::from_static("mcp-session-id");

/// Generous read cap, matching the push/register routes.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The two tool servers. Sessions are per-instance, exactly like upstream's
/// two `StreamableHTTPServer`s.
#[derive(Clone)]
pub struct McpRegistry {
    generic: McpServer,
    specific: McpServer,
}

impl McpRegistry {
    pub fn new(idle_ttl: Duration) -> Self {
        Self {
            generic: McpServer {
                name: "Bark MCP Server",
                device_key_in_schema: true,
                sessions: SessionTable::new(idle_ttl),
            },
            specific: McpServer {
                name: "Bark MCP Server (Specific)",
                device_key_in_schema: false,
                sessions: SessionTable::new(idle_ttl),
            },
        }
    }
}

#[derive(Clone)]
struct McpServer {
    name: &'static str,
    /// The generic endpoint declares `device_key` as a required tool argument
    /// (upstream appends `mcp.WithString("device_key", mcp.Required(), ...)`).
    device_key_in_schema: bool,
    sessions: SessionTable,
}

/// `POST /mcp` — generic endpoint: `device_key` comes from the tool args.
pub async fn generic(State(state): State<AppState>, req: Request) -> Response {
    state.mcp.generic.handle(&state, None, req).await
}

/// `POST /mcp/:device_key` — path-bound endpoint: the path `device_key` is
/// injected over the tool args (upstream's `deviceKeyCtxKey` context value).
pub async fn specific(
    State(state): State<AppState>,
    Path(device_key): Path<String>,
    req: Request,
) -> Response {
    state
        .mcp
        .specific
        .handle(&state, Some(device_key), req)
        .await
}

impl McpServer {
    /// Upstream `ServeHTTP` method dispatch. All methods are registered
    /// (fiber `router.All`), so nothing answers 405 from the router itself.
    async fn handle(
        &self,
        state: &AppState,
        path_device_key: Option<String>,
        req: Request,
    ) -> Response {
        match *req.method() {
            axum::http::Method::POST => self.handle_post(state, path_device_key, req).await,
            // WithDisableStreaming(true): every GET is rejected before any
            // session handling.
            axum::http::Method::GET => text_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "Streaming is disabled on this server",
            ),
            // DELETE terminates the session; unknown ids answer 200 anyway
            // (upstream's manager Terminate is a no-op for unknown ids).
            axum::http::Method::DELETE => {
                if let Some(id) = session_header(req.headers()) {
                    self.sessions.terminate(&id);
                }
                StatusCode::OK.into_response()
            }
            axum::http::Method::HEAD => StatusCode::OK.into_response(),
            _ => text_error(StatusCode::NOT_FOUND, "404 page not found"),
        }
    }

    /// Upstream `handlePost` + `MCPServer.HandleMessage` (legacy, session era).
    async fn handle_post(
        &self,
        state: &AppState,
        path_device_key: Option<String>,
        req: Request,
    ) -> Response {
        // Content type: `mime.ParseMediaType` must yield exactly
        // `application/json` (parameters like charset are fine).
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !media_type_is_json(content_type) {
            return text_error(
                StatusCode::BAD_REQUEST,
                "Invalid content type: must be 'application/json'",
            );
        }
        let session_header_value = session_header(req.headers());

        let body = req.into_body();
        let bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
            Ok(bytes) => bytes,
            Err(e) => {
                return jsonrpc_error_response(
                    StatusCode::BAD_REQUEST,
                    &Value::Null,
                    PARSE_ERROR,
                    &format!("read request body error: {e}"),
                );
            }
        };

        // Probe the message shape first (upstream's 4-field struct): the body
        // must be a JSON object, `method` must be a string when present.
        let probe = match parse_probe(&bytes) {
            Ok(probe) => probe,
            Err(()) => {
                return jsonrpc_error_response(
                    StatusCode::BAD_REQUEST,
                    &Value::Null,
                    PARSE_ERROR,
                    "request body is not valid json",
                );
            }
        };

        // Client-to-server responses (no method, an id): empty results are
        // accepted with 202; anything else would answer a server-initiated
        // request, which bark never issues.
        if probe.method.is_empty() && probe.id.is_some() {
            let result_empty = probe.result.as_ref().is_none_or(json_empty);
            let error_empty = probe.error.as_ref().is_none_or(json_empty);
            if result_empty && error_empty {
                return StatusCode::ACCEPTED.into_response();
            }
            return self.sampling_response_rejection(session_header_value.as_deref());
        }

        // Session handling: initialize mints a session; every other message
        // must present a live session id.
        let is_initialize = probe.method == "initialize";
        let session_id = if is_initialize {
            self.sessions.mint()
        } else {
            let Some(id) = session_header_value else {
                return text_error(StatusCode::NOT_FOUND, "Invalid session ID");
            };
            if !is_session_id(&id) {
                return text_error(StatusCode::NOT_FOUND, "Invalid session ID");
            }
            match self.sessions.validate_and_touch(&id) {
                SessionCheck::Active => id,
                SessionCheck::Terminated => {
                    return text_error(StatusCode::NOT_FOUND, "Session terminated");
                }
                SessionCheck::Unknown => {
                    return text_error(StatusCode::NOT_FOUND, "Invalid session ID");
                }
            }
        };

        // JSON-RPC dispatch (upstream `HandleMessage`).
        let id = probe.id.clone().unwrap_or(Value::Null);
        if probe.jsonrpc_was_wrong_type {
            return jsonrpc_error_response(
                StatusCode::OK,
                &id,
                PARSE_ERROR,
                "Failed to parse message",
            );
        }
        if probe.jsonrpc.as_deref() != Some("2.0") {
            return jsonrpc_error_response(
                StatusCode::OK,
                &id,
                INVALID_REQUEST,
                "Invalid JSON-RPC version",
            );
        }
        let Some(id) = probe.id.clone() else {
            // Notification: no response, nothing to do (upstream returns nil
            // → 202 Accepted).
            return StatusCode::ACCEPTED.into_response();
        };

        let response: JsonRpcOut = match probe.method.as_str() {
            "initialize" => JsonRpcOut::result(
                &id,
                json!({
                    "protocolVersion": negotiate_protocol_version(probe.protocol_version.as_deref()),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": self.name, "version": crate::VERSION},
                }),
            ),
            "ping" => JsonRpcOut::result(&id, json!({})),
            "tools/list" => JsonRpcOut::result(&id, json!({"tools": [self.tool_json()]})),
            "tools/call" => {
                self.handle_tool_call(state, path_device_key.as_deref(), &probe, &id)
                    .await
            }
            other => JsonRpcOut::error(&id, METHOD_NOT_FOUND, &format!("Method {other} not found")),
        };

        let mut res = response.into_response();
        if is_initialize {
            res.headers_mut().insert(
                MCP_SESSION_ID_HEADER,
                session_id.parse().expect("session id header"),
            );
        }
        res
    }

    /// Upstream `handleSamplingResponse` + `deliverSamplingResponse` for a
    /// client answer bark never asked for: session validation order mirrors
    /// upstream, then the missing pending request fails the call.
    fn sampling_response_rejection(&self, session_header: Option<&str>) -> Response {
        let Some(sid) = session_header else {
            return text_error(
                StatusCode::BAD_REQUEST,
                "Missing session ID for sampling response",
            );
        };
        if !is_session_id(sid) {
            return text_error(StatusCode::NOT_FOUND, "Invalid session ID");
        }
        match self.sessions.validate_without_touch(sid) {
            SessionCheck::Terminated => text_error(StatusCode::NOT_FOUND, "Session terminated"),
            SessionCheck::Unknown => text_error(
                StatusCode::NOT_FOUND,
                "No active session found for the given session ID",
            ),
            SessionCheck::Active => text_error(
                StatusCode::BAD_REQUEST,
                "No pending sampling request found for the given request ID",
            ),
        }
    }

    /// Upstream `handleToolCall` for the single registered tool.
    async fn handle_tool_call(
        &self,
        state: &AppState,
        path_device_key: Option<&str>,
        probe: &MessageProbe,
        id: &Value,
    ) -> JsonRpcOut {
        let name = probe.tool_name.as_deref().unwrap_or("");
        if name != "notify" {
            return JsonRpcOut::error(
                id,
                INVALID_PARAMS,
                &format!("tool '{name}' not found: tool not found"),
            );
        }
        let result = notify_tool_result(state, path_device_key, probe.arguments.clone()).await;
        JsonRpcOut::result(id, result)
    }

    /// The `notify` tool descriptor, exactly as mcp-go serializes upstream's
    /// `getCommonToolOpts()` (Go map keys marshal in sorted order).
    fn tool_json(&self) -> Value {
        // Sorted ASCII order, like Go's map marshaling: badge, body, call,
        // copy, device_key, group, icon, image, isArchive, level, markdown,
        // sound, subtitle, title, ttl, url, volume.
        let mut properties = Map::new();
        properties.insert(
            "badge".into(),
            json!({"type": "number", "description": "Badge number"}),
        );
        properties.insert("body".into(), string_prop("Notification content"));
        properties.insert(
            "call".into(),
            string_prop("Set to '1' to repeat the notification ringtone"),
        );
        properties.insert("copy".into(), string_prop("Text to copy on copy action"));
        if self.device_key_in_schema {
            properties.insert("device_key".into(), string_prop("Device Key"));
        }
        properties.insert("group".into(), string_prop("Notification group"));
        properties.insert("icon".into(), string_prop("Notification icon URL"));
        properties.insert("image".into(), string_prop("Notification image URL"));
        properties.insert(
            "isArchive".into(),
            string_prop("Set to '1' to save the notification or any other value to skip saving"),
        );
        properties.insert(
            "level".into(),
            json!({
                "type": "string",
                "description": "Notification level",
                "enum": ["critical", "active", "timeSensitive", "passive"],
            }),
        );
        properties.insert(
            "markdown".into(),
            string_prop("Basic Markdown notification content. Overrides body."),
        );
        properties.insert("sound".into(), string_prop("Notification sound"));
        properties.insert("subtitle".into(), string_prop("Notification subtitle"));
        properties.insert("title".into(), string_prop("Notification title"));
        properties.insert(
            "ttl".into(),
            json!({
                "type": "number",
                "description": "Time to live in seconds for archived messages; expired items are automatically deleted",
            }),
        );
        properties.insert("url".into(), string_prop("Click action URL"));
        properties.insert(
            "volume".into(),
            json!({
                "type": "number",
                "description": "Alert volume for important notification",
                "default": 5,
                "minimum": 0,
                "maximum": 10,
            }),
        );

        let required = if self.device_key_in_schema {
            vec!["device_key"]
        } else {
            Vec::new()
        };
        json!({
            "name": "notify",
            "description": "Send a notification to a device via Bark",
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": false,
                "openWorldHint": true,
            },
        })
    }
}

/// Upstream `notifyHandler`: resolve `device_key` (args first, path
/// overwrites), require it, push through the shared core, and map the
/// outcome onto the upstream tool result texts.
async fn notify_tool_result(
    state: &AppState,
    path_device_key: Option<&str>,
    arguments: Option<Value>,
) -> Value {
    // `request.Params.Arguments.(map[string]any)` — anything but an object
    // (including absent/null arguments) is the invalid-format error.
    let Some(Value::Object(mut args)) = arguments else {
        return tool_error_result("Invalid arguments format");
    };

    let mut device_key = match args.get("device_key") {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };
    if let Some(path_key) = path_device_key {
        // The context value (URL path) overwrites the argument.
        device_key = path_key.to_string();
    }
    if device_key.is_empty() {
        return tool_error_result("device_key is required");
    }
    args.insert("device_key".into(), Value::String(device_key));

    match push_core(state, args).await {
        Ok(()) => json!({
            "content": [{"type": "text", "text": "Notification sent successfully"}],
        }),
        Err((code, message)) => tool_error_result(&format!(
            "Failed to send notification: {message} (code {code})"
        )),
    }
}

/// Upstream `mcp.NewToolResultError`: a text content result with
/// `isError: true`.
fn tool_error_result(message: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": message}],
        "isError": true,
    })
}

fn string_prop(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

enum SessionCheck {
    Active,
    Terminated,
    Unknown,
}

#[derive(Clone)]
struct SessionTable {
    idle_ttl: Duration,
    shared: Arc<Mutex<TableState>>,
    sweeper_started: Arc<AtomicBool>,
}

struct TableState {
    /// session id → last activity (monotonic clock).
    active: HashMap<String, Instant>,
    /// ids terminated via DELETE; answering requests on them is
    /// `Session terminated` (mcp-go's stateful manager semantics).
    terminated: HashSet<String>,
}

impl SessionTable {
    fn new(idle_ttl: Duration) -> Self {
        Self {
            idle_ttl,
            shared: Arc::new(Mutex::new(TableState {
                active: HashMap::new(),
                terminated: HashSet::new(),
            })),
            sweeper_started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mint a fresh session id and register it (upstream's initialize path).
    fn mint(&self) -> String {
        let id = format!("{SESSION_ID_PREFIX}{}", uuid_v4());
        self.shared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .active
            .insert(id.clone(), Instant::now());
        self.start_sweeper_once();
        id
    }

    /// Validate a presented session id and refresh its idle timer.
    fn validate_and_touch(&self, id: &str) -> SessionCheck {
        let mut state = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if state.terminated.contains(id) {
            return SessionCheck::Terminated;
        }
        match state.active.get(id) {
            Some(&last) if last.elapsed() <= self.idle_ttl => {
                state.active.insert(id.to_string(), Instant::now());
                SessionCheck::Active
            }
            Some(_) => {
                state.active.remove(id);
                SessionCheck::Unknown
            }
            None => SessionCheck::Unknown,
        }
    }

    /// Validate without refreshing (the sampling-response path never touches).
    fn validate_without_touch(&self, id: &str) -> SessionCheck {
        let mut state = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if state.terminated.contains(id) {
            return SessionCheck::Terminated;
        }
        match state.active.get(id) {
            Some(&last) if last.elapsed() <= self.idle_ttl => SessionCheck::Active,
            Some(_) => {
                state.active.remove(id);
                SessionCheck::Unknown
            }
            None => SessionCheck::Unknown,
        }
    }

    /// DELETE: move an active session to the terminated set (unknown ids are
    /// a no-op, like upstream's manager, and still answer 200).
    fn terminate(&self, id: &str) {
        let mut state = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if state.active.remove(id).is_some() {
            state.terminated.insert(id.to_string());
        }
    }

    /// Launch the idle sweeper once (interval `max(ttl/2, 1s)`, like
    /// mcp-go's `startSessionSweeper`).
    fn start_sweeper_once(&self) {
        if self.sweeper_started.swap(true, Ordering::Relaxed) {
            return;
        }
        let shared = Arc::clone(&self.shared);
        let ttl = self.idle_ttl;
        tokio::spawn(async move {
            let interval = (ttl / 2).max(Duration::from_secs(1));
            loop {
                tokio::time::sleep(interval).await;
                let mut state = shared.lock().unwrap_or_else(|p| p.into_inner());
                state.active.retain(|_, last| last.elapsed() <= ttl);
            }
        });
    }
}

/// mcp-go's session id format check: `mcp-session-` + a canonical UUID.
fn is_session_id(id: &str) -> bool {
    id.strip_prefix(SESSION_ID_PREFIX)
        .map(is_canonical_uuid)
        .unwrap_or(false)
}

/// Canonical `8-4-4-4-12` hex UUID form — what `uuid.Parse` accepts for the
/// canonical spelling our clients mint.
fn is_canonical_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// A random v4 UUID from the OS CSPRNG (version/variant bits set).
fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    crate::random::fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// One probed JSON-RPC message (upstream's 4-field struct plus the fields
/// the dispatch needs).
#[derive(Debug, Default)]
struct MessageProbe {
    /// `jsonrpc` when it is a string (Go parses it into a `string` field).
    jsonrpc: Option<String>,
    /// Set when `jsonrpc` had a JSON type Go's string field would reject.
    jsonrpc_was_wrong_type: bool,
    /// `method` (absent/null → empty; non-string → probe failure).
    method: String,
    /// `id` (absent/null → None; everything else kept verbatim).
    id: Option<Value>,
    /// `result`/`error` presence (null folds into None; emptiness then
    /// decides between the 202 and the sampling-rejection paths).
    result: Option<Value>,
    error: Option<Value>,
    /// Nested fields of the dispatch: `params.protocolVersion`, `params.name`,
    /// `params.arguments`.
    protocol_version: Option<String>,
    tool_name: Option<String>,
    arguments: Option<Value>,
}

/// Parse the probe: the body must be a JSON object, `method` must be a
/// string when present (`json.Unmarshal` into Go's `MCPMethod` string kind).
fn parse_probe(bytes: &[u8]) -> Result<MessageProbe, ()> {
    let value = match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => v,
        Err(_) => return Err(()),
    };
    let Value::Object(map) = value else {
        return Err(());
    };

    let mut probe = MessageProbe::default();
    let mut method: Option<String> = None;
    let mut params: Option<Map<String, Value>> = None;
    for (key, value) in map {
        match key.as_str() {
            "jsonrpc" => match value {
                Value::String(s) => probe.jsonrpc = Some(s),
                Value::Null => {}
                _ => probe.jsonrpc_was_wrong_type = true,
            },
            "method" => match value {
                Value::String(s) => method = Some(s),
                Value::Null => {}
                _ => return Err(()),
            },
            "id" => match value {
                Value::Null => {}
                other => probe.id = Some(other),
            },
            "result" => match value {
                Value::Null => {}
                other => probe.result = Some(other),
            },
            "error" => match value {
                Value::Null => {}
                other => probe.error = Some(other),
            },
            "params" => {
                if let Value::Object(p) = value {
                    params = Some(p);
                }
            }
            _ => {}
        }
    }
    probe.method = method.unwrap_or_default();

    if let Some(params) = params {
        probe.protocol_version = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .map(str::to_string);
        probe.tool_name = params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string);
        probe.arguments = params.get("arguments").cloned();
        // `arguments: null` behaves like absent (Go: nil interface).
        if probe.arguments == Some(Value::Null) {
            probe.arguments = None;
        }
    }
    Ok(probe)
}

/// mcp-go `NegotiateLegacyVersion`: echo a known legacy version, assume
/// `2025-03-26` when absent, otherwise fall back to the latest legacy
/// version (`2025-11-25`).
fn negotiate_protocol_version(client_version: Option<&str>) -> &'static str {
    let requested = client_version.unwrap_or("");
    if requested.is_empty() {
        // Spec fallback: assume 2025-03-26 when the client identifies nothing.
        return "2025-03-26";
    }
    LEGACY_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|v| *v == requested)
        .unwrap_or("2025-11-25")
}

/// `mime.ParseMediaType` reduced to the decision that matters: the token
/// before the first `;`, trimmed, must be `application/json` (Go lowercases
/// and validates the token; parameters are fine).
fn media_type_is_json(content_type: &str) -> bool {
    let token = content_type.split(';').next().unwrap_or("").trim();
    !token.is_empty()
        && token.bytes().all(|b| b.is_ascii_graphic())
        && token.eq_ignore_ascii_case("application/json")
}

/// mcp-go `isJSONEmpty`: null, empty object/array (and absence) are empty;
/// strings — even `""` — are not.
fn json_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(map) => map.is_empty(),
        Value::Array(items) => items.is_empty(),
        _ => false,
    }
}

/// The `Mcp-Session-Id` request header, if present.
fn session_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(&MCP_SESSION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// mcp-go `writeHTTPError`: plain text + trailing newline.
fn text_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        format!("{message}\n"),
    )
        .into_response()
}

/// A JSON-RPC response envelope in mcp-go's marshaling shape
/// (`{"jsonrpc","id","result"}` / `{"jsonrpc","id","error"}`).
enum JsonRpcOut {
    Result(Value, Value),
    Error(Value, i64, String),
}

impl JsonRpcOut {
    fn result(id: &Value, result: Value) -> Self {
        Self::Result(id.clone(), result)
    }

    fn error(id: &Value, code: i64, message: &str) -> Self {
        Self::Error(id.clone(), code, message.to_string())
    }
}

impl IntoResponse for JsonRpcOut {
    fn into_response(self) -> Response {
        let (id, body) = match self {
            JsonRpcOut::Result(id, result) => (id, json!({"result": result})),
            JsonRpcOut::Error(id, code, message) => {
                (id, json!({"error": {"code": code, "message": message}}))
            }
        };
        jsonrpc_response(StatusCode::OK, id, body)
    }
}

/// HTTP-level JSON-RPC error (upstream `writeJSONRPCError`): an explicit
/// status with the JSON-RPC error body.
fn jsonrpc_error_response(status: StatusCode, id: &Value, code: i64, message: &str) -> Response {
    jsonrpc_response(
        status,
        id.clone(),
        json!({"error": {"code": code, "message": message}}),
    )
}

/// Render `{"jsonrpc":"2.0","id":...,...}` with Go's `json.Encoder` trailing
/// newline.
fn jsonrpc_response(status: StatusCode, id: Value, envelope: Value) -> Response {
    let mut map = match envelope {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    map.shift_insert(0, "id".into(), id);
    map.shift_insert(0, "jsonrpc".into(), json!("2.0"));
    let mut body = serde_json::to_string(&Value::Object(map)).expect("serializable");
    body.push('\n');
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}
