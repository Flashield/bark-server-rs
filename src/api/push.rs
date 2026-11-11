//! Push core, mirroring upstream `route_push.go`'s V2 route (JSON body on
//! `POST /push`):
//!
//! - content-type dispatch: `application/json` (after fiber's
//!   vendor-specific normalization) is V2; everything else belongs to the V1
//!   form/query/multipart collection that arrives with the compat routes
//!   (ticket 04) and currently answers the bind-failure envelope;
//! - parameter collection: JSON body → params map (`json.Unmarshal` into
//!   `map[string]interface {}` semantics: object required, `null` empty,
//!   last duplicate wins), then query args override (medium priority — keys
//!   lowercased, values become strings), then path params (highest priority;
//!   none on `/push` — the path-style compat routes are ticket 04);
//! - `device_keys` extraction: string split on `,` (empty string yields one
//!   empty key, like `strings.Split`), array → `fmt.Sprint`-ed elements,
//!   other types → 400 `invalid type for device_keys`; always removed from
//!   the params;
//! - push core (upstream `push()`): defaults (empty body, sound `1107`),
//!   the string-param switch (`id` dual-written as collapse id and custom
//!   key, `sound` gets `.caf` unless suffixed, unknown keys lowercased into
//!   Ext Params), map values merge into Ext Params, other JSON values pass
//!   through with their original key case; empty `device_key` → 400; empty
//!   alert → `Empty Message` body (APNs silently discards empty
//!   notifications, which breaks encrypted pushes);
//! - device lookup: unknown keys and blanked tokens fail exactly like
//!   upstream's `db.DeviceTokenByKey` ("failed to get [key] ..." /
//!   "device token invalid");
//! - delivery via the configured APNs client; APNs 410 or 400
//!   BadDeviceToken blank the Device Token (upstream saves an empty token,
//!   ignoring errors); APNs statuses and reasons surface in the envelope —
//!   per this ticket's contract upstream's blanket
//!   `500 "push failed: <reason>"` mapping is deviated from deliberately
//!   (transport failures still answer 500 with that message).

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use serde_json::{Map, Value};

use crate::api::{CommonResp, envelope_response, error_envelope};
use crate::apns::{self, PushMessage};
use crate::server::AppState;

/// `POST /push` — V2 push with a JSON body.
pub async fn push_post(State(state): State<AppState>, req: Request) -> Response {
    // Upstream routeDoPush: the content type decides the API version.
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let raw_query = req.uri().query().map(str::to_string);
    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return error_envelope(
                StatusCode::BAD_REQUEST,
                format!("request bind failed: failed to read body: {e}"),
            );
        }
    };

    if !is_json_content_type(&content_type) {
        // The V1 collection (form/multipart/plain POST bodies, plus the
        // path-style compat routes) arrives with ticket 04; non-JSON pushes
        // fail simply for now, in fiber's bind-failure message family.
        return error_envelope(
            StatusCode::BAD_REQUEST,
            "request bind failed: Unprocessable Entity",
        );
    }

    let mut params = match bind_json_params(&body) {
        Ok(params) => params,
        Err(detail) => {
            return error_envelope(
                StatusCode::BAD_REQUEST,
                format!("request bind failed: {detail}"),
            );
        }
    };

    // Query args override the body (medium priority): keys lowercased, the
    // value becomes a string — exactly fasthttp's visitor over the URI args.
    if let Some(query) = raw_query.as_deref() {
        for (key, value) in super::register::decode_form_pairs(query) {
            params.insert(key.to_lowercase(), Value::String(value));
        }
    }

    // Path params (highest priority) don't exist on /push; the compat routes
    // carrying them are ticket 04.

    let device_keys = match extract_device_keys(&mut params) {
        Ok(keys) => keys,
        Err((status, message)) => return error_envelope(status, message),
    };
    if !device_keys.is_empty() {
        // Batch push (per-item results, fan-out) arrives with ticket 04; the
        // single-push path below is this ticket's scope.
        return error_envelope(StatusCode::BAD_REQUEST, "batch push is not implemented yet");
    }

    match push_core(&state, params).await {
        Ok(()) => envelope_response(StatusCode::OK, &CommonResp::success()),
        Err((code, message)) => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            error_envelope(status, message)
        }
    }
}

/// Upstream `push(params)`: collect a [`PushMessage`], resolve the Device,
/// deliver, and map the outcome onto `(status, message)`. Shared by the HTTP
/// push routes and the MCP `notify` tool (crate-visible: `src/mcp.rs` routes
/// through the exact same core).
pub(crate) async fn push_core(
    state: &AppState,
    params: Map<String, Value>,
) -> Result<(), (u16, String)> {
    // Default value: empty body, default sound "1107".
    let mut msg = PushMessage {
        id: String::new(),
        device_token: String::new(),
        device_type: String::new(),
        device_key: String::new(),
        subtitle: String::new(),
        title: String::new(),
        body: String::new(),
        sound: "1107".to_string(),
        ext_params: Map::new(),
    };

    for (key, value) in params {
        match value {
            Value::String(s) => match key.to_lowercase().as_str() {
                "id" => {
                    // Dual-written: the APNs collapse id and a custom key.
                    msg.id = s.clone();
                    msg.ext_params.insert("id".into(), Value::String(s));
                }
                "device_key" => msg.device_key = s,
                "subtitle" => msg.subtitle = s,
                "title" => msg.title = s,
                "body" => msg.body = s,
                // Compatible with old parameters: append ".caf" unless the
                // value is already suffixed.
                "sound" => {
                    msg.sound = if s.ends_with(".caf") {
                        s
                    } else {
                        format!("{s}.caf")
                    };
                }
                _ => {
                    msg.ext_params.insert(key.to_lowercase(), Value::String(s));
                }
            },
            // Map values merge into Ext Params (keys kept as-is; the payload
            // build lowercases them).
            Value::Object(map) => {
                for (k, v) in map {
                    msg.ext_params.insert(k, v);
                }
            }
            // Other JSON values keep their original key case.
            other => {
                msg.ext_params.insert(key, other);
            }
        }
    }

    if msg.device_key.is_empty() {
        return Err((400, "device key is empty".to_string()));
    }

    // For encrypted push notifications a Body is required, otherwise APNs
    // will silently discard the notification.
    if msg.title.is_empty() && msg.subtitle.is_empty() && msg.body.is_empty() {
        msg.body = "Empty Message".to_string();
    }

    // Upstream db.DeviceTokenByKey: unknown keys fail with the quoted key,
    // blanked (invalid) tokens with "device token invalid" — both wrapped
    // into "failed to get device token: %v" here.
    let record = match state.store.device_record_by_key(&msg.device_key) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return Err((
                400,
                format!(
                    "failed to get device token: failed to get [{}] device token from database",
                    msg.device_key
                ),
            ));
        }
        Err(e) => return Err((400, format!("failed to get device token: {e}"))),
    };

    msg.device_token = record.token.clone();
    msg.device_type = record.device_type.clone();

    // Ticket 07 (ADR-0002/0006): every push to a resolved Device persists to
    // the per-device message store and fans out on the event bus BEFORE any
    // delivery — APNs below and the SSE streams (subscribed on the bus) both
    // hang off this same pipeline. A store failure answers 500.
    if let Err(e) = state.events.publish(&msg).await {
        return Err((500, format!("message store failed: {e}")));
    }

    // A Stream Device has no Device Token: the realtime stream is its only
    // delivery path (ADR-0006), so the push succeeds without APNs. An
    // upstream device type with a blanked token keeps upstream's error —
    // the stream mirror and store entry above still happened.
    if record.token.is_empty() {
        if record.device_type == crate::store::DEVICE_TYPE_STREAM {
            return Ok(());
        }
        return Err((
            400,
            "failed to get device token: device token invalid".to_string(),
        ));
    }

    match state.apns.push(&msg).await {
        apns::ApnsOutcome::Accepted => Ok(()),
        apns::ApnsOutcome::Transport(detail) => Err((500, format!("push failed: {detail}"))),
        apns::ApnsOutcome::Rejected { status, reason } => {
            // Invalid token: blank it so the registry self-heals (upstream
            // ignores the save error with `_, _ =`).
            if status == 410 || (status == 400 && reason.contains("BadDeviceToken")) {
                let _ =
                    state
                        .store
                        .save_device_token_by_key(&msg.device_key, "", &record.device_type);
            }
            // The APNs status and reason surface in the envelope.
            Err((status, reason))
        }
    }
}

/// Upstream `routeDoPush` dispatch: lowercase the content type, apply fiber's
/// `ParseVendorSpecificContentType` (`application/vnd.x+json` →
/// `application/json`), then the V2 route when it starts with
/// `application/json`.
fn is_json_content_type(raw: &str) -> bool {
    let ctype = raw.to_ascii_lowercase();
    let prefix_match = ctype.starts_with("application/json");
    match ctype.find('+') {
        None => prefix_match,
        Some(plus) => {
            let mut parsable = &ctype[plus + 1..];
            if let Some(semi) = parsable.find(';') {
                parsable = &parsable[..semi];
            }
            if parsable == "json" {
                // Vendor-specific type normalized to application/json.
                true
            } else {
                prefix_match
            }
        }
    }
}

/// JSON body bind into the params map, with Go `json.Unmarshal` into
/// `map[string]interface {}` semantics: an object parses (duplicate keys:
/// last wins), `null` parses as an empty map, anything else — including an
/// empty body ("unexpected end of JSON input") — is a bind failure.
fn bind_json_params(body: &[u8]) -> Result<Map<String, Value>, String> {
    if body.is_empty() {
        return Err("unexpected end of JSON input".to_string());
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(Value::Null) => Ok(Map::new()),
        Ok(other) => Err(format!(
            "json: cannot unmarshal {} into Go value of type map[string]interface {{}}",
            go_json_kind(&other)
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// Go's JSON type name for the unmarshal-error message.
fn go_json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Upstream's `device_keys` handling (routeDoPushV2): a string splits on `,`
/// (`""` → one empty key), an array maps each element through `fmt.Sprint`,
/// anything else → the `(status, message)` of
/// 400 `invalid type for device_keys`. The param is removed from the map
/// whenever present.
fn extract_device_keys(
    params: &mut Map<String, Value>,
) -> Result<Vec<String>, (StatusCode, &'static str)> {
    let Some(value) = params.remove("device_keys") else {
        return Ok(Vec::new());
    };
    match value {
        Value::String(s) => Ok(s.split(',').map(str::to_string).collect()),
        Value::Array(items) => Ok(items.iter().map(apns::go_stringify).collect()),
        _ => Err((StatusCode::BAD_REQUEST, "invalid type for device_keys")),
    }
}

/// Generous read cap (fasthttp's default request body limit), matching the
/// register route's manual body read.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
