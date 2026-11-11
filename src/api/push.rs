//! Push core, mirroring upstream `route_push.go`'s full push surface:
//!
//! - route dispatch (`routeDoPush`): the content type decides the API
//!   version. After fiber's `ParseVendorSpecificContentType` normalization
//!   (`application/vnd.x+json[;...]` → `application/json...`), a type
//!   starting with `application/json` (case-insensitively) is V2; anything
//!   else — form, multipart, text/plain, none — is the V1 collection.
//! - V2 (`routeDoPushV2`): JSON body bind into the params map
//!   (`json.Unmarshal` into `map[string]interface {}` semantics: object
//!   required, duplicate keys last-wins). A `null` body unmarshals into a
//!   *nil* Go map, and assigning into it later panics — the query-arg and
//!   path-param merges answer upstream's 500 "assignment to entry in nil
//!   map" while a bare `null` keeps reaching the empty-key error. Query
//!   args override next (keys lowercased, values stringified), then path
//!   params (highest priority; none on `/push`, where `GET /push` resolves
//!   as the compat route with device_key="push").
//! - V1 (`routeDoPushV1`): parameter collection in upstream order — query
//!   args (keys lowercased) → POST body form args (parsed whenever the raw
//!   content type starts with `application/x-www-form-urlencoded`, any
//!   method; keys lowercased) → multipart form values (only for
//!   `multipart/form-data; boundary=...`; keys NOT lowercased, first value
//!   wins, file parts skipped, parse failures silently skipped) → path
//!   params (highest). `device_keys` is *not* expanded in V1 — it rides
//!   along as an Ext Param exactly like upstream.
//! - compat routes (`push_compat`, weight 1): `GET`/`POST` on
//!   `/{device_key}`, `/{device_key}/{body}`, `/{device_key}/{title}/{body}`
//!   and `/{device_key}/{title}/{subtitle}/{body}`, plus `GET /push` (the
//!   canonical `/push` is POST-only). Segments reach the handlers raw —
//!   fiber slices params from the original path (no percent-decoding, case
//!   preserved); `subtitle`/`title`/`body` are then `url.QueryUnescape`d
//!   (failures → 400 `url path parse failed: invalid URL escape "..."`)
//!   while `device_key` stays raw. More than four segments never match
//!   (fiber's enveloped 404).
//! - `device_keys` extraction (V2): string split on `,` (`""` yields one
//!   empty key, like `strings.Split`), array → `fmt.Sprint`-ed elements,
//!   other types → 400 `invalid type for device_keys`; exact-key lookup,
//!   always removed from the params.
//! - batch push: over `--max-batch-push-count` (default -1 = unlimited) →
//!   400 with the limit in the message; otherwise the params are copied per
//!   key (`device_key` overridden) and pushed concurrently, producing
//!   per-item results in input order — `{code, device_key}` plus `message`
//!   only on failure — inside the success envelope's `data`. An empty
//!   batch falls back to a single push.
//! - push core (upstream `push()`): defaults (empty body, sound `1107`),
//!   the string-param switch (`id` dual-written as collapse id and custom
//!   key, `sound` gets `.caf` unless suffixed, unknown keys lowercased into
//!   Ext Params), map values merge into Ext Params, other JSON values pass
//!   through with their original key case; empty `device_key` → 400; empty
//!   alert → `Empty Message` body (APNs silently discards empty
//!   notifications, which breaks encrypted pushes).
//! - device lookup: unknown keys and blanked tokens fail exactly like
//!   upstream's `db.DeviceTokenByKey` ("failed to get [key] ..." /
//!   "device token invalid");
//! - delivery via the configured APNs client; APNs 410 or 400
//!   BadDeviceToken blank the Device Token (upstream saves an empty token,
//!   ignoring errors); APNs statuses and reasons surface in the envelope —
//!   per ticket 03's contract upstream's blanket
//!   `500 "push failed: <reason>"` mapping is deviated from deliberately
//!   (transport failures still answer 500 with that message).

use axum::extract::{Extension, Request, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use serde_json::{Map, Value, json};

use crate::api::{
    CommonResp, CompatSegments, MAX_BODY_BYTES, PercentDecodePolicy, envelope_response,
    error_envelope, json_kind, percent_decode,
};
use crate::apns::{self, PushMessage};
use crate::server::AppState;

/// `POST /push` — V2 push with a JSON body.
pub async fn push_post(State(state): State<AppState>, req: Request) -> Response {
    route_do_push(state, req, Vec::new()).await
}

/// The compat route shapes, in segment order (upstream registers
/// `/:device_key`, `/:device_key/:body`, `/:device_key/:title/:body`,
/// `/:device_key/:title/:subtitle/:body`).
const SHAPE_1: [&str; 1] = ["device_key"];
const SHAPE_2: [&str; 2] = ["device_key", "body"];
const SHAPE_3: [&str; 3] = ["device_key", "title", "body"];
const SHAPE_4: [&str; 4] = ["device_key", "title", "subtitle", "body"];

/// Map the raw request segments onto the compat route's param names. `GET
/// /push` resolves through [`compat_1`]: its only segment ("push", or the
/// original casing as typed) becomes the `device_key` path param, exactly
/// like matching `GET /:device_key` upstream.
fn compat_path_params(
    segments: Option<Extension<CompatSegments>>,
    shape: &'static [&'static str],
) -> Vec<(&'static str, String)> {
    let Some(Extension(CompatSegments(segments))) = segments else {
        return Vec::new();
    };
    shape
        .iter()
        .enumerate()
        .filter_map(|(i, name)| segments.get(i).map(|value| (*name, value.clone())))
        .collect()
}

macro_rules! compat_handler {
    ($name:ident, $shape:expr) => {
        pub async fn $name(
            State(state): State<AppState>,
            segments: Option<Extension<CompatSegments>>,
            req: Request,
        ) -> Response {
            route_do_push(state, req, compat_path_params(segments, &$shape)).await
        }
    };
}

compat_handler!(compat_1, SHAPE_1);
compat_handler!(compat_2, SHAPE_2);
compat_handler!(compat_3, SHAPE_3);
compat_handler!(compat_4, SHAPE_4);

/// Upstream `routeDoPush`: the content type decides V2 (JSON) or V1.
async fn route_do_push(
    state: AppState,
    req: Request,
    raw_path_params: Vec<(&'static str, String)>,
) -> Response {
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

    if is_json_content_type(&content_type) {
        route_do_push_v2(&state, raw_query, &body, raw_path_params).await
    } else {
        route_do_push_v1(&state, &content_type, raw_query, &body, raw_path_params).await
    }
}

/// Upstream `routeDoPushV2`: JSON body bind, then query args, then path
/// params, then single push or batch fan-out.
async fn route_do_push_v2(
    state: &AppState,
    raw_query: Option<String>,
    body: &[u8],
    raw_path_params: Vec<(&'static str, String)>,
) -> Response {
    let bound = match bind_json_params(body) {
        Ok(bound) => bound,
        Err(detail) => {
            return error_envelope(
                StatusCode::BAD_REQUEST,
                format!("request bind failed: {detail}"),
            );
        }
    };
    let mut params = match &bound {
        ParamsBind::Map(map) => map.clone(),
        ParamsBind::Nil => Map::new(),
    };

    // Query args override the body (medium priority): keys lowercased, the
    // value becomes a string — exactly fasthttp's visitor over the URI args.
    // A `null` JSON body unmarshals into a nil Go map; assigning a query arg
    // into it panics upstream (recovered into a 500 envelope).
    let query_pairs = raw_query
        .map(|query| super::register::decode_form_pairs(&query))
        .unwrap_or_default();
    if matches!(bound, ParamsBind::Nil) && !query_pairs.is_empty() {
        return nil_map_panic();
    }
    for (key, value) in query_pairs {
        params.insert(key.to_lowercase(), Value::String(value));
    }

    // Path params (highest priority) — the compat routes carry them; a nil
    // map panics on the merge the same way.
    let path_params = match extract_url_path_params(&raw_path_params) {
        Ok(path_params) => path_params,
        Err(detail) => {
            return error_envelope(
                StatusCode::BAD_REQUEST,
                format!("url path parse failed: {detail}"),
            );
        }
    };
    if matches!(bound, ParamsBind::Nil) && !path_params.is_empty() {
        return nil_map_panic();
    }
    for (key, value) in path_params {
        params.insert(key, value);
    }

    let device_keys = match extract_device_keys(&mut params) {
        Ok(keys) => keys,
        Err((status, message)) => return error_envelope(status, message),
    };
    if device_keys.is_empty() {
        // Single push.
        push_and_respond(state, params).await
    } else {
        batch_push(state, params, device_keys).await
    }
}

/// Upstream `routeDoPushV1`: query args → POST args → multipart form values
/// → path params, then a single push (no `device_keys` expansion here).
async fn route_do_push_v1(
    state: &AppState,
    content_type: &str,
    raw_query: Option<String>,
    body: &[u8],
    raw_path_params: Vec<(&'static str, String)>,
) -> Response {
    let mut params = Map::new();

    // Query args (medium priority): fasthttp's visitor lowercases keys.
    if let Some(query) = raw_query {
        for (key, value) in super::register::decode_form_pairs(&query) {
            params.insert(key.to_lowercase(), Value::String(value));
        }
    }

    // POST args: fasthttp parses the body as form args only when the raw
    // content type starts with `application/x-www-form-urlencoded` (any
    // method — a GET with a form body collects too).
    if content_type.starts_with("application/x-www-form-urlencoded") {
        let body_str = String::from_utf8_lossy(body);
        for (key, value) in super::register::decode_form_pairs(&body_str) {
            params.insert(key.to_lowercase(), Value::String(value));
        }
    }

    // Multipart form values: only with a parseable `multipart/form-data`
    // boundary; keys keep their case, first value wins, and a parse failure
    // skips the whole collection (`err != nil` → `if err == nil` upstream).
    if let Some(boundary) = multipart_boundary(content_type)
        && let Some(values) = multipart_form_values(body, boundary.as_bytes())
    {
        let mut seen_first = Vec::new();
        for (key, value) in values {
            if seen_first.contains(&key) {
                continue; // first value wins, like `val[0]`
            }
            seen_first.push(key.clone());
            params.insert(key, Value::String(value));
        }
    }

    // Path params (highest priority).
    let path_params = match extract_url_path_params(&raw_path_params) {
        Ok(path_params) => path_params,
        Err(detail) => {
            return error_envelope(
                StatusCode::BAD_REQUEST,
                format!("url path parse failed: {detail}"),
            );
        }
    };
    for (key, value) in path_params {
        params.insert(key, value);
    }

    push_and_respond(state, params).await
}

/// The recovered panic envelope for assigning into a nil map (`null` JSON
/// body followed by a query/path merge).
fn nil_map_panic() -> Response {
    error_envelope(
        StatusCode::INTERNAL_SERVER_ERROR,
        "assignment to entry in nil map",
    )
}

/// Single push mapped onto the response envelope.
async fn push_and_respond(state: &AppState, params: Map<String, Value>) -> Response {
    match push_core(state, params).await {
        Ok(()) => envelope_response(StatusCode::OK, &CommonResp::success()),
        Err((code, message)) => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            error_envelope(status, message)
        }
    }
}

/// Upstream's batch branch: cap check, then a concurrent fan-out with
/// per-item results in input order. `device_key` is overridden per item, so
/// a key from the body/query/path never leaks into the other items.
async fn batch_push(
    state: &AppState,
    params: Map<String, Value>,
    device_keys: Vec<String>,
) -> Response {
    let max = state.config.max_batch_push_count;
    if max != -1 && device_keys.len() as i64 > max {
        return error_envelope(
            StatusCode::BAD_REQUEST,
            format!("batch push count exceeds the maximum limit: {max}"),
        );
    }

    let mut handles = Vec::with_capacity(device_keys.len());
    for device_key in device_keys {
        let mut item_params = params.clone();
        item_params.insert("device_key".into(), Value::String(device_key.clone()));
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            let result = push_core(&state, item_params).await;
            let mut item = Map::new();
            item.insert(
                "code".into(),
                json!(match &result {
                    Ok(()) => 200,
                    Err((code, _)) => *code,
                }),
            );
            item.insert("device_key".into(), Value::String(device_key));
            if let Err((_, message)) = &result {
                item.insert("message".into(), Value::String(message.clone()));
            }
            item
        }));
    }

    let mut items = Vec::with_capacity(handles.len());
    for handle in handles {
        // push_core never panics; a task failure would be a bug — answer the
        // item like upstream's recovered panic instead of unwrapping.
        let item = handle
            .await
            .unwrap_or_else(|_| Map::from_iter([("code".into(), json!(500))]));
        items.push(Value::Object(item));
    }

    // Upstream `c.JSON(data(result))`: a success envelope whose data is the
    // per-item array (HTTP 200 even when items failed).
    envelope_response(
        StatusCode::OK,
        &CommonResp::success().with_data(Value::Array(items)),
    )
}

/// Upstream `extractUrlPathParams`: collect the non-empty path params;
/// `device_key` stays raw, `subtitle`/`title`/`body` are QueryUnescaped —
/// subtitle checked before title, title before body (the first bad escape
/// wins).
fn extract_url_path_params(raw: &[(&'static str, String)]) -> Result<Map<String, Value>, String> {
    let mut params = Map::new();
    let get = |name: &str| {
        raw.iter()
            .find(|(param, _)| *param == name)
            .map(|(_, value)| value.clone())
    };
    if let Some(device_key) = get("device_key")
        && !device_key.is_empty()
    {
        params.insert("device_key".into(), Value::String(device_key));
    }
    for name in ["subtitle", "title", "body"] {
        if let Some(value) = get(name)
            && !value.is_empty()
        {
            // Go `url.QueryUnescape` (query-component mode): invalid escapes
            // fail with `invalid URL escape "..."` quoting the remainder
            // truncated to at most 3 bytes (Go's `EscapeError`).
            params.insert(
                name.into(),
                Value::String(percent_decode(
                    &value,
                    PercentDecodePolicy::GoQueryUnescape,
                )?),
            );
        }
    }
    Ok(params)
}

/// fasthttp `MultipartFormBoundary`: the raw content type must start with
/// `multipart/form-data` immediately followed by `;`, then a `boundary=`
/// parameter (case-sensitive, space-skipped, optional quotes) carries the
/// boundary. Any other content type yields no multipart parsing.
fn multipart_boundary(content_type: &str) -> Option<String> {
    let mut rest = content_type.strip_prefix("multipart/form-data")?;
    rest = rest.strip_prefix(';')?;
    loop {
        rest = rest.trim_start_matches(' ');
        if rest.is_empty() {
            return None;
        }
        if let Some(after_name) = rest.strip_prefix("boundary") {
            let value = after_name.strip_prefix('=')?;
            let value = match value.split_once(';') {
                Some((value, _)) => value,
                None => value,
            };
            return Some(
                if value.len() > 1 && value.starts_with('"') && value.ends_with('"') {
                    value[1..value.len() - 1].to_string()
                } else {
                    value.to_string()
                },
            );
        }
        let idx = rest.find(';')?;
        rest = &rest[idx + 1..];
    }
}

/// The form-value pairs of a multipart body (Go `mime/multipart` `ReadForm`'s
/// `form.Value`): preamble discarded, parts delimited by CRLF lines starting
/// with `--{boundary}` (transport padding tolerated), a final `--{boundary}--`
/// ends the body. Parts carry a `Content-Disposition: form-data` header; a
/// part without a `name` is skipped and one with a non-empty `filename` is a
/// file (upstream collects it into `form.File`, never `form.Value`).
/// Structural failure → `None`: upstream's `MultipartForm()` error path
/// silently skips the whole collection.
fn multipart_form_values(body: &[u8], boundary: &[u8]) -> Option<Vec<(String, String)>> {
    let mut delimiter = Vec::with_capacity(boundary.len() + 2);
    delimiter.extend_from_slice(b"--");
    delimiter.extend_from_slice(boundary);

    // The first delimiter must sit at the start of a line (or the very start
    // of the body); everything before it is preamble.
    let mut pos = find_delimiter(body, &delimiter, 0)?;

    let mut pairs = Vec::new();
    loop {
        // After the delimiter: optional transport padding, then a line end
        // (another part) or `--` (final boundary).
        let mut cursor = pos + delimiter.len();
        while cursor < body.len() && (body[cursor] == b' ' || body[cursor] == b'\t') {
            cursor += 1;
        }
        if body[cursor..].starts_with(b"--") {
            return Some(pairs);
        }
        if body[cursor..].starts_with(b"\r\n") {
            cursor += 2;
        } else if body[cursor..].starts_with(b"\n") {
            cursor += 1;
        } else {
            return None; // malformed delimiter line
        }

        // Part headers, up to an empty line. A part whose headers end
        // directly at the next delimiter has an empty value.
        let (header_block, value_start) = find_headers_end(body, cursor)?;
        let (name, filename) = parse_content_disposition(header_block)?;
        let is_file = !filename.is_empty();

        let next = find_delimiter(body, &delimiter, value_start)?;
        // The CRLF (or LF) before the delimiter belongs to the delimiter.
        let mut value_end = next;
        if body[..value_end].ends_with(b"\r\n") {
            value_end -= 2;
        } else if body[..value_end].ends_with(b"\n") {
            value_end -= 1;
        }
        if !name.is_empty() && !is_file {
            // Values are byte strings upstream; invalid UTF-8 is replaced
            // where the params map requires a String.
            pairs.push((
                name,
                String::from_utf8_lossy(&body[value_start..value_end]).into_owned(),
            ));
        }
        pos = next;
    }
}

/// Find the next occurrence of `delimiter` that starts a line (`body[pos..]`).
fn find_delimiter(body: &[u8], delimiter: &[u8], from: usize) -> Option<usize> {
    let mut search = from;
    loop {
        let idx = body[search.min(body.len())..]
            .windows(delimiter.len())
            .position(|window| window == delimiter)
            .map(|idx| idx + search)?;
        // Line start: body start, or right after LF.
        if idx == 0 || body[idx - 1] == b'\n' {
            return Some(idx);
        }
        search = idx + 1;
        if search >= body.len() {
            return None;
        }
    }
}

/// Split the part header block from its value: headers run to the first
/// empty line (CRLFCRLF or LFLF); a delimiter line encountered while
/// scanning headers means the part has no value (headers end at the
/// delimiter). Returns the header block bytes and the value start offset.
fn find_headers_end(body: &[u8], start: usize) -> Option<(&[u8], usize)> {
    let mut cursor = start;
    loop {
        let line_end = body[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|idx| cursor + idx)?;
        let mut line = &body[cursor..line_end];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            return Some((&body[start..line_end], line_end + 1));
        }
        cursor = line_end + 1;
        if cursor >= body.len() {
            return None;
        }
    }
}

/// Parse `Content-Disposition` out of a raw header block: `(name, filename)`.
/// MIME-style params: `token` or quoted `string`, semicolon-separated; header
/// names case-insensitive. `None` when the block is unusable.
fn parse_content_disposition(header_block: &[u8]) -> Option<(String, String)> {
    let mut name = String::new();
    let mut filename = String::new();
    for line in header_block.split(|byte| *byte == b'\n') {
        let line = String::from_utf8_lossy(line);
        let line = line.trim_end_matches('\r');
        let Some((header_name, header_value)) = line.split_once(':') else {
            continue;
        };
        if !header_name
            .trim()
            .eq_ignore_ascii_case("content-disposition")
        {
            continue;
        }
        // Params after the disposition type (`form-data`).
        for param in header_value.split(';').skip(1) {
            let param = param.trim();
            let Some((param_name, param_value)) = param.split_once('=') else {
                continue;
            };
            let mut value = param_value.trim().to_string();
            if value.len() > 1 && value.starts_with('"') && value.ends_with('"') {
                value = value[1..value.len() - 1].to_string();
            }
            if param_name.trim().eq_ignore_ascii_case("name") {
                name = value;
            } else if param_name.trim().eq_ignore_ascii_case("filename") {
                filename = value;
            }
        }
    }
    Some((name, filename))
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
/// `ParseVendorSpecificContentType` (the subtype after the first `+`, up to
/// `;`, replaces everything after the `/` — `application/vnd.x+json; ...` →
/// `application/json`), then the V2 route when it starts with
/// `application/json`.
fn is_json_content_type(raw: &str) -> bool {
    let ctype = raw.to_ascii_lowercase();
    let normalized = match ctype.find('+') {
        None => ctype,
        Some(plus) => match ctype.find(';') {
            // ';' before '+': fiber truncates the type at the ';'.
            Some(semi) if plus > semi => ctype[..semi].to_string(),
            semi => {
                let parsable = match semi {
                    Some(semi) => &ctype[plus + 1..semi],
                    None => &ctype[plus + 1..],
                };
                match ctype.find('/') {
                    Some(slash) => format!("{}{}", &ctype[..slash + 1], parsable),
                    None => ctype,
                }
            }
        },
    };
    normalized.starts_with("application/json")
}

/// The JSON body bind result. A `null` body unmarshals into a nil Go map
/// (`json.Unmarshal(null, &params)` nils the map), which later merges panic
/// on; anything else — including an empty body ("unexpected end of JSON
/// input") — is a bind failure.
enum ParamsBind {
    Map(Map<String, Value>),
    Nil,
}

/// JSON body bind into the params map, with Go `json.Unmarshal` into
/// `map[string]interface {}` semantics: an object parses (duplicate keys:
/// last wins), `null` yields the nil-map bind, anything else is a bind
/// failure.
fn bind_json_params(body: &[u8]) -> Result<ParamsBind, String> {
    if body.is_empty() {
        return Err("unexpected end of JSON input".to_string());
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => Ok(ParamsBind::Map(map)),
        Ok(Value::Null) => Ok(ParamsBind::Nil),
        Ok(other) => Err(format!(
            "json: cannot unmarshal {} into Go value of type map[string]interface {{}}",
            json_kind(&other)
        )),
        Err(e) => Err(e.to_string()),
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
