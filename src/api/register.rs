//! Device registration routes, byte-compatible with upstream
//! `route_register.go`:
//! - `POST /register`            — body bind (JSON / form / XML), create or
//!   refresh the Device Record
//! - `GET /register/{device_key}` — existence check
//! - `GET /register`             — legacy compat: query bind with the
//!   `key`/`devicetoken` aliases (body ignored)
//!
//! Binding semantics mirror fiber's `BodyParser`/`QueryParser` as probed
//! against the live Go server: content-type dispatch with vendor-specific
//! `+json`/`+xml` normalization, case-insensitive field matching (Go's
//! encoding/json fallback and gorilla/schema's EqualFold), last value wins
//! for duplicates, unknown fields ignored, JSON `null` binding as an empty
//! string, and non-string JSON scalars being bind failures.
//!
//! One documented deviation: fiber also binds `multipart/form-data` POST
//! bodies, which upstream bark clients do not use for registration (the app
//! posts JSON; scripts use query or form). This implementation answers
//! multipart with fiber's "request bind failed2: Unprocessable Entity"
//! instead of binding it.

use axum::extract::{Path, RawQuery, Request, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{CommonResp, envelope_response, error_envelope};
use crate::server::AppState;
use crate::store::{DEVICE_TYPE_IOS, DEVICE_TYPE_WATCHOS};

/// Upstream `DeviceInfo` (route_register.go): canonical fields plus the
/// `key`/`devicetoken` aliases for old requests.
#[derive(Default)]
struct DeviceInfo {
    device_key: String,
    device_token: String,
    device_type: String,
    old_device_key: String,
    old_device_token: String,
}

/// The five bind field names in upstream tag order. Exact match is preferred
/// over a case-insensitive match (Go encoding/json rule for JSON bodies).
const BIND_FIELDS: [&str; 5] = [
    "device_key",
    "device_token",
    "device_type",
    "key",
    "devicetoken",
];

impl DeviceInfo {
    fn set(&mut self, field: &str, value: String) {
        match field {
            "device_key" => self.device_key = value,
            "device_token" => self.device_token = value,
            "device_type" => self.device_type = value,
            "key" => self.old_device_key = value,
            "devicetoken" => self.old_device_token = value,
            _ => unreachable!("field set comes from BIND_FIELDS"),
        }
    }
}

/// Map a request-provided key onto a bind field: exact match first, then a
/// case-insensitive fallback (JSON), or fold-only matching (form/query —
/// gorilla/schema `EqualFold`).
fn field_for_key(key: &str, exact_first: bool) -> Option<&'static str> {
    if exact_first && let Some(f) = BIND_FIELDS.iter().find(|f| **f == key) {
        return Some(f);
    }
    BIND_FIELDS
        .iter()
        .find(|f| f.eq_ignore_ascii_case(key))
        .copied()
}

/// `POST /register` — bind the body per content type, then register.
pub async fn register_post(State(state): State<AppState>, req: Request) -> Response {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(e) => return bind_failed(format!("failed to read body: {e}")),
    };

    let info = match content_type_family(&content_type) {
        ContentFamily::Json => match bind_json(&body) {
            Ok(info) => info,
            Err(detail) => return bind_failed(detail),
        },
        ContentFamily::Form => bind_pairs(&decode_form_pairs(&String::from_utf8_lossy(&body))),
        ContentFamily::Xml => match bind_xml(&body) {
            Ok(info) => info,
            Err(detail) => return bind_failed(detail),
        },
        // Includes multipart/form-data (see module docs for the deviation
        // note) and anything unrecognized — fiber's ErrUnprocessableEntity.
        ContentFamily::Unprocessable => {
            return bind_failed("Unprocessable Entity".to_string());
        }
    };

    do_register(state, info).await
}

/// `GET /register` — legacy compat: query bind only; the body is ignored.
pub async fn register_compat_get(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Response {
    let query = query.unwrap_or_default();
    let info = bind_pairs(&decode_form_pairs(&query));
    do_register(state, info).await
}

/// `GET /register/{device_key}` — existence check (upstream `doRegisterCheck`).
pub async fn register_check(
    State(state): State<AppState>,
    Path(device_key): Path<String>,
) -> Response {
    if device_key.is_empty() {
        // Unreachable through the router (an empty param never matches and a
        // trailing slash falls back to the compat route), kept for upstream
        // fidelity.
        return error_envelope(StatusCode::BAD_REQUEST, "device key is empty");
    }

    match state.store.device_record_by_key(&device_key) {
        Ok(Some(record)) => {
            if record.token.is_empty() {
                // Upstream bbolt: a record whose token is blank is invalid.
                error_envelope(StatusCode::BAD_REQUEST, "device token invalid")
            } else {
                envelope_response(StatusCode::OK, &CommonResp::success())
            }
        }
        Ok(None) => error_envelope(
            StatusCode::BAD_REQUEST,
            format!("failed to get [{device_key}] device token from database"),
        ),
        Err(e) => error_envelope(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// Shared registration flow (upstream `doRegister`): alias resolution,
/// validation, save, and the response carrying both key spellings.
async fn do_register(state: AppState, mut info: DeviceInfo) -> Response {
    if info.device_key.is_empty() && !info.old_device_key.is_empty() {
        info.device_key = std::mem::take(&mut info.old_device_key);
    }

    if info.device_token.is_empty() {
        if info.old_device_token.is_empty() {
            return error_envelope(StatusCode::BAD_REQUEST, "device token is empty");
        }
        info.device_token = std::mem::take(&mut info.old_device_token);
    }

    // DeviceToken length is variable, but should not be too long.
    if info.device_token.len() > 160 {
        return error_envelope(StatusCode::BAD_REQUEST, "device token is invalid");
    }

    // The device type selects the APNs topic when pushing; default to ios
    // for compatibility. The error quotes the value as provided.
    let original_type = info.device_type.clone();
    let device_type = match normalized_device_type(&info.device_type) {
        Ok(t) => t,
        Err(()) => {
            return error_envelope(
                StatusCode::BAD_REQUEST,
                format!("invalid device type: {original_type}"),
            );
        }
    };

    // An empty or unknown key is a new registration: the store mints a new
    // Device Key (upstream bbolt semantics).
    let key = match state.store.save_device_token_by_key(
        &info.device_key,
        &info.device_token,
        device_type,
    ) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!("device registration failed: {e}");
            return error_envelope(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("device registration failed: {e}"),
            );
        }
    };

    envelope_response(
        StatusCode::OK,
        &CommonResp::success().with_data(json!({
            // compatible with old resp
            "key": key,
            "device_key": key,
            "device_token": info.device_token,
            "device_type": device_type,
        })),
    )
}

/// Lowercase the device type, defaulting to `ios` when empty; anything
/// besides the two supported types is rejected.
fn normalized_device_type(device_type: &str) -> Result<&'static str, ()> {
    let lowered = device_type.to_lowercase();
    match lowered.as_str() {
        "" => Ok(DEVICE_TYPE_IOS),
        DEVICE_TYPE_IOS => Ok(DEVICE_TYPE_IOS),
        DEVICE_TYPE_WATCHOS => Ok(DEVICE_TYPE_WATCHOS),
        _ => Err(()),
    }
}

fn bind_failed(detail: String) -> Response {
    error_envelope(
        StatusCode::BAD_REQUEST,
        format!("request bind failed2: {detail}"),
    )
}

/// Generous read cap (fasthttp's default request body limit) for the manual
/// body read; register bodies are tiny.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The body-bind family for a raw Content-Type value, mirroring fiber's
/// `BodyParser` dispatch: lowercase, vendor-specific `+json`/`+xml`
/// normalization, parameter cut at `;`, then `json` suffix or exact match.
fn content_type_family(raw: &str) -> ContentFamily {
    let mut ctype = raw.to_ascii_lowercase();
    // utils.ParseVendorSpecificContentType: "application/vnd.x+json" →
    // "application/json" (same for xml) when the suffix sits before ';'.
    if let Some(plus) = ctype.find('+') {
        let parsable = match ctype.find(';') {
            Some(semi) if semi > plus => &ctype[plus + 1..semi],
            Some(_) => "", // plus index at/after ';' — left untouched
            None => &ctype[plus + 1..],
        };
        match parsable {
            "json" => ctype = "application/json".to_string(),
            "xml" => ctype = "application/xml".to_string(),
            _ => {}
        }
    }
    let ctype = match ctype.split_once(';') {
        Some((base, _params)) => base,
        None => ctype.as_str(),
    };

    if ctype.ends_with("json") {
        ContentFamily::Json
    } else if ctype == "application/x-www-form-urlencoded" {
        ContentFamily::Form
    } else if ctype == "application/xml" || ctype == "text/xml" {
        ContentFamily::Xml
    } else {
        ContentFamily::Unprocessable
    }
}

enum ContentFamily {
    Json,
    Form,
    Xml,
    Unprocessable,
}

/// JSON body bind. Walks the parsed object so field matching and duplicate
/// keys behave like Go's encoding/json: exact tag match preferred per key,
/// case-insensitive fallback, later entries overwriting earlier ones, unknown
/// fields ignored, `null` as an empty string, non-string scalars a failure.
fn bind_json(body: &[u8]) -> Result<DeviceInfo, String> {
    let value: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let obj = value
        .as_object()
        .ok_or_else(|| format!("cannot unmarshal {} into device info", json_kind(&value)))?;
    let mut info = DeviceInfo::default();
    for (key, value) in obj {
        let Some(field) = field_for_key(key, true) else {
            continue; // unknown fields are ignored
        };
        let bound = match value {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => {
                return Err(format!(
                    "cannot unmarshal {} into string field {field}",
                    json_kind(other)
                ));
            }
        };
        info.set(field, bound);
    }
    Ok(info)
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Form body / query string bind: `&`-separated, `=`-split pairs with
/// percent-decoding (`+` as space). Keys match case-insensitively (gorilla/
/// schema EqualFold) and the last duplicate wins. Unknown keys are ignored.
fn bind_pairs(pairs: &[(String, String)]) -> DeviceInfo {
    let mut info = DeviceInfo::default();
    for (key, value) in pairs {
        if let Some(field) = field_for_key(key, false) {
            info.set(field, value.clone());
        }
    }
    info
}

/// Decode an `application/x-www-form-urlencoded` string into pairs.
fn decode_form_pairs(input: &str) -> Vec<(String, String)> {
    input
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (decode_component(key), decode_component(value)),
            None => (decode_component(pair), String::new()),
        })
        .collect()
}

/// Percent-decode with `+` as space (fasthttp form/query semantics); invalid
/// escape sequences pass through verbatim.
fn decode_component(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hex = bytes.get(i + 1..i + 3).and_then(|h| {
                    std::str::from_utf8(h)
                        .ok()
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                });
                match hex {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// XML body bind (upstream `xml.Unmarshal` with the same struct tags):
/// exact element names, unknown elements ignored, errors wrapped like
/// upstream's "failed to unmarshal: %w".
fn bind_xml(body: &[u8]) -> Result<DeviceInfo, String> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct DeviceInfoXml {
        device_key: Option<String>,
        device_token: Option<String>,
        device_type: Option<String>,
        key: Option<String>,
        devicetoken: Option<String>,
    }

    let text = std::str::from_utf8(body).map_err(|_| "invalid utf-8".to_string())?;
    let xml: DeviceInfoXml =
        quick_xml::de::from_str(text).map_err(|e| format!("failed to unmarshal: {e}"))?;
    Ok(DeviceInfo {
        device_key: xml.device_key.unwrap_or_default(),
        device_token: xml.device_token.unwrap_or_default(),
        device_type: xml.device_type.unwrap_or_default(),
        old_device_key: xml.key.unwrap_or_default(),
        old_device_token: xml.devicetoken.unwrap_or_default(),
    })
}
