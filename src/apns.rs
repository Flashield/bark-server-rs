//! APNs delivery: the token-authenticated HTTP/2 provider client and the
//! payload construction, mirroring upstream `apns/apns.go` (sideshow/apns2 +
//! payload builders) byte for byte where it is observable on the wire:
//!
//! - `POST {endpoint}/3/device/{token}` over HTTP/2 (Apple's requirement);
//! - `authorization: bearer <jwt>` — ES256 JWT over the embedded upstream
//!   key (ADR-0004) with `kid` in the header and `iss`/`iat` claims,
//!   regenerated at most every 3000s (apns2's `TokenTimeout`, under Apple's
//!   one-hour acceptance window);
//! - `Content-Type: application/json; charset=utf-8`, `apns-topic` by device
//!   type, `apns-push-type` (`alert`, or `background` for `delete=1`),
//!   `apns-expiration` = now + 24h, `apns-collapse-id` only when the push
//!   carries an `id` — `apns-priority`/`apns-id` are never sent (upstream
//!   leaves both unset);
//! - payload: `mutable-content` always 1, hardcoded category
//!   `myNotificationCategory`, alert dictionary with Go `omitempty`-style
//!   empty-field omission, `group` → `thread-id`, `delete=1` → silent
//!   background push, and every Ext Param as a root-level custom key
//!   (lowercased key, Go `%v`-stringified value; Go marshals the root map
//!   with sorted keys).
//!
//! The delivery client is hand-rolled (reqwest HTTP/2 + jsonwebtoken) per
//! the ticket's blessed fallback: the `apns-h2` crate hard-codes its
//! endpoint as a closed `Endpoint` enum (production/sandbox only), which
//! cannot point at the configured local stub.

use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::config::Config;
use crate::store::DEVICE_TYPE_WATCHOS;

/// Embedded Bark push private key — copied verbatim from upstream
/// `apns/apns_certs.go` (also shipped as `deploy/AuthKey_*.p8`). The key is
/// already public in the MIT-licensed upstream repository; ADR-0004 embeds
/// it for the zero-config, unmodified-official-app behavior.
pub const APNS_PRIVATE_KEY_PEM: &str = concat!(
    "-----BEGIN PRIVATE KEY-----\n",
    "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg4vtC3g5L5HgKGJ2+\n",
    "T1eA0tOivREvEAY2g+juRXJkYL2gCgYIKoZIzj0DAQehRANCAASmOs3JkSyoGEWZ\n",
    "sUGxFs/4pw1rIlSV2IC19M8u3G5kq36upOwyFWj9Gi3Ejc9d3sC7+SHRqXrEAJow\n",
    "8/7tRpV+\n",
    "-----END PRIVATE KEY-----\n",
);

/// Upstream `keyID`.
pub const APNS_KEY_ID: &str = "LH4T9V5U4R";
/// Upstream `teamID`.
pub const APNS_TEAM_ID: &str = "5U8LBRXG3A";
/// Upstream `topic` (iOS Bark app).
pub const APNS_TOPIC: &str = "me.fin.bark";
/// Upstream `watchOSTopic`.
pub const APNS_WATCHOS_TOPIC: &str = "me.fin.bark.watch";

/// Upstream `apns2.HTTPClientTimeout`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Upstream `token.TokenTimeout` (seconds): tokens are refreshed well under
/// Apple's one-hour acceptance window.
const TOKEN_TIMEOUT_SECS: i64 = 3000;

/// One push collected from request parameters (upstream `apns.PushMessage`).
/// Defaults (`body` empty, `sound` "1107") are applied by the push core.
pub struct PushMessage {
    pub id: String,
    pub device_token: String,
    pub device_type: String,
    pub device_key: String,
    pub subtitle: String,
    pub title: String,
    pub body: String,
    pub sound: String,
    pub ext_params: Map<String, Value>,
}

/// Upstream `PushMessage.IsDelete`: Ext Params `delete` equals `"1"` (or the
/// number 1 — Go untyped-constant comparison against the interface).
fn is_delete(ext_params: &Map<String, Value>) -> bool {
    match ext_params.get("delete") {
        Some(Value::String(s)) => s == "1",
        Some(Value::Number(n)) => n.as_f64() == Some(1.0),
        _ => false,
    }
}

/// Build the APNs payload exactly like upstream `apns.Push`. `delete` is the
/// [`is_delete`] verdict, computed once by the caller.
pub fn build_payload(msg: &PushMessage, delete: bool) -> Value {
    let mut aps = Map::new();
    if delete {
        // Silent push notification: content-available + mutable-content,
        // no alert/sound/category/thread-id.
        aps.insert("content-available".into(), json!(1));
        aps.insert("mutable-content".into(), json!(1));
    } else {
        // Regular push notification. The aps struct fields marshal in
        // upstream declaration order (alert, category, mutable-content,
        // sound, thread-id); alert sub-fields in declaration order
        // (title, subtitle, body) with empty strings omitted (omitempty).
        let mut alert = Map::new();
        if !msg.title.is_empty() {
            alert.insert("title".into(), json!(msg.title));
        }
        if !msg.subtitle.is_empty() {
            alert.insert("subtitle".into(), json!(msg.subtitle));
        }
        if !msg.body.is_empty() {
            alert.insert("body".into(), json!(msg.body));
        }
        aps.insert("alert".into(), Value::Object(alert));
        aps.insert("category".into(), json!("myNotificationCategory"));
        aps.insert("mutable-content".into(), json!(1));
        aps.insert("sound".into(), json!(msg.sound));
        // Upstream type-asserts the Ext Param to string here (a non-string
        // `group` panics and fiber answers 500); we simply skip the
        // thread-id for non-string groups — the root custom key is still
        // emitted below.
        if let Some(Value::String(group)) = msg.ext_params.get("group") {
            aps.insert("thread-id".into(), json!(group));
        }
    }

    let mut payload = Map::new();
    payload.insert("aps".into(), Value::Object(aps));
    // Custom keys at root level: change all parameter names to lowercase to
    // prevent inconsistent capitalization, and stringify every value with Go
    // `%v`. Go marshals the payload's content map with sorted keys.
    let mut keys: Vec<&String> = msg.ext_params.keys().collect();
    keys.sort();
    for key in keys {
        let value = go_stringify(&msg.ext_params[key.as_str()]);
        payload.insert(key.to_lowercase(), json!(value));
    }
    Value::Object(payload)
}

/// Go `fmt.Sprintf("%v", v)` for JSON-decoded values — the stringification
/// upstream applies to Ext Param values (and `device_keys` elements).
pub(crate) fn go_stringify(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "<nil>".into(),
        // encoding/json decodes every JSON number to float64; `%v` renders
        // it like `strconv.FormatFloat(f, 'g', -1, 64)`.
        Value::Number(n) => go_format_float(n.as_f64().unwrap_or_default()),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(go_stringify).collect();
            format!("[{}]", parts.join(" "))
        }
        Value::Object(map) => {
            // fmt prints maps with sorted keys: map[a:1 b:2].
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", k, go_stringify(&map[k.as_str()])))
                .collect();
            format!("map[{}]", parts.join(" "))
        }
    }
}

/// Go `strconv.FormatFloat(f, 'g', -1, 64)` — the exact formatter behind
/// `%v` for float64 (which is what `encoding/json` produces for every JSON
/// number): shortest round-trip digits, switching to exponent notation when
/// the decimal exponent is < -4 or >= 6 (verified against the Go oracle:
/// `123456` stays plain, `1234567` becomes `1.234567e+06`), with at least
/// two exponent digits ("1e-05", "1.794353102e+09").
fn go_format_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f.is_sign_negative() { "-Inf" } else { "+Inf" }.into();
    }
    if f == 0.0 {
        // Go renders negative zero as "-0" (verified: FormatFloat of
        // Copysign(0, -1)).
        return if f.is_sign_negative() { "-0" } else { "0" }.into();
    }
    // Rust's `{:e}` for f64 is also the shortest round-trip representation:
    // "d.dddde<exp>" (or "de<exp>").
    let rendered = format!("{:e}", f);
    let (mantissa, exponent) = rendered.split_once('e').expect("LowerExp format");
    let exponent: i32 = exponent.parse().expect("exponent integer");
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    if !(-4..6).contains(&exponent) {
        let sign = if exponent < 0 { '-' } else { '+' };
        let body = format!("{mantissa}e{sign}{:02}", exponent.abs());
        return body;
    }
    // Plain decimal expansion of mantissa * 10^exponent.
    let decimal_at = exponent + 1; // digits left of the decimal point
    let expanded = if decimal_at >= digits.len() as i32 {
        format!(
            "{}{}",
            digits,
            "0".repeat(decimal_at as usize - digits.len())
        )
    } else if decimal_at <= 0 {
        format!("0.{}{}", "0".repeat((-decimal_at) as usize), digits)
    } else {
        let at = decimal_at as usize;
        format!("{}.{}", &digits[..at], &digits[at..])
    };
    if negative {
        format!("-{expanded}")
    } else {
        expanded
    }
}

/// Outcome of one delivery attempt (upstream `apns.Push` returns
/// `(code, error)`; the push core maps this onto the HTTP response).
#[derive(Debug)]
pub enum ApnsOutcome {
    /// APNs answered 200: accepted.
    Accepted,
    /// APNs answered with a non-200 status and its `reason` string.
    Rejected { status: u16, reason: String },
    /// Transport-level failure (connect/TLS/timeout/protocol).
    Transport(String),
}

#[derive(Serialize)]
struct ApnsJwtClaims {
    iss: &'static str,
    iat: i64,
}

struct CachedToken {
    bearer: String,
    issued_at: i64,
}

/// The APNs provider client: HTTP/2 (via TLS ALPN, like Apple requires) with
/// a cached ES256 provider token. Cheap to clone; the reqwest client pools
/// connections, covering upstream's client pool (`--max-apns-client-count`
/// stays an accepted no-op knob).
pub struct ApnsClient {
    http: reqwest::Client,
    endpoint: String,
    encoding_key: EncodingKey,
    token: Mutex<Option<CachedToken>>,
}

impl ApnsClient {
    /// Build from the configuration: endpoint and TLS strictness.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let endpoint = config.apns_endpoint.trim_end_matches('/').to_string();
        let mut builder = reqwest::Client::builder().timeout(REQUEST_TIMEOUT);
        if config.apns_insecure_skip_tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http = builder
            .build()
            .context("failed to build APNs HTTP client")?;
        let encoding_key = EncodingKey::from_ec_pem(APNS_PRIVATE_KEY_PEM.as_bytes())
            .context("embedded APNs auth key is invalid")?;
        Ok(Self {
            http,
            endpoint,
            encoding_key,
            token: Mutex::new(None),
        })
    }

    /// The cached provider token, regenerated when older than
    /// [`TOKEN_TIMEOUT_SECS`] (apns2's `GenerateIfExpired`).
    fn bearer(&self) -> anyhow::Result<String> {
        let mut cache = self.token.lock().unwrap_or_else(|p| p.into_inner());
        let now = crate::api::now_unix();
        if let Some(cached) = cache.as_ref()
            && now < cached.issued_at + TOKEN_TIMEOUT_SECS
        {
            return Ok(cached.bearer.clone());
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(APNS_KEY_ID.to_string());
        let claims = ApnsJwtClaims {
            iss: APNS_TEAM_ID,
            iat: now,
        };
        let bearer = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .context("failed to sign APNs provider token")?;
        *cache = Some(CachedToken {
            bearer: bearer.clone(),
            issued_at: now,
        });
        Ok(bearer)
    }

    /// Deliver one push (upstream `apns.Push`).
    pub async fn push(&self, msg: &PushMessage) -> ApnsOutcome {
        let delete = is_delete(&msg.ext_params);
        let payload = build_payload(msg, delete);
        let topic = if msg.device_type == DEVICE_TYPE_WATCHOS {
            APNS_WATCHOS_TOPIC
        } else {
            APNS_TOPIC
        };
        let push_type = if delete { "background" } else { "alert" };
        // Upstream: time.Now().Add(24 * time.Hour).
        let expiration = crate::api::now_unix() + 24 * 3600;

        let bearer = match self.bearer() {
            Ok(bearer) => bearer,
            Err(e) => return ApnsOutcome::Transport(e.to_string()),
        };
        let mut request = self
            .http
            .post(format!("{}/3/device/{}", self.endpoint, msg.device_token))
            .header("authorization", format!("bearer {bearer}"))
            .header("Content-Type", "application/json; charset=utf-8")
            .header("apns-topic", topic)
            .header("apns-push-type", push_type)
            .header("apns-expiration", expiration.to_string());
        // apns2 only sends apns-collapse-id when non-empty, and never sends
        // apns-priority (0) or apns-id (both unset upstream).
        if !msg.id.is_empty() {
            request = request.header("apns-collapse-id", msg.id.as_str());
        }
        let response = match request.body(payload.to_string()).send().await {
            Ok(response) => response,
            Err(e) => return ApnsOutcome::Transport(e.to_string()),
        };
        let status = response.status().as_u16();
        if status == 200 {
            return ApnsOutcome::Accepted;
        }
        let reason = response
            .json::<Value>()
            .await
            .ok()
            .and_then(|body| {
                body.get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        ApnsOutcome::Rejected { status, reason }
    }
}
