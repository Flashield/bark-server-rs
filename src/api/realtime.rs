//! The realtime credential plane (ADR-0006): Stream Token minting, listing
//! and revocation under `/realtime/v1`, versioned per the spec's contract
//! decision. This module is half of the wire contract — `docs/protocol.md`
//! (ticket 10) transcribes the shapes below verbatim. Registration only:
//! the SSE endpoint consuming these tokens is ticket 07.
//!
//! # Credential presentation
//!
//! Every `/realtime/v1` request presents the Device Key in the
//! **`X-Device-Key` header**, byte-exact against the `{device_key}` path
//! parameter (case-sensitive: a Device Key is a 22-char identifier, not a
//! name). The Device Key *is* the credential — it already authorizes pushing
//! to the Device (GLOSSARY.md), so its holder may mint read credentials for
//! that Device (ADR-0006 bridge model: reading is delegated, pushing stays
//! with the key). One presentation rule for all three methods; JSON bodies
//! carry only the client label. Absent header → 401; present but not equal
//! → 401. Operator Basic Auth (see [`super::auth`]) still wraps this plane:
//! `/realtime/v1` is not in upstream's auth-free list, so with Basic Auth
//! configured its 418 fires before the Device Key check.
//!
//! # Stream Token format
//!
//! `st_` + 43 unpadded base64url characters (RFC 4648 §5) over 32 random
//! bytes from the OS CSPRNG — 256 bits of entropy, opaque, URL-safe. The
//! constant `st_` prefix exists for human recognition in configs and logs;
//! it carries no meaning to the server. Each mint generates a fresh token;
//! the full token appears in a response **exactly once** (the mint response)
//! and is never returned again.
//!
//! Alongside the secret, each token gets a non-secret public identifier
//! `token_id` (16 lowercase hex chars = 8 random bytes) — the handle the
//! list and revoke endpoints use, so revocation never requires re-presenting
//! the secret. List/revoke responses instead carry a `token_hint` (first 12
//! characters of the full token + `...`) purely so a user can match a stored
//! token to a list entry.
//!
//! # Endpoints
//!
//! ## `POST /realtime/v1/devices/{device_key}/streams` — mint
//!
//! Authenticates as above. Body: a JSON object (parsed regardless of
//! Content-Type), unknown fields ignored:
//!
//! ```json
//! {"client_label": "macbook-reminder"}
//! ```
//!
//! `client_label` is optional: absent or `null` binds to the empty string;
//! it must otherwise be a string of at most 256 bytes. It is free-form text
//! naming the Realtime Client (user story 17: one revocable token per
//! client) and is persisted verbatim.
//!
//! Streams attach to any Device — `stream`, `ios` or `watchos` (ADR-0006
//! bridge model); `stream` merely exists so users without the Bark App can
//! create an addressable Device in the first place.
//!
//! Success `200` with the upstream envelope, the full token exactly once:
//!
//! ```json
//! {"code": 200, "message": "success", "timestamp": 1760000000,
//!  "data": {"token": "st_A1b2C3...", "token_id": "0123456789abcdef",
//!           "device_key": "…22-char key…", "client_label": "macbook-reminder",
//!           "created_at": 1760000000, "revoked": false}}
//! ```
//!
//! ## `GET /realtime/v1/devices/{device_key}/streams` — list
//!
//! Success `200`, `data` is an array in creation order of summaries — never
//! the full token:
//!
//! ```json
//! {"code": 200, "message": "success", "timestamp": 1760000000,
//!  "data": [{"token_id": "0123456789abcdef", "device_key": "…",
//!            "client_label": "macbook-reminder", "created_at": 1760000000,
//!            "revoked": false, "token_hint": "st_A1b2C3d4E5f..."}]}
//! ```
//!
//! ## `DELETE /realtime/v1/devices/{device_key}/streams/{token_id}` — revoke
//!
//! Success `200`, `data` is the summary with `revoked: true`. Revocation is
//! persistent and takes effect for the SSE auth path (ticket 07): the store
//! flips the `revoked` flag atomically and every subsequent lookup — by id
//! or by presented secret — reports it. Revoking an already-revoked token is
//! refused with `409` ("this token is already dead") rather than silently
//! succeeding, so a scripted revoke loop notices when the target is gone.
//!
//! # Error table (upstream envelope, `code` mirrors the HTTP status)
//!
//! | Status | Message | When |
//! |--------|---------|------|
//! | 400 | `invalid JSON body` | body is not parseable JSON |
//! | 400 | `request body must be a JSON object` | JSON array/string/… |
//! | 400 | `client_label must be a string` | non-string label |
//! | 400 | `client_label too long` | label exceeds 256 bytes |
//! | 401 | `device key required` | `X-Device-Key` header absent |
//! | 401 | `device key mismatch` | header value ≠ path device_key |
//! | 404 | `device not found` | path device_key unknown |
//! | 404 | `stream token not found` | unknown token_id, or the token
//!         belongs to another Device (ids are Device-scoped; no leak) |
//! | 409 | `stream token already revoked` | revoking twice |
//! | 500 | `stream token storage failed: {e}` | store failure |
//!
//! Check order is auth-first: header presence, then header equality, then
//! Device existence, then the operation — a request failing earlier never
//! reveals later-stage facts.

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::api::{CommonResp, MAX_BODY_BYTES, envelope_response, error_envelope};
use crate::server::AppState;
use crate::store::{RevokeOutcome, StoreError, StreamTokenRecord};

/// A rejection before the envelope exists: status plus the error-table
/// message. Handlers render it via [`error_envelope`]. (Small `Err` by
/// design — the helpers below must not lug a full `Response` around.)
type Rejection = (StatusCode, String);

/// The credential header; see the module docs for the presentation contract.
pub const DEVICE_KEY_HEADER: &str = "X-Device-Key";

/// Random bytes behind a Stream Token's secret: 256 bits of entropy.
const TOKEN_SECRET_BYTES: usize = 32;
/// Constant recognition prefix; carries no meaning to the server.
const TOKEN_PREFIX: &str = "st_";
/// Random bytes behind a `token_id` (rendered lowercase hex = 16 chars).
const TOKEN_ID_BYTES: usize = 8;
/// Client label cap in bytes (UTF-8; a 256-byte cap is generous for a name).
const MAX_CLIENT_LABEL_BYTES: usize = 256;
/// How many leading characters of the full token the hint reveals.
const TOKEN_HINT_CHARS: usize = 12;
/// Mint retries on the (statistically negligible) id/secret collision.
const MINT_ATTEMPTS: usize = 3;

/// `POST /realtime/v1/devices/{device_key}/streams` — mint a Stream Token.
pub async fn streams_create(
    State(state): State<AppState>,
    Path(device_key): Path<String>,
    headers: HeaderMap,
    req: Request,
) -> Response {
    if let Err((status, message)) = authorize(&state, &device_key, &headers) {
        return error_envelope(status, message);
    }

    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return error_envelope(StatusCode::BAD_REQUEST, format!("failed to read body: {e}"));
        }
    };
    let client_label = match parse_client_label(&body) {
        Ok(label) => label,
        Err((status, message)) => return error_envelope(status, message),
    };

    for _ in 0..MINT_ATTEMPTS {
        let record = StreamTokenRecord {
            token_id: new_token_id(),
            token: new_stream_token(),
            device_key: device_key.clone(),
            client_label: client_label.clone(),
            created_at: crate::api::now_unix(),
            revoked: false,
        };
        match state.store.insert_stream_token(&record) {
            Ok(()) => {
                let mut data = summary_json(&record);
                // The full token leaves the server exactly once.
                data["token"] = json!(record.token);
                return envelope_response(StatusCode::OK, &CommonResp::success().with_data(data));
            }
            Err(e) if StoreError::is_unique_violation(&e) => continue, // fresh randomness, retry
            Err(e) => {
                tracing::error!("stream token mint failed: {e}");
                return storage_failed(e);
            }
        }
    }
    error_envelope(
        StatusCode::INTERNAL_SERVER_ERROR,
        "stream token generation failed",
    )
}

/// `GET /realtime/v1/devices/{device_key}/streams` — list the Device's
/// Stream Token summaries (creation order, hints only).
pub async fn streams_list(
    State(state): State<AppState>,
    Path(device_key): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err((status, message)) = authorize(&state, &device_key, &headers) {
        return error_envelope(status, message);
    }
    match state.store.stream_tokens_by_device(&device_key) {
        Ok(records) => envelope_response(
            StatusCode::OK,
            &CommonResp::success()
                .with_data(Value::Array(records.iter().map(summary_json).collect())),
        ),
        Err(e) => storage_failed(e),
    }
}

/// `DELETE /realtime/v1/devices/{device_key}/streams/{token_id}` — revoke.
pub async fn stream_revoke(
    State(state): State<AppState>,
    Path((device_key, token_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err((status, message)) = authorize(&state, &device_key, &headers) {
        return error_envelope(status, message);
    }
    match state.store.revoke_stream_token(&device_key, &token_id) {
        Ok(RevokeOutcome::Revoked) => {
            match state.store.stream_token_by_id(&device_key, &token_id) {
                Ok(Some(record)) => envelope_response(
                    StatusCode::OK,
                    &CommonResp::success().with_data(summary_json(&record)),
                ),
                Ok(None) => error_envelope(StatusCode::NOT_FOUND, "stream token not found"),
                Err(e) => storage_failed(e),
            }
        }
        Ok(RevokeOutcome::NotFound) => {
            error_envelope(StatusCode::NOT_FOUND, "stream token not found")
        }
        Ok(RevokeOutcome::AlreadyRevoked) => {
            error_envelope(StatusCode::CONFLICT, "stream token already revoked")
        }
        Err(e) => storage_failed(e),
    }
}

/// Auth-first shared check: header presence → header equality → Device
/// existence. See the module docs' error table.
fn authorize(state: &AppState, device_key: &str, headers: &HeaderMap) -> Result<(), Rejection> {
    let presented = headers
        .get(DEVICE_KEY_HEADER)
        .and_then(|value| value.to_str().ok());
    let Some(presented) = presented else {
        return Err((StatusCode::UNAUTHORIZED, "device key required".to_string()));
    };
    if presented != device_key {
        return Err((StatusCode::UNAUTHORIZED, "device key mismatch".to_string()));
    }
    match state.store.device_record_by_key(device_key) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err((StatusCode::NOT_FOUND, "device not found".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// Bind the mint body's `client_label`: JSON object required, label optional
/// (absent/null → empty), string-typed, ≤256 bytes. Unknown fields ignored.
fn parse_client_label(body: &[u8]) -> Result<String, Rejection> {
    let value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return Err((StatusCode::BAD_REQUEST, "invalid JSON body".to_string())),
    };
    let Some(obj) = value.as_object() else {
        return Err((
            StatusCode::BAD_REQUEST,
            "request body must be a JSON object".to_string(),
        ));
    };
    let label = match obj.get("client_label") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "client_label must be a string".to_string(),
            ));
        }
    };
    if label.len() > MAX_CLIENT_LABEL_BYTES {
        return Err((StatusCode::BAD_REQUEST, "client_label too long".to_string()));
    }
    Ok(label)
}

/// A fresh Stream Token secret: `st_` + base64url(32 random bytes).
fn new_stream_token() -> String {
    let mut bytes = [0u8; TOKEN_SECRET_BYTES];
    crate::random::fill(&mut bytes);
    format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// A fresh `token_id`: 16 lowercase hex chars over 8 random bytes.
fn new_token_id() -> String {
    let mut bytes = [0u8; TOKEN_ID_BYTES];
    crate::random::fill(&mut bytes);
    let mut hex = String::with_capacity(TOKEN_ID_BYTES * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// The list/revoke summary shape: everything about the token except the
/// secret, plus the identification hint.
fn summary_json(record: &StreamTokenRecord) -> Value {
    json!({
        "token_id": record.token_id,
        "device_key": record.device_key,
        "client_label": record.client_label,
        "created_at": record.created_at,
        "revoked": record.revoked,
        "token_hint": token_hint(&record.token),
    })
}

/// First [`TOKEN_HINT_CHARS`] characters of the full token + "..." — enough
/// to tell stored tokens apart, nowhere near enough to recover the secret.
fn token_hint(token: &str) -> String {
    let cut = token
        .char_indices()
        .nth(TOKEN_HINT_CHARS)
        .map(|(i, _)| i)
        .unwrap_or(token.len());
    format!("{}...", &token[..cut])
}

fn storage_failed(e: StoreError) -> Response {
    error_envelope(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("stream token storage failed: {e}"),
    )
}
