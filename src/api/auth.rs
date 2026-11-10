//! Basic Auth, byte-compatible with upstream `route_auth.go` and fiber's
//! `middleware/basicauth` (verified against the live Go server v2.4.0).
//!
//! Mirrored behaviors:
//! - Auth is enabled when either `--user` or `--password` is set (the other
//!   defaults to empty); both empty disables it entirely.
//! - Coverage follows fiber's `Use("/+")` on the url-prefix group: `+` is a
//!   *required* greedy parameter, so the detection path must be
//!   `prefix + "/"` plus at least one character. The bare root (`/`, or the
//!   url-prefix root itself) is therefore NOT covered and answers without
//!   credentials, and paths outside the prefix are not challenged either.
//! - Exemptions (`/ping`, `/register`, `/healthz`) are byte prefix matches on
//!   the RAW request path (percent-encoded, case-sensitive) joined with the
//!   url prefix. They run in the unauthorized handler, so even requests
//!   carrying wrong credentials proceed on exempt paths.
//! - Failed auth returns HTTP 418 with the plain-text body `I'm a teapot` and
//!   no `WWW-Authenticate` challenge (upstream overrides fiber's default
//!   unauthorized handler).
//! - Credentials parse like fiber's basicauth: case-insensitive `Basic `
//!   scheme prefix, standard base64 decode of the remainder, split at the
//!   first `:` (missing colon → unauthorized), then user/password comparison.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Upstream `Unauthorized` failure body.
pub const TEAPOT_BODY: &str = "I'm a teapot";

/// Upstream `authFreeRouters`.
const AUTH_FREE_ROUTES: &[&str] = &["/ping", "/register", "/healthz"];

/// Compared case-insensitively, like fiber's `utils.EqualFold(auth[:6], "basic ")`.
const BASIC_PREFIX: &[u8] = b"basic ";

/// Precomputed basic auth state; `None` when auth is disabled.
#[derive(Clone, Debug)]
pub struct BasicAuth {
    user: String,
    password: String,
    /// Byte prefixes that pass without credentials (raw request path).
    exempt_prefixes: Vec<String>,
    /// `prefix + "/"`: the middleware coverage boundary on the detection path.
    coverage_prefix: String,
}

impl BasicAuth {
    /// Upstream `routerAuth`: `None` when both credentials are empty.
    pub fn from_config(url_prefix: &str, user: &str, password: &str) -> Option<Self> {
        if user.is_empty() && password.is_empty() {
            return None;
        }
        let prefix = super::normalized_prefix(url_prefix);
        Some(Self {
            user: user.to_string(),
            password: password.to_string(),
            exempt_prefixes: AUTH_FREE_ROUTES
                .iter()
                .map(|route| format!("{prefix}{route}"))
                .collect(),
            coverage_prefix: format!("{prefix}/"),
        })
    }

    /// Fiber `Use("/+")` coverage: the `+` parameter is required and greedy,
    /// so the detection path must start with `prefix + "/"` and carry at
    /// least one more character.
    pub fn covers(&self, detection_path: &str) -> bool {
        detection_path.starts_with(&self.coverage_prefix)
            && detection_path.len() > self.coverage_prefix.len()
    }

    /// Upstream exemption check: `strings.HasPrefix(c.Path(),
    /// path.Join(urlPrefix, route))` — byte prefix on the raw path.
    pub fn is_exempt(&self, raw_path: &str) -> bool {
        self.exempt_prefixes
            .iter()
            .any(|prefix| raw_path.starts_with(prefix))
    }

    /// fiber basicauth credential check against the single configured user.
    pub fn authorized(&self, headers: &http::HeaderMap) -> bool {
        let Some(value) = headers.get(header::AUTHORIZATION) else {
            return false;
        };
        let Ok(auth) = value.to_str() else {
            return false;
        };
        let auth = auth.as_bytes();
        // `len(auth) <= 6 || !EqualFold(auth[:6], "basic ")` → unauthorized.
        if auth.len() <= BASIC_PREFIX.len()
            || !auth[..BASIC_PREFIX.len()].eq_ignore_ascii_case(BASIC_PREFIX)
        {
            return false;
        }
        // `base64.StdEncoding.DecodeString(auth[6:])` (canonical padding).
        let Ok(decoded) = STANDARD.decode(&auth[BASIC_PREFIX.len()..]) else {
            return false;
        };
        let Ok(creds) = std::str::from_utf8(&decoded) else {
            return false;
        };
        // Split at the first ':'; no colon → unauthorized.
        let Some((user, password)) = creds.split_once(':') else {
            return false;
        };
        user == self.user && constant_time_eq(password, &self.password)
    }
}

/// Length-checked constant-time password comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Upstream failure response: `c.Status(418).SendString("I'm a teapot")` —
/// plain text, no `WWW-Authenticate` challenge. The `Server: Bark` header is
/// added by [`super::AppService`].
pub fn teapot_response() -> Response {
    (
        StatusCode::IM_A_TEAPOT,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        TEAPOT_BODY,
    )
        .into_response()
}
