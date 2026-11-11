//! HTTP API: router assembly, the universal response envelope, the `Server:
//! Bark` header, and fiber-compatible 404/405 error envelopes.
//!
//! Route matching mirrors upstream fiber v2 semantics (verified against the
//! live Go server): case-insensitive and trailing-slash-tolerant by default,
//! with `--case-sensitive` / `--strict-routing` restoring strict behavior.
//! Case-insensitivity applies to the static route segments only — path
//! parameters (Device Keys) reach handlers with their original casing,
//! exactly like fiber, which matches consts against the lowercased detection
//! path but slices params from the original path.
//!
//! Basic Auth (see [`auth`]) also runs in [`AppService`], in front of every
//! route including the fallbacks, exactly like upstream's fiber middleware —
//! so the MCP (`src/mcp.rs`) and SSE routes inherit it automatically.
//!
//! The normalization runs in [`AppService`], which wraps the whole `Router`:
//! `Router::layer` middleware would run *after* routing (see axum's
//! "Rewriting request URI in middleware" docs) and be too late.

mod auth;
pub mod misc;
pub mod push;
pub mod realtime;
pub mod register;
pub mod sse;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::Router;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{MethodRouter, any, delete, get, post};
use pin_project_lite::pin_project;
use serde::Serialize;
use serde_json::Value;

use crate::mcp;
use crate::server::AppState;

/// Upstream `CommonResp` (router.go): `{code, message, data?, timestamp}`.
/// `data` is omitted when unset, exactly like Go's `omitempty`.
#[derive(Debug, Serialize)]
pub struct CommonResp {
    pub code: u16,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    pub timestamp: i64,
}

impl CommonResp {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
            timestamp: now_unix(),
        }
    }

    /// Upstream `success()`.
    pub fn success() -> Self {
        Self::new(200, "success")
    }

    /// Upstream `data(...)` helper: success envelope carrying `data`.
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

/// Generous read cap (fasthttp's default request body limit) for the manual
/// body reads on the register/push/realtime/MCP routes; request bodies are
/// tiny in practice.
pub(crate) const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The JSON type name used in bind-failure messages (Go's encoding/json
/// wording: "cannot unmarshal <kind> into ...").
pub(crate) fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The invalid-escape policy of [`percent_decode`], matching the two upstream
/// call sites.
#[derive(Clone, Copy)]
pub(crate) enum PercentDecodePolicy {
    /// fasthttp form/query semantics (register bodies and query strings):
    /// invalid escape sequences pass through verbatim.
    PassThrough,
    /// Go's `url.QueryUnescape` (compat-route path segments): the first
    /// invalid escape fails the decode.
    GoQueryUnescape,
}

/// Percent-decode with `+` as space, shared by the register form/query bind
/// ([`PercentDecodePolicy::PassThrough`]) and the compat-route
/// subtitle/title/body segments ([`PercentDecodePolicy::GoQueryUnescape`]).
///
/// `%XX` accepts exactly two ASCII hex digits (Go's `unhex`); anything else —
/// a truncated escape, a non-hex byte, a `+`/`-` sign-looking character — is
/// invalid. Decoded bytes that are not valid UTF-8 are replaced (Go marshals
/// invalid UTF-8 as U+FFFD downstream).
pub(crate) fn percent_decode(s: &str, policy: PercentDecodePolicy) -> Result<String, String> {
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
                let hex = bytes.get(i + 1..i + 3).and_then(|pair| {
                    let hi = (pair[0] as char).to_digit(16);
                    let lo = (pair[1] as char).to_digit(16);
                    hi.zip(lo).map(|(hi, lo)| (hi * 16 + lo) as u8)
                });
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => match policy {
                        PercentDecodePolicy::PassThrough => {
                            out.push(b'%');
                            i += 1;
                        }
                        PercentDecodePolicy::GoQueryUnescape => {
                            let rest = &bytes[i..];
                            let end = rest.len().min(3);
                            return Err(format!(
                                "invalid URL escape \"{}\"",
                                String::from_utf8_lossy(&rest[..end])
                            ));
                        }
                    },
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Render an envelope as a JSON response with the given status.
pub fn envelope_response(status: StatusCode, resp: &CommonResp) -> Response {
    (status, Json(resp)).into_response()
}

/// Upstream's `customErrorHandler` wraps every router error in the envelope.
pub fn error_envelope(status: StatusCode, message: impl Into<String>) -> Response {
    let mut res = envelope_response(status, &CommonResp::new(status.as_u16(), message));
    res.headers_mut()
        .insert(header::SERVER, HeaderValue::from_static("Bark"));
    res
}

/// The original request path, captured by [`AppService`] before any
/// case/trailing-slash rewriting, so error envelopes can quote it verbatim
/// like fiber's `pathOriginal`.
#[derive(Clone, Debug)]
pub struct OriginalPath(pub String);

/// The raw path segments of the original request (after the url prefix),
/// captured by [`AppService`] for the compat routes (see [`push`]). Fiber
/// slices route params from the raw path — no percent-decoding, original
/// casing — while matching on the lowercased detection path; axum's `Path`
/// extractor percent-decodes, so the compat handlers read these instead.
/// Trailing-slash remnants (empty final segments) are popped to match
/// fiber's detection-path trailing-slash trim.
#[derive(Clone, Debug)]
pub struct CompatSegments(pub Vec<String>);

/// Go `html.EscapeString` — fiber HTML-escapes the path in 404 messages.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            other => out.push(other),
        }
    }
    out
}

/// Fiber's true 404: `Cannot {METHOD} {pathOriginal}` in the envelope
/// (router.go: `NewError(StatusNotFound, "Cannot " + method + path)`).
async fn not_found(
    method: axum::http::Method,
    original: Option<axum::Extension<OriginalPath>>,
    uri: Uri,
) -> Response {
    let path = original
        .map(|o| o.0.0)
        .unwrap_or_else(|| uri.path().to_string());
    error_envelope(
        StatusCode::NOT_FOUND,
        format!("Cannot {} {}", method, escape_html(&path)),
    )
}

/// Fiber's 405 when the path exists under another method
/// (`ErrMethodNotAllowed`, message "Method Not Allowed").
async fn method_not_allowed() -> Response {
    error_envelope(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

/// `get(...)` with a fiber-compatible 405 fallback for other methods.
fn get_route<H, T>(handler: H) -> MethodRouter<AppState>
where
    H: axum::handler::Handler<T, AppState>,
    T: 'static,
{
    get(handler).fallback(method_not_allowed)
}

/// `post(...)` + `get(...)` on one path (upstream registers both on
/// `/register`), with a fiber-compatible 405 fallback for other methods.
fn post_get_route<H1, T1, H2, T2>(post_handler: H1, get_handler: H2) -> MethodRouter<AppState>
where
    H1: axum::handler::Handler<T1, AppState>,
    H2: axum::handler::Handler<T2, AppState>,
    T1: 'static,
    T2: 'static,
{
    post(post_handler)
        .get(get_handler)
        .fallback(method_not_allowed)
}

/// `delete(...)` with a fiber-compatible 405 fallback for other methods.
fn delete_route<H, T>(handler: H) -> MethodRouter<AppState>
where
    H: axum::handler::Handler<T, AppState>,
    T: 'static,
{
    delete(handler).fallback(method_not_allowed)
}

/// `any(...)` — upstream fiber `router.All`: the MCP endpoints are
/// registered for every HTTP method (the handler dispatches on the method
/// itself, mirroring net/http's ServeHTTP switch).
fn any_route<H, T>(handler: H) -> MethodRouter<AppState>
where
    H: axum::handler::Handler<T, AppState>,
    T: 'static,
{
    any(handler)
}

pub fn normalized_prefix(url_prefix: &str) -> String {
    let trimmed = url_prefix.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        String::new()
    } else {
        trimmed.to_string()
    }
}

/// The static (non-parametric) path segments of all routes. Under fiber's
/// default case-insensitive matching, segments equal to one of these
/// (ignoring ASCII case) canonicalize to their lowercase form; every other
/// segment — path parameters like Device Keys, or unmatched paths — keeps
/// its original case. Device Keys are 22 chars and can never collide with a
/// static name, so this is exact for all reachable requests.
const STATIC_SEGMENTS: &[&str] = &[
    "ping", "healthz", "info", "register", "push",
    // Realtime credential plane (api/realtime.rs) and the SSE stream
    // endpoint (api/sse.rs); like the upstream route names, these match
    // case-insensitively under fiber's default config.
    "realtime", "v1", "devices", "streams", "stream",
    // MCP tool server (src/mcp.rs); upstream registers it with router.All.
    "mcp",
];

/// Fiber-compatible path normalization: trim all trailing slashes unless
/// `--strict-routing` (fiber: `utils.TrimRightBytes(detectionPath, '/')`),
/// then canonicalize static segments to lowercase unless `--case-sensitive`
/// (fiber matches the lowercased detection path but keeps param case).
fn detection_path_for(path: &str, case_sensitive: bool, strict_routing: bool) -> String {
    let mut trimmed = path;
    if !strict_routing {
        while trimmed.len() > 1 && trimmed.ends_with('/') {
            trimmed = &trimmed[..trimmed.len() - 1];
        }
    }
    if case_sensitive {
        return trimmed.to_string();
    }
    // Canonicalize recognized static segments; keep everything else verbatim.
    let mut out = String::with_capacity(trimmed.len());
    for (i, segment) in trimmed.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if STATIC_SEGMENTS
            .iter()
            .any(|s| s.eq_ignore_ascii_case(segment))
        {
            out.push_str(&segment.to_lowercase());
        } else {
            out.push_str(segment);
        }
    }
    out
}

/// The application service: the route [`Router`] wrapped with Basic Auth
/// (before everything), fiber-compatible request normalization (before
/// routing) and the `Server: Bark` response header (on every response, like
/// fiber's `ServerHeader` config).
///
/// Generic over the request body type so it can be served both by
/// `axum::serve` (axum `Body`) and `axum_server` (hyper `Incoming`).
#[derive(Clone)]
pub struct AppService<S> {
    inner: S,
    case_sensitive: bool,
    strict_routing: bool,
    auth: Option<auth::BasicAuth>,
    /// Normalized url prefix, used to strip the prefix from the raw segments
    /// captured for the compat routes.
    prefix: String,
}

impl<S> AppService<S> {
    pub fn new(
        inner: S,
        case_sensitive: bool,
        strict_routing: bool,
        auth: Option<auth::BasicAuth>,
        url_prefix: &str,
    ) -> Self {
        Self {
            inner,
            case_sensitive,
            strict_routing,
            auth,
            prefix: normalized_prefix(url_prefix),
        }
    }
}

impl<S, B> tower::Service<http::Request<B>> for AppService<S>
where
    S: tower::Service<http::Request<B>, Response = Response, Error = std::convert::Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future = AppServiceFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let path = req.uri().path().to_string();
        req.extensions_mut().insert(OriginalPath(path.clone()));

        // Raw segments (after the url prefix) for the compat routes: fiber
        // slices param values from the raw path, keeping both percent-escapes
        // and the original casing.
        let after_prefix = path.strip_prefix(&self.prefix).unwrap_or(&path).to_string();
        let mut segments: Vec<String> = after_prefix
            .split('/')
            .skip(1)
            .map(str::to_string)
            .collect();
        while segments.last().is_some_and(String::is_empty) {
            segments.pop();
        }
        req.extensions_mut().insert(CompatSegments(segments));

        let detection_path = detection_path_for(&path, self.case_sensitive, self.strict_routing);

        // Basic Auth sits in front of everything (before routing and before
        // case/trailing-slash normalization), mirroring upstream's fiber
        // middleware: coverage is decided on the detection path, exemptions
        // on the raw path, and failures answer 418 without reaching any route.
        if let Some(auth) = &self.auth
            && auth.covers(&detection_path)
            && !auth.is_exempt(&path)
            && !auth.authorized(req.headers())
        {
            return AppServiceFuture::Teapot {
                inner: std::future::ready(Ok(auth::teapot_response())),
            };
        }

        if detection_path != path {
            let path_and_query = match req.uri().query() {
                Some(q) => format!("{detection_path}?{q}"),
                None => detection_path.clone(),
            };
            if let Ok(uri) = Uri::builder().path_and_query(path_and_query).build() {
                *req.uri_mut() = uri;
            }
        }
        AppServiceFuture::Inner {
            inner: self.inner.call(req),
        }
    }
}

pin_project! {
    #[project = AppServiceFutureProj]
    pub enum AppServiceFuture<F> {
        Inner {
            #[pin]
            inner: F,
        },
        /// Immediate 418 teapot from the Basic Auth middleware.
        Teapot {
            #[pin]
            inner: std::future::Ready<Result<Response, std::convert::Infallible>>,
        },
    }
}

impl<F> Future for AppServiceFuture<F>
where
    F: Future<Output = Result<Response, std::convert::Infallible>> + Send,
{
    type Output = Result<Response, std::convert::Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut res = match this {
            AppServiceFutureProj::Inner { inner } => std::task::ready!(inner.poll(cx))?,
            AppServiceFutureProj::Teapot { inner } => std::task::ready!(inner.poll(cx))?,
        };
        res.headers_mut()
            .insert(header::SERVER, HeaderValue::from_static("Bark"));
        Poll::Ready(Ok(res))
    }
}

/// Assemble the application: routes (optionally nested under the url prefix)
/// wrapped in [`AppService`].
///
/// Route mount parity with upstream (router.go weight ordering, verified
/// against the Go server): `register_compat` (weight 100) mounts first, the
/// canonical routes (weight 50) next, and the parametric compat push routes
/// (`push_compat`, weight 1) last. Fiber matches in registration order, so
/// the compat mounts only see paths the canonical routes missed; axum's
/// matchit gives static segments precedence over parameters natively, and
/// the method-level fallbacks reproduce fiber's 405-on-existing-path.
pub fn build_app_service(state: &AppState) -> AppService<Router> {
    let inner = Router::new()
        .route("/", get_route(misc::root))
        .route("/ping", get_route(misc::ping))
        .route("/healthz", get_route(misc::healthz))
        .route("/info", get_route(misc::info))
        .route(
            "/register",
            post_get_route(register::register_post, register::register_compat_get),
        )
        .route(
            "/register/{device_key}",
            // Canonical GET check; POST falls through to the compat push
            // (upstream: GET /register/:device_key is registered before the
            // compat routes, but the compat POST /:device_key/:body catches
            // the method the canonical route does not handle).
            get(register::register_check)
                .post(push::compat_2)
                .fallback(method_not_allowed),
        )
        .route("/push", post_get_route(push::push_post, push::compat_1))
        // MCP tool server: generic endpoint (device_key as tool argument) and
        // the path-bound one (device_key injected over the args). All HTTP
        // methods, like upstream fiber's router.All; src/mcp.rs holds the
        // contract.
        .route("/mcp", any_route(mcp::generic))
        .route("/mcp/{device_key}", any_route(mcp::specific))
        // Realtime credential plane: mint (POST) + list (GET) a Device's
        // Stream Tokens, revoke one by id (DELETE). api/realtime.rs holds
        // the contract.
        .route(
            "/realtime/v1/devices/{device_key}/streams",
            post_get_route(realtime::streams_create, realtime::streams_list),
        )
        .route(
            "/realtime/v1/devices/{device_key}/streams/{token_id}",
            delete_route(realtime::stream_revoke),
        )
        // The SSE realtime stream: Stream Token auth, live push mirror
        // (api/sse.rs holds the contract).
        .route("/realtime/v1/stream", get_route(sse::stream_connect))
        // Legacy compat push routes (upstream `push_compat`, weight 1):
        // GET/POST on 1-4 segment paths, mounted after every canonical
        // route. `GET /push` resolves here upstream (the canonical /push is
        // POST-only), which is why the static route above chains compat_1
        // as its GET handler. Static segments (/mcp, /realtime/v1/stream)
        // outrank these parameters natively in matchit.
        .route(
            "/{device_key}",
            get(push::compat_1)
                .post(push::compat_1)
                .fallback(method_not_allowed),
        )
        .route(
            "/{device_key}/{body}",
            get(push::compat_2)
                .post(push::compat_2)
                .fallback(method_not_allowed),
        )
        .route(
            "/{device_key}/{title}/{body}",
            get(push::compat_3)
                .post(push::compat_3)
                .fallback(method_not_allowed),
        )
        .route(
            "/{device_key}/{title}/{subtitle}/{body}",
            get(push::compat_4)
                .post(push::compat_4)
                .fallback(method_not_allowed),
        )
        .fallback(not_found)
        .with_state(state.clone());

    let prefix = normalized_prefix(&state.config.url_prefix);
    let app: Router = if prefix.is_empty() {
        inner
    } else {
        // Fallback set on both levels so unmatched paths under and outside
        // the prefix both get the enveloped 404 regardless of how axum's
        // nest consults fallbacks.
        Router::new().nest(&prefix, inner).fallback(not_found)
    };

    AppService::new(
        app,
        state.config.case_sensitive,
        state.config.strict_routing,
        auth::BasicAuth::from_config(
            &state.config.url_prefix,
            &state.config.basic_auth_user,
            &state.config.basic_auth_password,
        ),
        &state.config.url_prefix,
    )
}
