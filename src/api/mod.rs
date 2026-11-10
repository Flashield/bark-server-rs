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
//! so later MCP/SSE routes inherit it automatically.
//!
//! The normalization runs in [`AppService`], which wraps the whole `Router`:
//! `Router::layer` middleware would run *after* routing (see axum's
//! "Rewriting request URI in middleware" docs) and be too late.

mod auth;
pub mod misc;
pub mod register;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::Router;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{MethodRouter, get, post};
use pin_project_lite::pin_project;
use serde::Serialize;

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
const STATIC_SEGMENTS: &[&str] = &["ping", "healthz", "info", "register"];

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
}

impl<S> AppService<S> {
    pub fn new(
        inner: S,
        case_sensitive: bool,
        strict_routing: bool,
        auth: Option<auth::BasicAuth>,
    ) -> Self {
        Self {
            inner,
            case_sensitive,
            strict_routing,
            auth,
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
            get_route(register::register_check),
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
    )
}
