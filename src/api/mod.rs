//! HTTP API: router assembly, the universal response envelope, the `Server:
//! Bark` header, and fiber-compatible 404/405 error envelopes.
//!
//! Route matching mirrors upstream fiber v2 semantics (verified against the
//! live Go server): case-insensitive and trailing-slash-tolerant by default,
//! with `--case-sensitive` / `--strict-routing` restoring strict behavior.
//!
//! The normalization runs in [`AppService`], which wraps the whole `Router`:
//! `Router::layer` middleware would run *after* routing (see axum's
//! "Rewriting request URI in middleware" docs) and be too late.

pub mod misc;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::Router;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{MethodRouter, get};
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

pub fn normalized_prefix(url_prefix: &str) -> String {
    let trimmed = url_prefix.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        String::new()
    } else {
        trimmed.to_string()
    }
}

/// Fiber-compatible path normalization: lowercase the path unless
/// `--case-sensitive`, and trim all trailing slashes unless `--strict-routing`
/// (fiber: `utils.TrimRightBytes(detectionPath, '/')`).
fn detection_path_for(path: &str, case_sensitive: bool, strict_routing: bool) -> String {
    let mut detection_path = path.to_string();
    if !case_sensitive {
        detection_path = detection_path.to_lowercase();
    }
    if !strict_routing {
        while detection_path.len() > 1 && detection_path.ends_with('/') {
            detection_path.pop();
        }
    }
    detection_path
}

/// The application service: the route [`Router`] wrapped with fiber-compatible
/// request normalization (before routing) and the `Server: Bark` response
/// header (on every response, like fiber's `ServerHeader` config).
///
/// Generic over the request body type so it can be served both by
/// `axum::serve` (axum `Body`) and `axum_server` (hyper `Incoming`).
#[derive(Clone)]
pub struct AppService<S> {
    inner: S,
    case_sensitive: bool,
    strict_routing: bool,
}

impl<S> AppService<S> {
    pub fn new(inner: S, case_sensitive: bool, strict_routing: bool) -> Self {
        Self {
            inner,
            case_sensitive,
            strict_routing,
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
        if detection_path != path {
            let path_and_query = match req.uri().query() {
                Some(q) => format!("{detection_path}?{q}"),
                None => detection_path.clone(),
            };
            if let Ok(uri) = Uri::builder().path_and_query(path_and_query).build() {
                *req.uri_mut() = uri;
            }
        }
        AppServiceFuture {
            inner: self.inner.call(req),
        }
    }
}

pin_project! {
    pub struct AppServiceFuture<F> {
        #[pin]
        inner: F,
    }
}

impl<F> Future for AppServiceFuture<F>
where
    F: Future<Output = Result<Response, std::convert::Infallible>> + Send,
{
    type Output = Result<Response, std::convert::Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut res = std::task::ready!(this.inner.poll(cx))?;
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
    )
}
