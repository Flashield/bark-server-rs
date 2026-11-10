//! Misc routes, byte-compatible with upstream `route_misc.go`:
//! - `GET /`        → `ok` (plain text)
//! - `GET /ping`    → `{code: 200, message: "pong", timestamp}` envelope
//! - `GET /healthz` → `ok` (plain text)
//! - `GET /info`    → bare JSON map `{version, build, arch, commit, devices}`

use axum::extract::State;
use axum::response::Json;
use serde_json::json;

use crate::server::AppState;

/// `GET /` — "Return an OK to indicate the server is running normally".
pub async fn root() -> String {
    "ok".into()
}

/// `GET /ping` — "ping func only returns a 'pong' string".
pub async fn ping() -> Json<crate::api::CommonResp> {
    Json(crate::api::CommonResp::new(200, "pong"))
}

/// `GET /healthz` — "usually used for health check".
pub async fn healthz() -> String {
    "ok".into()
}

/// `GET /info` — server build info plus the live device count from the store.
/// Upstream ignores a count error (`devices, _ := db.CountAll()`) → 0.
pub async fn info(State(state): State<AppState>) -> Json<serde_json::Value> {
    let devices = state.store.count_devices().unwrap_or(0);
    Json(json!({
        "version": crate::VERSION,
        "build": crate::BUILD_DATE,
        "arch": crate::go_arch(),
        "commit": crate::COMMIT_ID,
        "devices": devices,
    }))
}
