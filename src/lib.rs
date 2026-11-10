//! bark-server-rs: a drop-in Rust rewrite of bark-server (ADR-0003) with SSE
//! realtime mirroring. Single crate; modules per the spec:
//! `api` (routes/middleware), `store` (trait + SQLite impl), `config`
//! (flags/env). `events`, `apns` and `mcp` arrive with their tickets.

pub mod api;
pub mod config;
pub mod server;
pub mod store;

pub use config::Config;
pub use server::{run_server, shutdown_signal};

/// Upstream injects these via ldflags (`git describe --tags`, `git
/// rev-parse HEAD`, build date). Overridable at build time with
/// `BARK_SERVER_VERSION` / `BARK_SERVER_COMMIT` / `BARK_SERVER_BUILD_DATE`.
pub const VERSION: &str = match option_env!("BARK_SERVER_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

pub const COMMIT_ID: &str = match option_env!("BARK_SERVER_COMMIT") {
    Some(v) => v,
    None => "unknown",
};

pub const BUILD_DATE: &str = match option_env!("BARK_SERVER_BUILD_DATE") {
    Some(v) => v,
    None => "unknown",
};

/// `runtime.GOOS + "/" + runtime.GOARCH` equivalent for `/info`, mapping
/// Rust's platform constants onto Go's naming (`linux/amd64`).
pub fn go_arch() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}/{arch}")
}
