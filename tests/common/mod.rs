//! Shared helpers for the HTTP-seam test suite.
//!
//! Per the testing decision in the spec, every test drives a real server
//! (ephemeral port, temporary SQLite store) with a real HTTP client (reqwest).
//! No internal mocks.

#![allow(dead_code)] // helpers are shared per test-target, not all used everywhere

pub mod apns_stub;
pub mod pg;
pub mod sse_client;

use std::time::Duration;

use bark_server_rs::config::Config;
use serde_json::Value;

/// Pick a free TCP port by binding to 0 and dropping the listener.
/// The tiny race is acceptable for tests; readiness polling covers slow starts.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Boot the real server in-process on an ephemeral port with a temporary
/// store. `shutdown()` stops it and drops the temp dir.
pub struct TestServer {
    pub base_url: String,
    /// Normalized url prefix ("" for root).
    pub url_prefix: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    pub handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    _dir: Option<tempfile::TempDir>,
}

impl TestServer {
    pub async fn spawn(config: Config, dir: tempfile::TempDir) -> Self {
        Self::spawn_at(config, Some(dir)).await
    }

    /// Spawn with an externally managed data dir (`config.data_dir`). The
    /// caller owns the directory lifetime — used for restart tests where the
    /// store must outlive a server shutdown.
    pub async fn spawn_with_data_dir(config: Config) -> Self {
        Self::spawn_at(config, None).await
    }

    async fn spawn_at(config: Config, dir: Option<tempfile::TempDir>) -> Self {
        let base_url = format!("http://{}", config.addr);
        let url_prefix = bark_server_rs::api::normalized_prefix(&config.url_prefix);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(bark_server_rs::run_server(config, async move {
            let _ = rx.await;
        }));
        wait_ready(&format!("{base_url}{url_prefix}/ping")).await;
        Self {
            base_url,
            url_prefix,
            shutdown: Some(tx),
            handle,
            _dir: dir,
        }
    }

    /// URL for a route under the server's url prefix.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}{}", self.base_url, self.url_prefix, path)
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.handle.await;
    }
}

/// A config whose data dir and port are ephemeral, plus its temp dir handle.
pub fn ephemeral_config() -> (Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = Config {
        addr: format!("127.0.0.1:{}", free_port()),
        data_dir: dir.path().to_path_buf(),
        ..Default::default()
    };
    // Backend parity (ticket 12): in PG parity mode the same suites, with
    // untouched assertions, run against a fresh PostgreSQL database; absent
    // the parity env the default SQLite backend is used.
    config.dsn = pg::parity_dsn().unwrap_or_default();
    (config, dir)
}

/// Poll `probe_url` (a full URL, e.g. prefix-aware `/ping`) until it answers
/// with a success status.
pub async fn wait_ready(probe_url: &str) {
    let client = reqwest::Client::new();
    // PG parity mode (ticket 12) adds per-spawn provisioning + connect +
    // schema migration work on a possibly loaded machine; give it headroom.
    let budget = if std::env::var_os("BARK_TEST_PG_DSN").is_some() {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(15)
    };
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("server at {probe_url} did not become ready in time");
        }
        match client.get(probe_url).send().await {
            Ok(res) if res.status().is_success() => return,
            Ok(res) => eprintln!("wait_ready: got status {}", res.status()),
            Err(err) => eprintln!("wait_ready: connect error: {err}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client")
}

pub fn tls_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client")
}

/// Assert a JSON body is exactly the upstream envelope shape without data:
/// `{code, message, timestamp}` (data omitted when unset) with a fresh timestamp.
pub fn assert_envelope_no_data(body: &Value, expected_code: i64, expected_message: &str) {
    assert_eq!(body["code"], expected_code, "envelope code: {body}");
    assert_eq!(
        body["message"], expected_message,
        "envelope message: {body}"
    );
    assert!(
        body.get("data").is_none(),
        "envelope must omit data when unset: {body}"
    );
    assert!(
        body["timestamp"].is_i64(),
        "envelope timestamp must be an integer: {body}"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ts = body["timestamp"].as_i64().unwrap();
    assert!(
        (now - ts).abs() <= 5,
        "timestamp {ts} not within 5s of now {now}"
    );
}

/// Read the `Server` response header; panics if absent.
pub fn server_header(res: &reqwest::Response) -> String {
    res.headers()
        .get("Server")
        .map(|v| v.to_str().expect("server header ascii").to_string())
        .unwrap_or_else(|| panic!("missing Server header"))
}
