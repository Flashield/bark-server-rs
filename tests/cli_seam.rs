//! Ticket 01 acceptance: the full upstream flag/env table accepted with
//! upstream defaults, `--cert`/`--key` TLS, `--unix-socket`, and clean
//! SIGINT/SIGTERM shutdown — all verified by spawning the real binary and
//! driving it over HTTP.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{assert_envelope_no_data, client, free_port, server_header, tls_client, wait_ready};
use serde_json::Value;

fn bin_path() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_bark-server"))
}

struct SpawnedServer {
    child: tokio::process::Child,
    base_url: String,
}

impl Drop for SpawnedServer {
    fn drop(&mut self) {
        // Best-effort cleanup if a test asserts before shutting down.
        let _ = self.child.start_kill();
    }
}

async fn spawn_raw(args: &[&str]) -> tokio::process::Child {
    tokio::process::Command::new(bin_path())
        .args(args)
        .env_remove("RUST_LOG")
        .spawn()
        .expect("failed to spawn bark-server binary; run `cargo build` first")
}

/// Spawn the binary with the given args, wait until GET /ping answers on the
/// given address, and return the handle.
async fn spawn_ready(args: &[&str], addr: &str) -> SpawnedServer {
    let child = spawn_raw(args).await;
    let server = SpawnedServer {
        child,
        base_url: format!("http://{addr}"),
    };
    wait_ready(&format!("{}/ping", server.base_url)).await;
    server
}

/// Like [`spawn_ready`] but polls a specific probe URL (use with url prefixes).
async fn spawn_ready_probe(args: &[&str], addr: &str, probe_url: &str) -> SpawnedServer {
    let child = spawn_raw(args).await;
    let server = SpawnedServer {
        child,
        base_url: format!("http://{addr}"),
    };
    wait_ready(probe_url).await;
    server
}

async fn shutdown_cleanly(mut server: SpawnedServer, signal: i32, name: &str) {
    let pid = server.child.id().expect("child pid");
    assert_eq!(
        unsafe { libc::kill(pid as i32, signal) },
        0,
        "failed to send {name}"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match server.child.try_wait().expect("try_wait") {
            Some(status) => {
                assert!(
                    status.success(),
                    "server must exit cleanly on {name}, got {status}"
                );
                return;
            }
            None => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "server did not exit within 10s of {name}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

#[tokio::test]
async fn boots_with_all_audited_flags_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let server = spawn_ready(
        &[
            "-addr",
            &addr,
            "-data",
            data.to_str().unwrap(),
            "-url-prefix",
            "/",
            "-reduce-memory-usage",
            "-concurrency",
            "128",
            "-read-timeout",
            "5s",
            "-write-timeout",
            "5s",
            "-idle-timeout",
            "30s",
            "-max-batch-push-count",
            "10",
            "-max-apns-client-count",
            "2",
            "-proxy-header",
            "X-Real-IP",
            "-user",
            "someone",
            "-password",
            "secret",
        ],
        &addr,
    )
    .await;

    // Basic auth flags are accepted (enforcement is a later ticket); /ping
    // must answer with the upstream envelope regardless.
    let res = client()
        .get(format!("{}/ping", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], 200);
    assert_eq!(body["message"], "pong");

    drop(server);
}

#[tokio::test]
async fn env_vars_configure_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let child = tokio::process::Command::new(bin_path())
        .env_remove("RUST_LOG")
        .env("BARK_SERVER_ADDRESS", &addr)
        .env("BARK_SERVER_DATA_DIR", data.to_str().unwrap())
        .env("BARK_SERVER_CASE_SENSITIVE", "true")
        .env("BARK_SERVER_READ_TIMEOUT", "5s")
        .spawn()
        .unwrap();
    let server = SpawnedServer {
        child,
        base_url: format!("http://{addr}"),
    };
    wait_ready(&format!("{}/ping", server.base_url)).await;

    assert!(
        data.join("bark.db").exists(),
        "env-configured data dir must hold the store file"
    );

    // Case sensitivity honored through the env var: /PING misses the static
    // /ping route and falls to the compat push with the original-case key.
    let miss = client()
        .get(format!("{}/PING", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(miss.status(), 400);
    let body: Value = miss.json().await.unwrap();
    assert_eq!(
        body["message"],
        "failed to get device token: failed to get [PING] device token from database"
    );
    let hit = client()
        .get(format!("{}/ping", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(hit.status(), 200);

    drop(server);
}

#[tokio::test]
async fn unknown_flag_fails_fast() {
    let dir = tempfile::tempdir().unwrap();
    let out = tokio::process::Command::new(bin_path())
        .arg("--definitely-not-a-flag")
        .env("BARK_SERVER_DATA_DIR", dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .unwrap();
    assert!(
        !out.status.success(),
        "unknown flag must be rejected, got {out:?}"
    );
}

#[tokio::test]
async fn invalid_duration_env_fails_fast() {
    let dir = tempfile::tempdir().unwrap();
    let out = tokio::process::Command::new(bin_path())
        .env("BARK_SERVER_DATA_DIR", dir.path())
        .env("BARK_SERVER_READ_TIMEOUT", "banana")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .unwrap();
    assert!(
        !out.status.success(),
        "invalid duration must be rejected, got {out:?}"
    );
}

#[tokio::test]
async fn default_addr_is_upstream_8080() {
    // Only meaningful if nothing else occupies 8080 (upstream default).
    if std::net::TcpListener::bind("127.0.0.1:8080").is_err() {
        eprintln!("skipping: port 8080 already in use");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = spawn_ready(&["-data", dir.path().to_str().unwrap()], "127.0.0.1:8080").await;

    let res = client()
        .get(format!("{}/ping", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    drop(server);
}

#[tokio::test]
async fn url_prefix_flag_mounts_routes() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let server = spawn_ready_probe(
        &[
            "-addr",
            &addr,
            "-data",
            dir.path().to_str().unwrap(),
            "-url-prefix",
            "/bark",
        ],
        &addr,
        &format!("http://{addr}/bark/ping"),
    )
    .await;

    let hit = client()
        .get(format!("{}/bark/ping", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(hit.status(), 200);
    let miss = client()
        .get(format!("{}/ping", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(miss.status(), 404);
    drop(server);
}

#[tokio::test]
async fn cert_and_key_flags_enable_tls() {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    let data = tempfile::tempdir().unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let child = spawn_raw(&[
        "-addr",
        &addr,
        "-data",
        data.path().to_str().unwrap(),
        "-cert",
        cert_path.to_str().unwrap(),
        "-key",
        key_path.to_str().unwrap(),
    ])
    .await;
    let server = SpawnedServer {
        child,
        base_url: format!("https://{addr}"),
    };

    // Poll readiness over TLS.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("TLS server did not come up");
        }
        let hit = tls_client()
            .get(format!("{}/ping", server.base_url))
            .send()
            .await
            .is_ok_and(|res| res.status().is_success());
        if hit {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let res = tls_client()
        .get(format!("{}/ping", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server_header(&res), "Bark");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["message"], "pong");
    drop(server);
}

#[tokio::test]
async fn unix_socket_flag_serves_http_over_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bark.sock");
    let data = dir.path().join("data");
    let child = spawn_raw(&[
        "-unix-socket",
        sock.to_str().unwrap(),
        "-data",
        data.to_str().unwrap(),
    ])
    .await;
    let server = SpawnedServer {
        child,
        base_url: String::new(),
    };

    // Wait for the socket file, then drive a raw HTTP/1.1 client over it
    // (reqwest has no unix-socket transport).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !sock.exists() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(sock.exists(), "unix socket file must be created");

    let (status, server_hdr, body) = unix_get(&sock, "/ping").await;
    assert_eq!(status, 200);
    assert_eq!(server_hdr, "Bark");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["code"], 200);
    assert_eq!(parsed["message"], "pong");

    let (status, _, body) = unix_get(&sock, "/healthz").await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok");
    drop(server);
}

/// Minimal HTTP/1.1 GET over a unix socket, sufficient for these tests.
async fn unix_get(sock: &Path, target: &str) -> (u16, String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(sock)
        .await
        .expect("connect unix socket");
    let req = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let raw = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .expect("http response head/body split");
    let status_line = head.lines().next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let server = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("server") {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    (status, server, body.to_string())
}

#[tokio::test]
async fn sigterm_drains_and_exits_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let server = spawn_ready(
        &["-addr", &addr, "-data", dir.path().to_str().unwrap()],
        &addr,
    )
    .await;
    shutdown_cleanly(server, libc::SIGTERM, "SIGTERM").await;
}

#[tokio::test]
async fn sigint_drains_and_exits_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let server = spawn_ready(
        &["-addr", &addr, "-data", dir.path().to_str().unwrap()],
        &addr,
    )
    .await;
    shutdown_cleanly(server, libc::SIGINT, "SIGINT").await;
}

#[tokio::test]
async fn info_has_upstream_map_shape_via_binary() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let server = spawn_ready(
        &["-addr", &addr, "-data", dir.path().to_str().unwrap()],
        &addr,
    )
    .await;
    let res = client()
        .get(format!("{}/info", server.base_url))
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    for key in ["version", "build", "arch", "commit", "devices"] {
        assert!(body.get(key).is_some(), "/info missing key {key}: {body}");
    }
    assert_eq!(body["devices"], 0);
    drop(server);
}

// ---------------------------------------------------------------------------
// PostgreSQL backend selection (ticket 12): `--dsn` / BARK_SERVER_DSN — the
// deliberate MySQL deviation (ADR-0005: upstream's --dsn activated MySQL).
// ---------------------------------------------------------------------------

/// Register a device against the spawned server and return its Device Key.
async fn register_device(base_url: &str, token: &str) -> String {
    let res = client()
        .post(format!("{base_url}/register"))
        .json(&serde_json::json!({"device_token": token, "device_type": "ios"}))
        .send()
        .await
        .expect("register request");
    assert_eq!(res.status(), 200, "register must succeed: {res:?}");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], 200, "register envelope: {body}");
    body["data"]["key"]
        .as_str()
        .expect("device key")
        .to_string()
}

/// `--dsn` pointing at PostgreSQL activates the PG backend and the record
/// persists across a restart on the same DSN (the env spelling
/// `BARK_SERVER_DSN` is exercised on the restart leg). Skipped unless the
/// suite runs in PG parity mode (`BARK_TEST_PG_DSN` — see
/// tests/common/pg.rs and scripts/test-postgres.sh).
#[tokio::test]
async fn dsn_selects_the_postgres_backend() {
    let Some(dsn) = common::pg::parity_dsn() else {
        eprintln!("skipping: BARK_TEST_PG_DSN not set (not in PG parity mode)");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    // Leg 1: the flag spelling.
    let server = spawn_ready(
        &[
            "-addr",
            &addr,
            "-data",
            dir.path().to_str().unwrap(),
            "--dsn",
            &dsn,
        ],
        &addr,
    )
    .await;
    let key = register_device(&server.base_url, "tokPgDsn").await;
    drop(server);

    // Leg 2: the env spelling, fresh process on the same DSN — the record
    // must survive, proving both that the env var selects PG and that the
    // store behind it is the same PostgreSQL database.
    let child = tokio::process::Command::new(bin_path())
        .args(["-addr", &addr, "-data", dir.path().to_str().unwrap()])
        .env_remove("RUST_LOG")
        .env("BARK_SERVER_DSN", &dsn)
        .spawn()
        .expect("failed to spawn bark-server binary; run `cargo build` first");
    let server = SpawnedServer {
        child,
        base_url: format!("http://{addr}"),
    };
    wait_ready(&format!("{}/ping", server.base_url)).await;

    let res = client()
        .get(format!("{}/register/{key}", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        200,
        "record must persist across restart: {key}"
    );
    let body: Value = res.json().await.unwrap();
    assert_envelope_no_data(&body, 200, "success");
    drop(server);
}
