/// Server bootstrap: builds the router, binds TCP / unix socket / TLS, serves
/// with graceful shutdown, mirroring upstream `runServer` flow order
/// (create app → routes → init database → shutdown handling → listen).
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::ServiceExt;

use crate::api;
use crate::apns::ApnsClient;
use crate::config::Config;
use crate::events::EventBus;
use crate::store::{PostgresStore, SqliteStore, Store};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    /// APNs delivery client (endpoint from `--apns-endpoint`).
    pub apns: Arc<ApnsClient>,
    /// Transport-agnostic event bus (ADR-0001): the push pipeline persists
    /// through it and the SSE streams subscribe to it.
    pub events: Arc<EventBus>,
    /// Flips to `true` when the shutdown signal fires. Long-lived responses
    /// (the SSE streams) watch it so graceful shutdown can complete instead
    /// of waiting on connections that would otherwise never end.
    pub shutdown: tokio::sync::watch::Receiver<bool>,
    /// MCP tool servers behind `/mcp` and `/mcp/:device_key` (src/mcp.rs);
    /// per-instance session tables with the configured idle TTL.
    pub mcp: crate::mcp::McpRegistry,
}

/// Future resolving on SIGINT or SIGTERM (upstream's graceful shutdown
/// triggers on either).
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
    tracing::warn!("Received a termination signal, bark server shutdown...");
}

/// rustls needs a process-level crypto provider; axum-server's `tls-rustls`
/// is provider-less by default. Ring keeps the build hermetic (no cmake/Go).
fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Run the server until `shutdown` resolves, mirroring upstream's
/// `runServer`: initialize the database first, then listen.
pub async fn run_server(
    config: Config,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    // Notify in-flight long-lived responses (SSE streams) about the shutdown
    // signal so they can end and let the graceful shutdown complete.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let shutdown = {
        let tx = shutdown_tx.clone();
        async move {
            shutdown.await;
            let _ = tx.send(true);
        }
    };

    let state = build_state(&config, shutdown_rx)?;
    let app_service = api::build_app_service(&state);
    // The log label names the backend only — the DSN carries credentials
    // and is never echoed (upstream logs its MySQL DSN-free equivalents
    // similarly).
    let db_label = db_label(&config);
    if !config.cert.is_empty() || !config.key.is_empty() {
        // Upstream: TLS only when BOTH cert and key are set, on TCP.
        if config.cert.is_empty() || config.key.is_empty() {
            anyhow::bail!("--cert and --key must both be provided to enable TLS");
        }
        install_default_crypto_provider();
        let tls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&config.cert, &config.key)
                .await
                .context("failed to load TLS certificate/key")?;
        let addr: std::net::SocketAddr = config
            .addr
            .parse()
            .with_context(|| format!("invalid --addr {:?}", config.addr))?;
        tracing::info!("Bark Server Listen at: {addr} , Database: {db_label} (TLS)");

        let handle: axum_server::Handle<std::net::SocketAddr> = axum_server::Handle::new();
        tokio::spawn(async move {
            shutdown.await;
            handle.shutdown();
        });
        // axum-server feeds hyper's Incoming body; AppService is body-generic.
        let make_service = <api::AppService<Router> as ServiceExt<
            http::Request<hyper::body::Incoming>,
        >>::into_make_service(app_service);
        axum_server::bind_rustls(addr, tls_config)
            .serve(make_service)
            .await
            .context("TLS server error")?;
        return Ok(());
    }

    if !config.unix_socket.is_empty() {
        // Upstream removes a stale socket file before listening.
        let socket_path = PathBuf::from(&config.unix_socket);
        let _ = std::fs::remove_file(&socket_path);
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .with_context(|| format!("failed to bind unix socket {socket_path:?}"))?;
        tracing::info!(
            "Bark Server Listen at: {} , Database: {db_label}",
            socket_path.display()
        );
        let make_service =
            <api::AppService<Router> as ServiceExt<axum::extract::Request>>::into_make_service(
                app_service,
            );
        axum::serve(listener, make_service)
            .with_graceful_shutdown(shutdown)
            .await
            .context("unix socket server error")?;
        return Ok(());
    }

    let listener = tokio::net::TcpListener::bind(&config.addr)
        .await
        .with_context(|| format!("failed to bind address {:?}", config.addr))?;
    serve_tcp(listener, app_service, &db_label, shutdown).await
}

/// [`run_server`] on an already-bound TCP listener: identical flow (store
/// first, then serve), but the plain-TCP path serves on `listener` instead of
/// binding `--addr`. The test seam's port-race fix: the port is held from
/// allocation through serve, so a concurrent spawn's ephemeral allocation can
/// never be handed the same port (the kernel never returns in-use ports) and
/// this server can never lose its port to another bind between allocation and
/// listen. TLS and unix-socket configurations are rejected — the pre-bound
/// listener serves plain TCP by definition.
pub async fn run_server_on_listener(
    listener: std::net::TcpListener,
    config: Config,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    if !config.cert.is_empty() || !config.key.is_empty() || !config.unix_socket.is_empty() {
        anyhow::bail!("run_server_on_listener serves plain TCP only");
    }
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let shutdown = async move {
        shutdown.await;
        let _ = shutdown_tx.send(true);
    };
    let state = build_state(&config, shutdown_rx)?;
    let app_service = api::build_app_service(&state);
    listener
        .set_nonblocking(true)
        .context("listener is not usable for async serving")?;
    let listener = tokio::net::TcpListener::from_std(listener)
        .context("failed to adapt the std listener for tokio")?;
    serve_tcp(listener, app_service, &db_label(&config), shutdown).await
}

/// Store, APNs client, MCP registry, event bus and shutdown watch — the
/// shared bootstrap of [`run_server`] / [`run_server_on_listener`].
fn build_state(
    config: &Config,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<AppState> {
    // Upstream: initializeDatabase before startServer (ReCreateAPNS runs in
    // upstream's init(); the client is built here from the config instead,
    // which is equivalent since no connection is made until a push).
    // Retention (ticket 08, ADR-0002): the additive flags are seconds/count
    // with 0 = limit disabled (MessageRetention::from_limits).
    let retention = crate::store::MessageRetention::from_limits(
        config.sse_message_ttl_secs,
        config.sse_message_cap,
    );
    // Backend selection (ticket 12, ADR-0005): --dsn / BARK_SERVER_DSN
    // activates PostgreSQL (the deliberate replacement for upstream's
    // MySQL); absent, the embedded SQLite default — single-file, zero
    // external dependencies — is used.
    let store: Arc<dyn Store> = if config.dsn.is_empty() {
        Arc::new(
            SqliteStore::open(&config.data_dir, retention)
                .with_context(|| format!("failed to open sqlite store at {:?}", config.data_dir))?,
        )
    } else {
        Arc::new(
            PostgresStore::open(&config.dsn, retention).context(
                "failed to open postgres store; check --dsn connectivity and credentials",
            )?,
        )
    };
    let apns = ApnsClient::from_config(config).context("failed to initialize APNs client")?;
    let mcp = crate::mcp::McpRegistry::new(config.mcp_session_idle_ttl);
    Ok(AppState {
        config: Arc::new(config.clone()),
        events: Arc::new(EventBus::new(store.clone())),
        store,
        apns: Arc::new(apns),
        shutdown: shutdown_rx,
        mcp,
    })
}

/// The backend label for the "Bark Server Listen at" log line.
fn db_label(config: &Config) -> String {
    if config.dsn.is_empty() {
        format!("sqlite({})", config.data_dir.display())
    } else {
        "postgres".to_string()
    }
}

/// Serve the assembled app on a ready TCP listener with graceful shutdown.
async fn serve_tcp(
    listener: tokio::net::TcpListener,
    app_service: api::AppService<Router>,
    db_label: &str,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let addr = listener.local_addr()?;
    tracing::info!("Bark Server Listen at: {addr} , Database: {db_label}");
    let make_service =
        <api::AppService<Router> as ServiceExt<axum::extract::Request>>::into_make_service(
            app_service,
        );
    axum::serve(listener, make_service)
        .with_graceful_shutdown(shutdown)
        .await
        .context("tcp server error")?;
    Ok(())
}
