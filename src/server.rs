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
use crate::store::{SqliteStore, Store};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    /// APNs delivery client (endpoint from `--apns-endpoint`).
    pub apns: Arc<ApnsClient>,
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
    // Upstream: initializeDatabase before startServer (ReCreateAPNS runs in
    // upstream's init(); the client is built here from the config instead,
    // which is equivalent since no connection is made until a push).
    let store = SqliteStore::open(&config.data_dir)
        .with_context(|| format!("failed to open sqlite store at {:?}", config.data_dir))?;
    let apns = ApnsClient::from_config(&config).context("failed to initialize APNs client")?;
    let mcp = crate::mcp::McpRegistry::new(config.mcp_session_idle_ttl);
    let state = AppState {
        config: Arc::new(config.clone()),
        store: Arc::new(store),
        apns: Arc::new(apns),
        mcp,
    };
    let app_service = api::build_app_service(&state);
    let db_label = format!("sqlite({})", config.data_dir.display());
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
