//! Configuration surface: the full upstream bark-server v2.4.0 flag/env table
//! (audited from upstream `main.go`), plus the additive APNs endpoint knob.
//!
//! Upstream flags that belong to deliberately dropped backends (MySQL
//! `--dsn`/`--mysql-*`, `--serverless`) are not accepted; see ADR-0005 and the
//! spec's Out of Scope section.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// Go-style duration parser (`"300ms"`, `"5s"`, `"2m45s"`, `"1h30m"`),
/// covering the units upstream's `cli.DurationFlag` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoDuration(pub Duration);

impl std::str::FromStr for GoDuration {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_go_duration(s).map(GoDuration)
    }
}

fn parse_go_duration(s: &str) -> Result<Duration, String> {
    let original = s;
    let mut rest = s;
    if rest.is_empty() {
        return Err(format!("invalid duration {original:?}: empty"));
    }
    let mut total_nanos: u128 = 0;
    while !rest.is_empty() {
        // Number part.
        let num_end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if num_end == 0 {
            return Err(format!("invalid duration {original:?}: missing number"));
        }
        let num: f64 = rest[..num_end]
            .parse()
            .map_err(|_| format!("invalid duration {original:?}: bad number"))?;
        rest = &rest[num_end..];
        // Unit part (longest match first).
        let (unit_nanos, unit_len) = if rest.starts_with("ns") {
            (1u128, 2)
        } else if rest.starts_with("us") || rest.starts_with("µs") {
            let len = if rest.starts_with("us") { 2 } else { 3 };
            (1_000, len)
        } else if rest.starts_with("ms") {
            (1_000_000, 2)
        } else if rest.starts_with('s') {
            (1_000_000_000, 1)
        } else if rest.starts_with('m') {
            (60_000_000_000, 1)
        } else if rest.starts_with('h') {
            (3_600_000_000_000, 1)
        } else {
            return Err(format!(
                "invalid duration {original:?}: unknown unit near {rest:?}"
            ));
        };
        rest = &rest[unit_len..];
        total_nanos += (num * unit_nanos as f64) as u128;
    }
    u64::try_from(total_nanos)
        .map(Duration::from_nanos)
        .map_err(|_| format!("invalid duration {original:?}: overflow"))
}

/// The full server configuration. Defaults mirror upstream exactly.
#[derive(Clone, Debug)]
pub struct Config {
    /// `--addr` / `BARK_SERVER_ADDRESS`
    pub addr: String,
    /// `--unix-socket` / `BARK_SERVER_UNIX_SOCKET` (empty = disabled)
    pub unix_socket: String,
    /// `--url-prefix` / `BARK_SERVER_URL_PREFIX`
    pub url_prefix: String,
    /// `--data` / `BARK_SERVER_DATA_DIR`
    pub data_dir: PathBuf,
    /// `--cert` / `BARK_SERVER_CERT` (with `--key`, enables TLS)
    pub cert: String,
    /// `--key` / `BARK_SERVER_KEY`
    pub key: String,
    /// `--case-sensitive` / `BARK_SERVER_CASE_SENSITIVE`
    pub case_sensitive: bool,
    /// `--strict-routing` / `BARK_SERVER_STRICT_ROUTING`
    pub strict_routing: bool,
    /// `--reduce-memory-usage` / `BARK_SERVER_REDUCE_MEMORY_USAGE` (accepted
    /// no-op: a fiber-specific memory/CPU trade-off with no axum equivalent)
    pub reduce_memory_usage: bool,
    /// `--user` / `BARK_SERVER_BASIC_AUTH_USER` (Basic Auth enforcement is a
    /// later ticket; accepted here for surface parity)
    pub basic_auth_user: String,
    /// `--password` / `BARK_SERVER_BASIC_AUTH_PASSWORD`
    pub basic_auth_password: String,
    /// `--proxy-header` / `BARK_SERVER_PROXY_HEADER`
    pub proxy_header: String,
    /// `--max-batch-push-count` / `BARK_SERVER_MAX_BATCH_PUSH_COUNT` (-1 = no limit)
    pub max_batch_push_count: i64,
    /// `--max-apns-client-count` / `BARK_SERVER_MAX_APNS_CLIENT_COUNT`
    pub max_apns_client_count: i64,
    /// `--concurrency` / `BARK_SERVER_CONCURRENCY` (hidden; accepted no-op —
    /// tokio has no fixed connection-count cap to mirror)
    pub concurrency: i64,
    /// `--read-timeout` / `BARK_SERVER_READ_TIMEOUT` (hidden; accepted knob)
    pub read_timeout: Duration,
    /// `--write-timeout` / `BARK_SERVER_WRITE_TIMEOUT` (hidden; accepted knob)
    pub write_timeout: Duration,
    /// `--idle-timeout` / `BARK_SERVER_IDLE_TIMEOUT` (hidden; accepted knob)
    pub idle_timeout: Duration,
    /// `--apns-endpoint` / `BARK_SERVER_APNS_ENDPOINT` (additive; the test
    /// stub injection point for APNs delivery, see spec/ADR-0004)
    pub apns_endpoint: String,
    /// `--apns-insecure-skip-tls-verify` /
    /// `BARK_SERVER_APNS_INSECURE_SKIP_TLS_VERIFY` (additive; companion to
    /// `--apns-endpoint` so a local self-signed APNs stub can stand in)
    pub apns_insecure_skip_tls_verify: bool,
    /// `--sse-keepalive-secs` / `BARK_SERVER_SSE_KEEPALIVE_SECS` (additive;
    /// seconds between SSE keepalive comment lines on the realtime stream,
    /// keeping proxies/NATs from idling the connection out; 0 disables)
    pub sse_keepalive_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:8080".into(),
            unix_socket: String::new(),
            url_prefix: "/".into(),
            data_dir: PathBuf::from("/data"),
            cert: String::new(),
            key: String::new(),
            case_sensitive: false,
            strict_routing: false,
            reduce_memory_usage: false,
            basic_auth_user: String::new(),
            basic_auth_password: String::new(),
            proxy_header: String::new(),
            max_batch_push_count: -1,
            max_apns_client_count: 1,
            concurrency: 256 * 1024,
            read_timeout: Duration::from_secs(3),
            write_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(10),
            apns_endpoint: "https://api.push.apple.com".into(),
            apns_insecure_skip_tls_verify: false,
            sse_keepalive_secs: 15,
        }
    }
}

/// CLI definition mirroring upstream `getAppFlags()`.
#[derive(Parser, Debug)]
#[command(
    name = "bark-server",
    about = "Push Server For Bark",
    version = crate::VERSION
)]
pub struct Cli {
    /// Server listen address
    #[arg(long, env = "BARK_SERVER_ADDRESS", default_value = "0.0.0.0:8080")]
    pub addr: String,

    /// Server listen unix socket
    #[arg(long, env = "BARK_SERVER_UNIX_SOCKET", default_value = "")]
    pub unix_socket: String,

    /// Serve URL Prefix
    #[arg(long, env = "BARK_SERVER_URL_PREFIX", default_value = "/")]
    pub url_prefix: String,

    /// Server data storage dir
    #[arg(long, env = "BARK_SERVER_DATA_DIR", default_value = "/data")]
    pub data: String,

    /// Server TLS certificate
    #[arg(long, env = "BARK_SERVER_CERT", default_value = "")]
    pub cert: String,

    /// Server TLS certificate key
    #[arg(long, env = "BARK_SERVER_KEY", default_value = "")]
    pub key: String,

    /// Enable HTTP URL case sensitive
    #[arg(
        long,
        env = "BARK_SERVER_CASE_SENSITIVE",
        default_value = "false",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    pub case_sensitive: bool,

    /// Enable strict routing distinction
    #[arg(
        long,
        env = "BARK_SERVER_STRICT_ROUTING",
        default_value = "false",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    pub strict_routing: bool,

    /// Aggressively reduces memory usage at the cost of higher CPU usage if set to true
    #[arg(
        long,
        env = "BARK_SERVER_REDUCE_MEMORY_USAGE",
        default_value = "false",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    pub reduce_memory_usage: bool,

    /// Basic auth username
    #[arg(long, env = "BARK_SERVER_BASIC_AUTH_USER", default_value = "")]
    pub user: String,

    /// Basic auth password
    #[arg(long, env = "BARK_SERVER_BASIC_AUTH_PASSWORD", default_value = "")]
    pub password: String,

    /// The remote IP address used by the bark server http header
    #[arg(long, env = "BARK_SERVER_PROXY_HEADER", default_value = "")]
    pub proxy_header: String,

    /// Maximum number of batch pushes allowed, -1 means no limit
    #[arg(long, env = "BARK_SERVER_MAX_BATCH_PUSH_COUNT", default_value = "-1")]
    pub max_batch_push_count: i64,

    /// Maximum number of APNs client connections
    #[arg(long, env = "BARK_SERVER_MAX_APNS_CLIENT_COUNT", default_value = "1")]
    pub max_apns_client_count: i64,

    /// Maximum number of concurrent connections (accepted; tokio has no fixed cap)
    #[arg(
        long,
        env = "BARK_SERVER_CONCURRENCY",
        default_value = "262144",
        hide = true
    )]
    pub concurrency: i64,

    /// The amount of time allowed to read the full request, including the body
    #[arg(
        long,
        env = "BARK_SERVER_READ_TIMEOUT",
        default_value = "3s",
        hide = true
    )]
    pub read_timeout: GoDuration,

    /// The maximum duration before timing out writes of the response
    #[arg(
        long,
        env = "BARK_SERVER_WRITE_TIMEOUT",
        default_value = "3s",
        hide = true
    )]
    pub write_timeout: GoDuration,

    /// The maximum amount of time to wait for the next request when keep-alive is enabled
    #[arg(
        long,
        env = "BARK_SERVER_IDLE_TIMEOUT",
        default_value = "10s",
        hide = true
    )]
    pub idle_timeout: GoDuration,

    /// APNs API endpoint base URL (additive; point at a local stub for tests)
    #[arg(
        long,
        env = "BARK_SERVER_APNS_ENDPOINT",
        default_value = "https://api.push.apple.com"
    )]
    pub apns_endpoint: String,

    /// Skip TLS certificate verification for the APNs endpoint (additive;
    /// companion to `--apns-endpoint` so a local self-signed stub can stand in)
    #[arg(
        long,
        env = "BARK_SERVER_APNS_INSECURE_SKIP_TLS_VERIFY",
        default_value = "false",
        default_missing_value = "true",
        num_args = 0..=1
    )]
    pub apns_insecure_skip_tls_verify: bool,

    /// Seconds between SSE keepalive comments on the realtime stream
    /// (additive; 0 disables keepalives)
    #[arg(long, env = "BARK_SERVER_SSE_KEEPALIVE_SECS", default_value = "15")]
    pub sse_keepalive_secs: u64,
}

/// Every long flag name the CLI defines (plus the auto-generated ones), used
/// by [`normalize_single_dash_args`].
const LONG_FLAGS: &[&str] = &[
    "addr",
    "unix-socket",
    "url-prefix",
    "data",
    "cert",
    "key",
    "case-sensitive",
    "strict-routing",
    "reduce-memory-usage",
    "user",
    "password",
    "proxy-header",
    "max-batch-push-count",
    "max-apns-client-count",
    "concurrency",
    "read-timeout",
    "write-timeout",
    "idle-timeout",
    "apns-endpoint",
    "apns-insecure-skip-tls-verify",
    "sse-keepalive-secs",
    "help",
    "version",
];

/// Rewrite `-flag` / `-flag=value` (single dash) into `--flag` / `--flag=value`
/// when `flag` names a known option. Unknown single-dash args (e.g. `-5` as a
/// value) pass through untouched.
pub fn normalize_single_dash_args<I: IntoIterator<Item = String>>(args: I) -> Vec<String> {
    args.into_iter()
        .map(|arg| {
            let Some(rest) = arg.strip_prefix('-') else {
                return arg;
            };
            if rest.is_empty() || rest.starts_with('-') {
                return arg;
            }
            let (name, value) = match rest.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (rest, None),
            };
            if LONG_FLAGS.contains(&name) {
                return match value {
                    Some(v) => format!("--{name}={v}"),
                    None => format!("--{name}"),
                };
            }
            arg
        })
        .collect()
}

impl Cli {
    /// Parse CLI args with upstream compatibility: urfave/cli accepts
    /// single-dash long flags (`-addr 0.0.0.0:8080`), clap only `--addr`, so
    /// known single-dash long flags are rewritten before parsing. This keeps
    /// upstream command lines, systemd units and docker-compose entries
    /// working unchanged.
    pub fn parse_args() -> Self {
        Self::parse_from(normalize_single_dash_args(std::env::args()))
    }

    pub fn to_config(&self) -> Config {
        Config {
            addr: self.addr.clone(),
            unix_socket: self.unix_socket.clone(),
            url_prefix: self.url_prefix.clone(),
            data_dir: PathBuf::from(&self.data),
            cert: self.cert.clone(),
            key: self.key.clone(),
            case_sensitive: self.case_sensitive,
            strict_routing: self.strict_routing,
            reduce_memory_usage: self.reduce_memory_usage,
            basic_auth_user: self.user.clone(),
            basic_auth_password: self.password.clone(),
            proxy_header: self.proxy_header.clone(),
            max_batch_push_count: self.max_batch_push_count,
            max_apns_client_count: self.max_apns_client_count,
            concurrency: self.concurrency,
            read_timeout: self.read_timeout.0,
            write_timeout: self.write_timeout.0,
            idle_timeout: self.idle_timeout.0,
            apns_endpoint: self.apns_endpoint.clone(),
            apns_insecure_skip_tls_verify: self.apns_insecure_skip_tls_verify,
            sse_keepalive_secs: self.sse_keepalive_secs,
        }
    }
}
