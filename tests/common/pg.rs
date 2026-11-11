//! PostgreSQL parity harness for the HTTP-seam suites (ticket 12, ADR-0005).
//!
//! The seam contract: the same suites, the same assertions, a different
//! backend. When `BARK_TEST_PG_DSN` is set — a libpq URL or keyword/value
//! string with CREATE DATABASE rights on a throwaway PostgreSQL instance,
//! as `scripts/test-postgres.sh` provisions on `postgres:alpine` —
//! [`parity_dsn`] hands every spawned server a fresh, uniquely named
//! database on that instance, and each test runs the full HTTP boundary
//! against real PostgreSQL. When the variable is absent the suites run
//! unchanged against the SQLite default (hermetic; no Docker needed).
//!
//! Databases are not dropped at test end: the canonical instance is a
//! throwaway container whose databases die with it. For a long-lived CI
//! instance, run the job against a disposable role and let the job's own
//! teardown drop `bark_test_*`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Database-name counter: unique per call within this test process.
static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// The per-test-thread database: libtest runs each test on its own OS
    /// thread, so this is one database per test, minted on first use and
    /// shared by every spawn in that test (restart tests need the same
    /// store across server lifetimes).
    static PER_TEST_DSN: Option<String> = parity_dsn();
}

/// The per-test database DSN, memoized for the calling test's thread —
/// [`parity_dsn`] mints it on first use within the test.
pub fn parity_dsn_per_test() -> Option<String> {
    PER_TEST_DSN.with(|slot| slot.clone())
}

/// A fresh PostgreSQL DSN for one test — `Some` only in parity mode
/// (`BARK_TEST_PG_DSN` set). The database is created up front; panics are
/// loud: parity mode demanded but unavailable must fail the suite, not
/// silently fall back to SQLite.
///
/// The provisioning runs on a dedicated OS thread: the sync rust-postgres
/// client builds its own internal tokio runtime and `block_on`s, which
/// panics on an async runtime thread — the same reason
/// `src/store/postgres.rs` routes all store work through one worker thread.
pub fn parity_dsn() -> Option<String> {
    let base = std::env::var("BARK_TEST_PG_DSN").ok()?;
    let name = format!(
        "bark_test_{}_{}",
        std::process::id(),
        DB_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let dsn = thread_result(move || {
        let admin: postgres::Config = base.parse().map_err(|e| {
            format!("BARK_TEST_PG_DSN must be a valid libpq URL or keyword/value string: {e}")
        })?;
        let mut client = admin
            .connect(postgres::NoTls)
            .map_err(|e| format!("connect to the BARK_TEST_PG_DSN instance: {e}"))?;
        // CREATE DATABASE cannot run inside a transaction block; the sync
        // client's batch_execute sends it standalone (ticket 12).
        client
            .batch_execute(&format!("CREATE DATABASE {}", quote_ident(&name)))
            .map_err(|e| {
                format!("create per-test database on the BARK_TEST_PG_DSN instance: {e}")
            })?;
        drop(client);
        Ok(rewrite_dbname(&base, &name))
    });
    Some(dsn)
}

/// Run `f` on a short-lived OS thread (off the async runtime) and return
/// its result, unwrapping both join and result loudly.
fn thread_result<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> T {
    std::thread::Builder::new()
        .name("bark-pg-provision".into())
        .spawn(f)
        .expect("spawn PG provisioning thread")
        .join()
        .expect("PG provisioning thread panicked")
        .expect("provision the per-test PostgreSQL database")
}

/// Quote a generated identifier (defensive: the names are pid/counter-built).
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Point `dsn` at database `dbname`, preserving every other parameter. Both
/// accepted libpq forms are handled: URL (`postgres://…/db?…`) and
/// keyword/value (`host=… dbname=…` — values must not contain whitespace).
fn rewrite_dbname(dsn: &str, dbname: &str) -> String {
    if let Some(scheme_end) = dsn.find("://") {
        // URL form: the authority ends before the first '/', '?' or '#'
        // after the scheme; replace (or add) the path segment.
        let after = &dsn[scheme_end + 3..];
        let authority_len = after.find(['/', '?', '#']).unwrap_or(after.len());
        let head = &dsn[..scheme_end + 3 + authority_len];
        let tail = &dsn[scheme_end + 3 + authority_len..];
        let query_start = tail.find(['?', '#']).unwrap_or(tail.len());
        format!("{head}/{dbname}{}", &tail[query_start..])
    } else {
        // keyword/value form: rebuild without any existing dbname entry and
        // append the fresh one (the generated name needs no quoting).
        let kept: Vec<&str> = dsn
            .split_whitespace()
            .filter(|kv| !kv.starts_with("dbname="))
            .collect();
        let mut out = kept.join(" ");
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str("dbname=");
        out.push_str(dbname);
        out
    }
}
