//! Storage layer: a backend-agnostic `Store` trait (PostgreSQL is the planned
//! second backend per ADR-0005) and the embedded SQLite implementation
//! (rusqlite, bundled) holding the single file under the configured data
//! directory, mirroring upstream's bbolt deployment shape.

mod sqlite;

pub use sqlite::SqliteStore;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("store lock poisoned")]
    Poisoned,
}

/// Persistence for Devices (and, in later tickets, Stream Tokens and pending
/// messages). Sync on purpose: SQLite calls are short and the connection is
/// mutex-guarded; callers on the async runtime should keep using it for
/// cheap statements and switch hot paths to `spawn_blocking` if profiling
/// ever demands it.
pub trait Store: Send + Sync {
    /// Number of registered Devices; backs `/info`'s `devices` field.
    fn count_devices(&self) -> Result<i64, StoreError>;
}
