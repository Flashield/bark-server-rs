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

/// Upstream device types (`database/database.go`); the device type selects
/// the APNs topic when pushing and defaults to `ios`.
pub const DEVICE_TYPE_IOS: &str = "ios";
pub const DEVICE_TYPE_WATCHOS: &str = "watchos";

/// Upstream `normalizeDeviceType`: empty device type defaults to `ios`.
pub fn normalize_device_type(device_type: &str) -> &str {
    if device_type.is_empty() {
        DEVICE_TYPE_IOS
    } else {
        device_type
    }
}

/// The persisted state of a Device (upstream `database.DeviceRecord`): its
/// Device Token, device type, and last-updated time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub token: String,
    pub device_type: String,
    pub updated_at: i64,
}

/// Persistence for Devices (and, in later tickets, Stream Tokens and pending
/// messages). Sync on purpose: SQLite calls are short and the connection is
/// mutex-guarded; callers on the async runtime should keep using it for
/// cheap statements and switch hot paths to `spawn_blocking` if profiling
/// ever demands it.
pub trait Store: Send + Sync {
    /// Number of registered Devices; backs `/info`'s `devices` field.
    fn count_devices(&self) -> Result<i64, StoreError>;

    /// Create or update the Device Record for `key`, mirroring upstream
    /// `SaveDeviceTokenByKey`: when `key` is empty or unknown, a new
    /// 22-char shortuuid-style Device Key is generated (a new Device
    /// registration); an existing key updates its record in place. Returns
    /// the (possibly newly generated) key.
    fn save_device_token_by_key(
        &self,
        key: &str,
        token: &str,
        device_type: &str,
    ) -> Result<String, StoreError>;

    /// Fetch the Device Record for `key`; `None` when unknown (upstream
    /// `DeviceTokenByKey`'s "failed to get ..." error surfaced as data).
    fn device_record_by_key(&self, key: &str) -> Result<Option<DeviceRecord>, StoreError>;
}
