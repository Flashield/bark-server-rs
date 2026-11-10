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

impl StoreError {
    /// A uniqueness constraint hit (SQLITE_CONSTRAINT_PRIMARYKEY 1555 /
    /// _UNIQUE 2067) — the mint path retries with fresh randomness.
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, StoreError::Sqlite(rusqlite::Error::SqliteFailure(f, _))
            if f.extended_code == 1555 || f.extended_code == 2067)
    }
}

/// Upstream device types (`database/database.go`); the device type selects
/// the APNs topic when pushing and defaults to `ios`. `stream` is this
/// server's token-less device type (ADR-0006 additive extension).
pub const DEVICE_TYPE_IOS: &str = "ios";
pub const DEVICE_TYPE_WATCHOS: &str = "watchos";
pub const DEVICE_TYPE_STREAM: &str = "stream";

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

/// A persisted Stream Token: the per-Realtime-Client read credential issued
/// at stream registration (ADR-0006), stored in its own table.
///
/// `token` is the opaque secret (presented verbatim on the SSE auth path,
/// ticket 07); `token_id` is its public, non-secret identifier used by the
/// list/revoke endpoints, so the full token never has to leave the server
/// again after creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamTokenRecord {
    pub token_id: String,
    pub token: String,
    pub device_key: String,
    pub client_label: String,
    pub created_at: i64,
    pub revoked: bool,
}

/// Result of a revoke request, distinguishing the three states the endpoint
/// maps onto 200 / 404 / 409.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The token existed unrevoked and is now revoked.
    Revoked,
    /// No such token for the Device (unknown id, or another Device's token).
    NotFound,
    /// The token was already revoked (idempotence is refused: the error
    /// signals "this token is already dead" to the caller).
    AlreadyRevoked,
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

    /// Persist a new Stream Token. `token_id` and `token` are minted by the
    /// caller; a uniqueness collision (statistically negligible with the
    /// CSPRNG values used) is the caller's problem to retry.
    fn insert_stream_token(&self, record: &StreamTokenRecord) -> Result<(), StoreError>;

    /// All Stream Tokens of a Device, in creation order.
    fn stream_tokens_by_device(
        &self,
        device_key: &str,
    ) -> Result<Vec<StreamTokenRecord>, StoreError>;

    /// Fetch one Stream Token by its public id, scoped to `device_key`: a
    /// token minted for another Device is not visible here (the revoke
    /// endpoint's 404, not a cross-Device leak).
    fn stream_token_by_id(
        &self,
        device_key: &str,
        token_id: &str,
    ) -> Result<Option<StreamTokenRecord>, StoreError>;

    /// Fetch one Stream Token by its secret — the lookup the SSE auth path
    /// (ticket 07) performs on a presented credential; the `revoked` flag on
    /// the returned record is the revocation guarantee this ticket enforces.
    fn stream_token_by_token(&self, token: &str) -> Result<Option<StreamTokenRecord>, StoreError>;

    /// Atomically mark the token `device_key`/`token_id` revoked (read and
    /// write happen under one store lock). Reports the pre-state via
    /// [`RevokeOutcome`].
    fn revoke_stream_token(
        &self,
        device_key: &str,
        token_id: &str,
    ) -> Result<RevokeOutcome, StoreError>;
}
