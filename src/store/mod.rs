//! Storage layer: a backend-agnostic `Store` trait with two implementations
//! — the embedded SQLite default (rusqlite, bundled) holding the single
//! file under the configured data directory, mirroring upstream's bbolt
//! deployment shape, and the PostgreSQL backend behind `--dsn`
//! (ticket 12, ADR-0005; the deliberate replacement for upstream's MySQL).
//! SQLite is used whenever `--dsn` is absent, so the default deployment
//! stays single-file with zero external dependencies.
//!
//! The per-device message store (ADR-0002) is bounded by a retention policy
//! ([`MessageRetention`], ticket 08): a per-device TTL (default 72h) and a
//! per-device cap (default 1000), both configurable via
//! `--sse-message-ttl-secs` / `--sse-message-cap` (0 = limit disabled).
//! Pruning is lazy — on insert, the inserting Device's expired and over-cap
//! rows are deleted under the same store lock (SQLite) or the same
//! transaction (PostgreSQL); there is no background sweeper. The replay
//! boundary is still exact: the replay scan (`Store::messages_after`) and
//! the retained count (`Store::count_messages`) ignore TTL-expired rows
//! even before the lazy pruning removed them, so an expired message is
//! never replayed and never counted, and a cap overflow only exists between
//! two inserts of the same Device. The `device_message_seq` counter is
//! independent of the messages table, so pruning never regresses or reuses
//! ids.

mod postgres;
mod sqlite;

pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;

use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("postgres error: {0}")]
    Postgres(#[from] ::postgres::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("store lock poisoned")]
    Poisoned,
}

impl StoreError {
    /// A uniqueness constraint hit — the mint path retries with fresh
    /// randomness. SQLite: SQLITE_CONSTRAINT_PRIMARYKEY 1555 / _UNIQUE 2067;
    /// PostgreSQL: SQLSTATE 23505 (unique_violation).
    pub fn is_unique_violation(&self) -> bool {
        match self {
            StoreError::Sqlite(rusqlite::Error::SqliteFailure(f, _)) => {
                f.extended_code == 1555 || f.extended_code == 2067
            }
            StoreError::Postgres(e) => e
                .as_db_error()
                .is_some_and(|db| db.code() == &::postgres::error::SqlState::UNIQUE_VIOLATION),
            _ => false,
        }
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

/// Per-Device retention policy of the message store (ADR-0002, ticket 08):
/// how much replay history a Device keeps. `ttl` prunes messages older than
/// the age; `cap` bounds the per-Device count, dropping oldest first (ids
/// are monotonic, so id order is age order). `None` disables the limit —
/// `Some(0)` must never be constructed (a zero cap would retain nothing).
///
/// The spec defaults live in [`MessageRetention::default`]; the additive
/// config flags map onto this via [`MessageRetention::from_limits`].
#[derive(Debug, Clone, Copy)]
pub struct MessageRetention {
    /// Maximum age of a retained message; `None` = no TTL pruning.
    pub ttl: Option<Duration>,
    /// Maximum number of retained messages per Device; `None` = no cap.
    pub cap: Option<i64>,
}

impl Default for MessageRetention {
    /// The spec defaults: 72h TTL, 1000 messages per Device.
    fn default() -> Self {
        Self {
            ttl: Some(Duration::from_secs(72 * 60 * 60)),
            cap: Some(1000),
        }
    }
}

impl MessageRetention {
    /// Map the additive config knobs (`--sse-message-ttl-secs` /
    /// `--sse-message-cap`, both 0 = limit disabled) onto the policy.
    pub fn from_limits(ttl_secs: u64, cap: u64) -> Self {
        Self {
            ttl: (ttl_secs > 0).then(|| Duration::from_secs(ttl_secs)),
            cap: (cap > 0).then_some(cap as i64),
        }
    }

    /// The TTL expiry cutoff for a message created `created_at`: retained
    /// iff `created_at >= cutoff`. Shared by the insert-time prune and the
    /// replay/count filters so all three draw the same line.
    pub fn ttl_cutoff_at(&self, created_at: i64) -> Option<i64> {
        self.ttl
            .map(|ttl| created_at.saturating_sub(ttl.as_secs() as i64))
    }
}

/// A Push to persist, before the store assigns its per-device monotonic id
/// (the exact payload the spec's `messages` table stores: title, subtitle,
/// body, Ext Params JSON, Device Key; `created_at` is assigned by the store).
#[derive(Debug, Clone)]
pub struct NewMessage {
    pub device_key: String,
    pub title: String,
    pub subtitle: String,
    pub body: String,
    /// Ext Params serialized as a JSON object (keys lowercased, values
    /// stringified per the push core's rules; `{}` when empty).
    pub ext_params: String,
}

/// A persisted Push: [`NewMessage`] plus the assigned per-device monotonic
/// id and the server-side creation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRecord {
    pub device_key: String,
    pub id: i64,
    pub title: String,
    pub subtitle: String,
    pub body: String,
    pub ext_params: String,
    pub created_at: i64,
}

/// Persistence for Devices (and, in later tickets, Stream Tokens and pending
/// messages). Sync on purpose: SQLite calls are short and the connection is
/// mutex-guarded; callers on the async runtime should keep using it for
/// cheap statements and switch hot paths to `spawn_blocking` if profiling
/// ever demands it.
pub trait Store: Send + Sync {
    /// Number of registered Devices; backs `/info`'s `devices` field.
    fn count_devices(&self) -> Result<i64, StoreError>;

    /// Number of minted Stream Tokens (all of them, revoked included — the
    /// `active_streams` stat covers liveness); backs `/info`'s `streams`.
    fn count_stream_tokens(&self) -> Result<i64, StoreError>;

    /// Number of retained (pending) messages across all Devices; backs
    /// `/info`'s `pending_messages`. Retention-aware (ticket 08): rows
    /// expired under the configured TTL never count, even before the lazy
    /// insert-time pruning removed them — pending_messages is the count of
    /// what replay could return. Cap overflow only exists between two
    /// inserts of the same Device (pruned on the next insert).
    fn count_messages(&self) -> Result<i64, StoreError>;

    /// Persist a Push to the per-device message store (ADR-0002) and return
    /// the full record. The per-device monotonic id is assigned here — from
    /// the `device_message_seq` counter, which never regresses even when
    /// retention pruning removes rows — and `created_at` is the assignment
    /// time. Callers persist BEFORE fan-out.
    ///
    /// Also performs the Device's lazy retention pruning (ticket 08): right
    /// after the insert, the Device's TTL-expired and over-cap rows are
    /// deleted under the same store lock.
    fn insert_message(&self, message: &NewMessage) -> Result<MessageRecord, StoreError>;

    /// Every retained message for `device_key` with per-device id >
    /// `after_id`, in ascending id order — the replay scan behind
    /// `Last-Event-ID` (ADR-0002, ticket 08). Retention bounds the result:
    /// rows expired under the configured TTL are never returned even before
    /// the lazy insert-time pruning removed them, and the per-Device cap
    /// bounds the count — so no artificial scan limit applies. An
    /// `after_id` older than the retained floor therefore replays from the
    /// oldest retained message.
    fn messages_after(
        &self,
        device_key: &str,
        after_id: i64,
    ) -> Result<Vec<MessageRecord>, StoreError>;

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
