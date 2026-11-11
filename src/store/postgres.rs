//! PostgreSQL implementation of [`Store`] (ticket 12, ADR-0005): the second
//! storage backend behind the store trait, selected by `--dsn` /
//! `BARK_SERVER_DSN` (see `src/config.rs`). SQLite stays the default
//! embedded backend; PostgreSQL serves shared-infrastructure deployments.
//!
//! # The deliberate MySQL deviation (what ticket 10 must document)
//!
//! Upstream bark-server v2.4.0 activates its **MySQL** backend with
//! `--dsn` (`database/mysql.go`); this server re-uses that flag for
//! **PostgreSQL** — a conscious deviation (ADR-0005, confirmed with the
//! maintainer 2026-11-10): we give up direct database migration from an
//! existing upstream instance in favor of our own infrastructure choice.
//! Concretely, relative to upstream's `MySQL` backend:
//!
//! * **Flag surface**: upstream pairs `--dsn` with `--mysql-tls-*` flags
//!   (`NewMySQLWithTLS`); those stay dropped. A TLS-capable PostgreSQL
//!   connector (beyond the `sslmode=` parameters the DSN itself carries) is
//!   future work; the current connector is `NoTls`, which fits local and
//!   trusted-network deployments (the intended shared-infrastructure case
//!   runs PostgreSQL on a private network).
//! * **Schema**: upstream `devices` has an auto-increment `id` surrogate
//!   with `UNIQUE KEY (key)`; ours keys the table on the Device Key itself
//!   (`key TEXT PRIMARY KEY`), matching this server's SQLite shape. Upstream
//!   migrates old tables with a column-existence check
//!   (`information_schema.COLUMNS` + `ALTER TABLE`); our idempotent baseline
//!   is `CREATE TABLE/INDEX IF NOT EXISTS`, and any future column-level
//!   upgrade joins the same idempotent migration batch.
//! * **Key minting**: upstream `SaveDeviceTokenByKey` mints a fresh key only
//!   when `key == ""`. This server follows the SQLite impl's (bbolt-derived)
//!   semantics instead: an empty *or unknown* key counts as a new
//!   registration and is minted (pinned by `tests/register_seam.rs`).
//! * **Serverless backend**: upstream's serverless-env single-device store
//!   is dropped entirely (spec, Out of Scope).
//!
//! # Shape and concurrency semantics
//!
//! The [`Store`] trait is deliberately synchronous (see its docs), and the
//! sync rust-postgres client cannot even be *created* on an async runtime
//! thread (it builds a private tokio runtime and `block_on`s, which panics
//! under tokio). So this impl is the spawned-blocking-pool shape the trait
//! docs anticipate: ONE dedicated OS thread owns the `Client` and a job
//! channel; every Store method ships its work there and blocks on the reply
//! — a wait of the same nature as the SQLite impl's mutex wait, with no
//! runtime-on-runtime conflict.
//!
//! One worker = one connection = jobs run strictly sequentially, which is
//! exactly the SQLite impl's `Mutex<Connection>` serialization; SQLite's
//! atomicity guarantees become explicit **transactions** on that thread:
//!
//! * `insert_message` claims the per-device monotonic id from
//!   `device_message_seq` (upsert + `RETURNING`), inserts the row, and
//!   prunes the Device's TTL-expired and over-cap history **in one
//!   transaction** — the id assignment and insertion are atomic, ids may
//!   skip (a crash between claim and insert burns one) but never repeat or
//!   regress, and concurrent pushes to one Device serialize on the seq row
//!   lock (cross-process, unlike the SQLite mutex).
//! * `save_device_token_by_key` runs the existence check, key minting and
//!   the upsert in one transaction (the lock scope the SQLite impl gets
//!   from its mutex).
//! * `revoke_stream_token` locks the row with `SELECT … FOR UPDATE` inside
//!   a transaction — the same read-and-write-under-one-lock contract.
//!
//! Like the SQLite connection, a broken client is not transparently
//! reconnected: the process restarts as it would on a corrupted SQLite
//! file.
//!
//! PG-specific implementation notes: `stream_tokens` carries an
//! `IDENTITY` column (`seq`) because PostgreSQL has no SQLite-style `rowid`
//! to order by — it is the creation-order contract
//! (`Store::stream_tokens_by_device`). Retention pruning SQL is the same
//! shape as SQLite's (`id` order is age order, cap keeps the newest rows).
//! The schema needs PostgreSQL 10+ (`GENERATED … AS IDENTITY`). Timestamps
//! are unix-epoch seconds in `BIGINT`, like SQLite's `INTEGER`.

use std::sync::mpsc::{Receiver, Sender, SyncSender, sync_channel};
use std::thread;
use std::time::Duration;

use postgres::{Client, NoTls};

use super::{
    DeviceRecord, MessageRecord, MessageRetention, NewMessage, RevokeOutcome, Store, StoreError,
    StreamTokenRecord,
};

/// One unit of serialized store work, executed on the worker thread.
type Job = Box<dyn FnOnce(&mut Client) + Send>;

/// The full schema, executed idempotently on every open (CREATE ... IF NOT
/// EXISTS): a fresh database gets it all, an existing one is untouched.
/// Column-level upgrades (upstream's guarded-`ALTER TABLE` pattern) join
/// this list when a schema change ever ships.
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS devices (
        key        TEXT PRIMARY KEY,
        token      TEXT,
        type       TEXT NOT NULL DEFAULT 'ios',
        updated_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS stream_tokens (
        -- `seq` is the insertion-order surrogate for SQLite's rowid (the
        -- list-by-Device creation-order contract); it is never exposed.
        seq          BIGINT GENERATED ALWAYS AS IDENTITY,
        token_id     TEXT PRIMARY KEY,
        token        TEXT NOT NULL UNIQUE,
        device_key   TEXT NOT NULL,
        client_label TEXT NOT NULL DEFAULT '',
        created_at   BIGINT NOT NULL,
        revoked      BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS idx_stream_tokens_device
        ON stream_tokens(device_key);
    CREATE TABLE IF NOT EXISTS messages (
        device_key  TEXT NOT NULL,
        id          BIGINT NOT NULL,
        title       TEXT NOT NULL DEFAULT '',
        subtitle    TEXT NOT NULL DEFAULT '',
        body        TEXT NOT NULL DEFAULT '',
        ext_params  TEXT NOT NULL DEFAULT '{}',
        created_at  BIGINT NOT NULL,
        PRIMARY KEY (device_key, id)
    );
    CREATE INDEX IF NOT EXISTS idx_messages_device_created
        ON messages(device_key, created_at);
    CREATE TABLE IF NOT EXISTS device_message_seq (
        device_key TEXT PRIMARY KEY,
        next_id    BIGINT NOT NULL
    );";

pub struct PostgresStore {
    /// The worker's job queue; dropping it (store dropped) ends the thread
    /// and closes the connection.
    tx: Sender<Job>,
    /// Per-Device retention policy (ticket 08): applied lazily at insert
    /// time and in the replay/count scans; see `MessageRetention`. Copied
    /// into every job closure.
    retention: MessageRetention,
}

impl PostgresStore {
    /// Connect to `dsn` (a libpq URL like
    /// `postgres://user:pass@host:port/db` or a keyword/value string), run
    /// the idempotent schema migration, and start the worker. The startup
    /// connect is bounded so a wrong `--dsn` fails the boot fast. TLS:
    /// `NoTls` (see the module docs for the deliberate scope of this
    /// ticket). The connect itself happens on the worker thread — the sync
    /// client must never be touched from an async runtime thread (module
    /// docs).
    pub fn open(dsn: &str, retention: MessageRetention) -> Result<Self, StoreError> {
        let dsn = dsn.to_string();
        let (ready_tx, ready_rx) = sync_channel::<Result<(), StoreError>>(1);
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        thread::Builder::new()
            .name("bark-pg-store".into())
            .spawn(move || {
                let mut config: postgres::Config = match dsn.parse() {
                    Ok(config) => config,
                    Err(e) => {
                        let _ = ready_tx.send(Err(StoreError::Postgres(e)));
                        return;
                    }
                };
                config.connect_timeout(Duration::from_secs(10));
                let mut client = match config.connect(NoTls) {
                    Ok(client) => client,
                    Err(e) => {
                        let _ = ready_tx.send(Err(StoreError::Postgres(e)));
                        return;
                    }
                };
                if let Err(e) = client.batch_execute(SCHEMA) {
                    let _ = ready_tx.send(Err(StoreError::Postgres(e)));
                    return;
                }
                // Signal readiness only after the schema is in place; a
                // dropped ready_tx (opener gone) just ends the thread.
                if ready_tx.send(Ok(())).is_err() {
                    return;
                }
                // Serialized work loop: one connection, one job at a time —
                // the SQLite impl's Mutex<Connection> semantics. The loop
                // (and the connection) ends when the store is dropped.
                for job in rx {
                    job(&mut client);
                }
            })
            .map_err(|_| StoreError::Poisoned)?;
        // Block the boot on connect + migration; a wrong --dsn must fail
        // fast (upstream `logger.Fatalf`s on the same conditions).
        ready_rx.recv().map_err(|_| StoreError::Poisoned)??;
        Ok(Self { tx, retention })
    }

    /// Run one operation on the worker thread and wait for its result —
    /// the sync facade over the spawned blocking pool.
    fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Client) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let (reply_tx, reply_rx): (SyncSender<Result<T, StoreError>>, Receiver<_>) =
            sync_channel(1);
        self.tx
            .send(Box::new(move |client| {
                // A gone receiver (store half-dropped) must not poison the
                // worker; the result is simply discarded.
                let _ = reply_tx.send(f(client));
            }))
            .map_err(|_| StoreError::Poisoned)?;
        reply_rx.recv().map_err(|_| StoreError::Poisoned)?
    }
}

impl Store for PostgresStore {
    fn count_devices(&self) -> Result<i64, StoreError> {
        self.call(|client| {
            Ok(client
                .query_one("SELECT COUNT(*) FROM devices", &[])
                .map_err(StoreError::Postgres)?
                .get(0))
        })
    }

    fn count_stream_tokens(&self) -> Result<i64, StoreError> {
        self.call(|client| {
            Ok(client
                .query_one("SELECT COUNT(*) FROM stream_tokens", &[])
                .map_err(StoreError::Postgres)?
                .get(0))
        })
    }

    fn count_messages(&self) -> Result<i64, StoreError> {
        // Retention-aware (ticket 08): pending_messages counts what replay
        // could return, so TTL-expired rows never count — even before the
        // lazy insert-time pruning removed them (MessageRetention docs).
        let cutoff = self.retention.ttl_cutoff_at(crate::api::now_unix());
        self.call(move |client| {
            let row = match cutoff {
                None => client
                    .query_one("SELECT COUNT(*) FROM messages", &[])
                    .map_err(StoreError::Postgres)?,
                Some(cutoff) => client
                    .query_one(
                        "SELECT COUNT(*) FROM messages WHERE created_at >= $1",
                        &[&cutoff],
                    )
                    .map_err(StoreError::Postgres)?,
            };
            Ok(row.get(0))
        })
    }

    fn insert_message(&self, message: &NewMessage) -> Result<MessageRecord, StoreError> {
        let retention = self.retention;
        let message = message.clone();
        self.call(move |client| {
            // One transaction = the SQLite impl's connection-mutex scope:
            // claim the next per-device monotonic id (upsert + RETURNING in
            // one statement — the seq row lock serializes concurrent pushes
            // to the same Device), insert the row, prune the Device's
            // history. Ids may skip (a crash between claim and insert burns
            // one) but never repeat or regress.
            let mut tx = client.transaction().map_err(StoreError::Postgres)?;
            let id: i64 = tx
                .query_one(
                    "INSERT INTO device_message_seq (device_key, next_id) VALUES ($1, 2)
                     ON CONFLICT (device_key) DO UPDATE SET
                        next_id = device_message_seq.next_id + 1
                     RETURNING next_id - 1",
                    &[&message.device_key],
                )
                .map_err(StoreError::Postgres)?
                .get(0);
            let created_at = crate::api::now_unix();
            tx.execute(
                "INSERT INTO messages
                    (device_key, id, title, subtitle, body, ext_params, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &message.device_key,
                    &id,
                    &message.title,
                    &message.subtitle,
                    &message.body,
                    &message.ext_params,
                    &created_at,
                ],
            )
            .map_err(StoreError::Postgres)?;
            // Lazy retention pruning (ticket 08, MessageRetention docs):
            // the inserting Device's TTL-expired and over-cap rows are
            // deleted in the same transaction — no background sweeper. The
            // fresh row is inserted first, so it is always the newest and
            // can never prune itself.
            if let Some(cutoff) = retention.ttl_cutoff_at(created_at) {
                tx.execute(
                    "DELETE FROM messages WHERE device_key = $1 AND created_at < $2",
                    &[&message.device_key, &cutoff],
                )
                .map_err(StoreError::Postgres)?;
            }
            if let Some(cap) = retention.cap {
                // Keep the newest `cap` rows by id (id order is age order);
                // drop the rest of this Device's history.
                tx.execute(
                    "DELETE FROM messages WHERE device_key = $1 AND id NOT IN (
                         SELECT id FROM messages WHERE device_key = $1
                         ORDER BY id DESC LIMIT $2
                     )",
                    &[&message.device_key, &cap],
                )
                .map_err(StoreError::Postgres)?;
            }
            tx.commit().map_err(StoreError::Postgres)?;
            Ok(MessageRecord {
                device_key: message.device_key,
                id,
                title: message.title,
                subtitle: message.subtitle,
                body: message.body,
                ext_params: message.ext_params,
                created_at,
            })
        })
    }

    fn messages_after(
        &self,
        device_key: &str,
        after_id: i64,
    ) -> Result<Vec<MessageRecord>, StoreError> {
        // The PRIMARY KEY (device_key, id) index serves this scan directly;
        // ORDER BY id is the replay contract (ascending per-device order).
        // TTL-expired rows are invisible to the replay boundary even before
        // the lazy insert-time pruning removed them (MessageRetention docs).
        let cutoff = self.retention.ttl_cutoff_at(crate::api::now_unix());
        let device_key = device_key.to_string();
        self.call(move |client| {
            let rows = match cutoff {
                None => client
                    .query(
                        "SELECT device_key, id, title, subtitle, body, ext_params, created_at
                         FROM messages WHERE device_key = $1 AND id > $2 ORDER BY id",
                        &[&device_key, &after_id],
                    )
                    .map_err(StoreError::Postgres)?,
                Some(cutoff) => client
                    .query(
                        "SELECT device_key, id, title, subtitle, body, ext_params, created_at
                         FROM messages WHERE device_key = $1 AND id > $2 AND created_at >= $3
                         ORDER BY id",
                        &[&device_key, &after_id, &cutoff],
                    )
                    .map_err(StoreError::Postgres)?,
            };
            Ok(rows.into_iter().map(map_message).collect())
        })
    }

    fn save_device_token_by_key(
        &self,
        key: &str,
        token: &str,
        device_type: &str,
    ) -> Result<String, StoreError> {
        // bbolt semantics (as in the SQLite impl): an empty key or one
        // absent from the store counts as a new registration, so a fresh
        // shortuuid-style key is minted — here inside the transaction that
        // also saves the record (the mutex scope the SQLite impl has).
        let key = key.to_string();
        let token = token.to_string();
        let device_type = device_type.to_string();
        self.call(move |client| {
            let mut tx = client.transaction().map_err(StoreError::Postgres)?;
            let exists = tx
                .query_opt("SELECT 1 FROM devices WHERE key = $1", &[&key])
                .map_err(StoreError::Postgres)?
                .is_some();
            let key = if key.is_empty() || !exists {
                crate::shortuuid::new_device_key()
            } else {
                key
            };
            let updated_at = crate::api::now_unix();
            tx.execute(
                "INSERT INTO devices (key, token, type, updated_at)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (key) DO UPDATE SET
                    token = EXCLUDED.token,
                    type = EXCLUDED.type,
                    updated_at = EXCLUDED.updated_at",
                &[
                    &key,
                    &token,
                    &super::normalize_device_type(&device_type),
                    &updated_at,
                ],
            )
            .map_err(StoreError::Postgres)?;
            tx.commit().map_err(StoreError::Postgres)?;
            Ok(key)
        })
    }

    fn device_record_by_key(&self, key: &str) -> Result<Option<DeviceRecord>, StoreError> {
        let key = key.to_string();
        self.call(move |client| {
            let row = client
                .query_opt(
                    "SELECT token, type, updated_at FROM devices WHERE key = $1",
                    &[&key],
                )
                .map_err(StoreError::Postgres)?;
            Ok(row.map(|row| DeviceRecord {
                token: row.get(0),
                device_type: row.get(1),
                updated_at: row.get(2),
            }))
        })
    }

    fn insert_stream_token(&self, record: &StreamTokenRecord) -> Result<(), StoreError> {
        let record = record.clone();
        self.call(move |client| {
            client
                .execute(
                    "INSERT INTO stream_tokens
                        (token_id, token, device_key, client_label, created_at, revoked)
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    &[
                        &record.token_id,
                        &record.token,
                        &record.device_key,
                        &record.client_label,
                        &record.created_at,
                        &record.revoked,
                    ],
                )
                .map_err(StoreError::Postgres)?;
            Ok(())
        })
    }

    fn stream_tokens_by_device(
        &self,
        device_key: &str,
    ) -> Result<Vec<StreamTokenRecord>, StoreError> {
        let device_key = device_key.to_string();
        self.call(move |client| {
            // seq = insertion order (see SCHEMA); creation order is part of
            // the list contract (docs/protocol.md examples rely on it).
            let rows = client
                .query(
                    "SELECT token_id, token, device_key, client_label, created_at, revoked
                     FROM stream_tokens WHERE device_key = $1 ORDER BY seq",
                    &[&device_key],
                )
                .map_err(StoreError::Postgres)?;
            Ok(rows.into_iter().map(map_stream_token).collect())
        })
    }

    fn stream_token_by_id(
        &self,
        device_key: &str,
        token_id: &str,
    ) -> Result<Option<StreamTokenRecord>, StoreError> {
        let device_key = device_key.to_string();
        let token_id = token_id.to_string();
        self.call(move |client| {
            let row = client
                .query_opt(
                    "SELECT token_id, token, device_key, client_label, created_at, revoked
                     FROM stream_tokens WHERE device_key = $1 AND token_id = $2",
                    &[&device_key, &token_id],
                )
                .map_err(StoreError::Postgres)?;
            Ok(row.map(map_stream_token))
        })
    }

    fn stream_token_by_token(&self, token: &str) -> Result<Option<StreamTokenRecord>, StoreError> {
        let token = token.to_string();
        self.call(move |client| {
            let row = client
                .query_opt(
                    "SELECT token_id, token, device_key, client_label, created_at, revoked
                     FROM stream_tokens WHERE token = $1",
                    &[&token],
                )
                .map_err(StoreError::Postgres)?;
            Ok(row.map(map_stream_token))
        })
    }

    fn revoke_stream_token(
        &self,
        device_key: &str,
        token_id: &str,
    ) -> Result<super::RevokeOutcome, StoreError> {
        let device_key = device_key.to_string();
        let token_id = token_id.to_string();
        self.call(move |client| {
            // SELECT ... FOR UPDATE inside the transaction: the read and
            // the write happen under one row lock — the same
            // read-and-write atomicity the SQLite impl gets from its
            // connection mutex.
            let mut tx = client.transaction().map_err(StoreError::Postgres)?;
            let current = tx
                .query_opt(
                    "SELECT revoked FROM stream_tokens
                     WHERE device_key = $1 AND token_id = $2
                     FOR UPDATE",
                    &[&device_key, &token_id],
                )
                .map_err(StoreError::Postgres)?;
            let outcome = match current {
                None => RevokeOutcome::NotFound,
                Some(row) if row.get::<_, bool>(0) => RevokeOutcome::AlreadyRevoked,
                Some(_) => {
                    tx.execute(
                        "UPDATE stream_tokens SET revoked = TRUE
                         WHERE device_key = $1 AND token_id = $2",
                        &[&device_key, &token_id],
                    )
                    .map_err(StoreError::Postgres)?;
                    RevokeOutcome::Revoked
                }
            };
            tx.commit().map_err(StoreError::Postgres)?;
            Ok(outcome)
        })
    }
}

/// Row mapper shared by the stream-token queries.
fn map_stream_token(row: postgres::Row) -> StreamTokenRecord {
    StreamTokenRecord {
        token_id: row.get(0),
        token: row.get(1),
        device_key: row.get(2),
        client_label: row.get(3),
        created_at: row.get(4),
        revoked: row.get(5),
    }
}

/// Row mapper for the message-store queries (replay scan, ticket 08).
fn map_message(row: postgres::Row) -> MessageRecord {
    MessageRecord {
        device_key: row.get(0),
        id: row.get(1),
        title: row.get(2),
        subtitle: row.get(3),
        body: row.get(4),
        ext_params: row.get(5),
        created_at: row.get(6),
    }
}

// Uniqueness-violation detection for stream-token inserts lives on
// StoreError (store/mod.rs) so the HTTP mint layer can retry on it —
// PostgreSQL's SQLSTATE 23505 joins the SQLite codes there.
