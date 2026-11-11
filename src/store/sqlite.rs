//! SQLite implementation of [`Store`] (rusqlite with the `bundled` feature,
//! ADR-0005). The database is the single file `<data dir>/bark.db` — the same
//! placement and naming upstream uses for its bbolt file.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use super::{
    DeviceRecord, MessageRecord, MessageRetention, NewMessage, RevokeOutcome, Store, StoreError,
    StreamTokenRecord,
};

pub struct SqliteStore {
    conn: Mutex<Connection>,
    /// Per-Device retention policy (ticket 08): applied lazily at insert
    /// time and in the replay/count scans; see `MessageRetention`.
    retention: MessageRetention,
}

impl SqliteStore {
    /// Open (creating if needed) the SQLite file under `data_dir`. The data
    /// directory is created if missing, like upstream's `MkdirAll(0755)`.
    /// `retention` bounds the per-Device message store (ticket 08).
    pub fn open(data_dir: &Path, retention: MessageRetention) -> Result<Self, StoreError> {
        std::fs::create_dir_all(data_dir)?;
        let conn = Connection::open(data_dir.join("bark.db"))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS devices (
                key        TEXT PRIMARY KEY,
                token      TEXT,
                type       TEXT NOT NULL DEFAULT 'ios',
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stream_tokens (
                token_id     TEXT PRIMARY KEY,
                token        TEXT NOT NULL UNIQUE,
                device_key   TEXT NOT NULL,
                client_label TEXT NOT NULL DEFAULT '',
                created_at   INTEGER NOT NULL,
                revoked      INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_stream_tokens_device
                ON stream_tokens(device_key);
            -- Per-device message store (ADR-0002): one row per Push, keyed by
            -- (device_key, per-device monotonic id). `created_at` backs the
            -- per-device TTL and the cap pruning of the replay ticket (08);
            -- the index serves its created_at-ordered scans.
            CREATE TABLE IF NOT EXISTS messages (
                device_key  TEXT NOT NULL,
                id          INTEGER NOT NULL,
                title       TEXT NOT NULL DEFAULT '',
                subtitle    TEXT NOT NULL DEFAULT '',
                body        TEXT NOT NULL DEFAULT '',
                ext_params  TEXT NOT NULL DEFAULT '{}',
                created_at  INTEGER NOT NULL,
                PRIMARY KEY (device_key, id)
            );
            CREATE INDEX IF NOT EXISTS idx_messages_device_created
                ON messages(device_key, created_at);
            -- Per-device monotonic id source, independent of the messages
            -- table so retention pruning (ticket 08) can never regress ids:
            -- `next_id` is the id the NEXT insert will use.
            CREATE TABLE IF NOT EXISTS device_message_seq (
                device_key TEXT PRIMARY KEY,
                next_id    INTEGER NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            retention,
        })
    }
}

// Uniqueness-violation detection for stream-token inserts lives on
// StoreError (store/mod.rs) so the HTTP mint layer can retry on it.

impl Store for SqliteStore {
    fn count_devices(&self) -> Result<i64, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(conn.query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?)
    }

    fn count_stream_tokens(&self) -> Result<i64, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(conn.query_row("SELECT COUNT(*) FROM stream_tokens", [], |row| row.get(0))?)
    }

    fn count_messages(&self) -> Result<i64, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        // Retention-aware (ticket 08): pending_messages counts what replay
        // could return, so TTL-expired rows never count — even before the
        // lazy insert-time pruning removed them (MessageRetention docs).
        match self.retention.ttl_cutoff_at(crate::api::now_unix()) {
            None => Ok(conn.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))?),
            Some(cutoff) => Ok(conn.query_row(
                "SELECT COUNT(*) FROM messages WHERE created_at >= ?1",
                rusqlite::params![cutoff],
                |row| row.get(0),
            )?),
        }
    }

    fn insert_message(&self, message: &NewMessage) -> Result<MessageRecord, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        // Claim the next per-device monotonic id from the dedicated counter
        // (upsert + RETURNING in one statement), then insert the row. Both
        // statements run under the connection mutex, so id assignment and
        // insertion are atomic within the process; ids may skip (a crash
        // between the two statements burns one) but never repeat or regress.
        let id: i64 = conn.query_row(
            "INSERT INTO device_message_seq (device_key, next_id) VALUES (?1, 2)
             ON CONFLICT(device_key) DO UPDATE SET next_id = next_id + 1
             RETURNING next_id - 1",
            rusqlite::params![message.device_key],
            |row| row.get(0),
        )?;
        let created_at = crate::api::now_unix();
        conn.execute(
            "INSERT INTO messages
                (device_key, id, title, subtitle, body, ext_params, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                message.device_key,
                id,
                message.title,
                message.subtitle,
                message.body,
                message.ext_params,
                created_at,
            ],
        )?;
        // Lazy retention pruning (ticket 08, MessageRetention docs): the
        // inserting Device's TTL-expired and over-cap rows are deleted right
        // here, under the connection mutex — no background sweeper. The
        // fresh row is inserted first, so it is always the newest and can
        // never prune itself.
        if let Some(cutoff) = self.retention.ttl_cutoff_at(created_at) {
            conn.execute(
                "DELETE FROM messages WHERE device_key = ?1 AND created_at < ?2",
                rusqlite::params![message.device_key, cutoff],
            )?;
        }
        if let Some(cap) = self.retention.cap {
            // Keep the newest `cap` rows by id (id order is age order); drop
            // the rest of this Device's history.
            conn.execute(
                "DELETE FROM messages WHERE device_key = ?1 AND id NOT IN (
                     SELECT id FROM messages WHERE device_key = ?1
                     ORDER BY id DESC LIMIT ?2
                 )",
                rusqlite::params![message.device_key, cap],
            )?;
        }
        Ok(MessageRecord {
            device_key: message.device_key.clone(),
            id,
            title: message.title.clone(),
            subtitle: message.subtitle.clone(),
            body: message.body.clone(),
            ext_params: message.ext_params.clone(),
            created_at,
        })
    }

    fn messages_after(
        &self,
        device_key: &str,
        after_id: i64,
    ) -> Result<Vec<MessageRecord>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        // The PRIMARY KEY (device_key, id) index serves this scan directly;
        // ORDER BY id is the replay contract (ascending per-device order).
        // TTL-expired rows are invisible to the replay boundary even before
        // the lazy insert-time pruning removed them (MessageRetention docs).
        let cutoff = self.retention.ttl_cutoff_at(crate::api::now_unix());
        let sql = match cutoff {
            None => {
                "SELECT device_key, id, title, subtitle, body, ext_params, created_at
                 FROM messages WHERE device_key = ?1 AND id > ?2 ORDER BY id"
            }
            Some(_) => {
                "SELECT device_key, id, title, subtitle, body, ext_params, created_at
                 FROM messages WHERE device_key = ?1 AND id > ?2 AND created_at >= ?3
                 ORDER BY id"
            }
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = match cutoff {
            None => stmt
                .query_map(rusqlite::params![device_key, after_id], map_message)?
                .collect::<Result<Vec<_>, _>>()?,
            Some(cutoff) => stmt
                .query_map(rusqlite::params![device_key, after_id, cutoff], map_message)?
                .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(rows)
    }

    fn save_device_token_by_key(
        &self,
        key: &str,
        token: &str,
        device_type: &str,
    ) -> Result<String, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        // bbolt semantics: an empty key or one absent from the store counts
        // as a new registration, so a fresh shortuuid-style key is minted
        // under the same lock that saves the record.
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM devices WHERE key = ?1",
                rusqlite::params![key],
                |_| Ok(()),
            )
            .map(|_| true)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                other => Err(other),
            })?;
        let key = if key.is_empty() || !exists {
            crate::shortuuid::new_device_key()
        } else {
            key.to_string()
        };
        conn.execute(
            "INSERT INTO devices (key, token, type, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET
                token = excluded.token,
                type = excluded.type,
                updated_at = excluded.updated_at",
            rusqlite::params![
                key,
                token,
                super::normalize_device_type(device_type),
                crate::api::now_unix()
            ],
        )?;
        Ok(key)
    }

    fn device_record_by_key(&self, key: &str) -> Result<Option<DeviceRecord>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let record = conn
            .query_row(
                "SELECT token, type, updated_at FROM devices WHERE key = ?1",
                rusqlite::params![key],
                |row| {
                    Ok(DeviceRecord {
                        token: row.get(0)?,
                        device_type: row.get(1)?,
                        updated_at: row.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(record)
    }

    fn insert_stream_token(&self, record: &StreamTokenRecord) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        conn.execute(
            "INSERT INTO stream_tokens
                (token_id, token, device_key, client_label, created_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                record.token_id,
                record.token,
                record.device_key,
                record.client_label,
                record.created_at,
                record.revoked as i64,
            ],
        )?;
        Ok(())
    }

    fn stream_tokens_by_device(
        &self,
        device_key: &str,
    ) -> Result<Vec<StreamTokenRecord>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            // rowid = insertion order; creation order is part of the list
            // contract (docs/protocol.md examples rely on it).
            "SELECT token_id, token, device_key, client_label, created_at, revoked
             FROM stream_tokens WHERE device_key = ?1 ORDER BY rowid",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![device_key], map_stream_token)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn stream_token_by_id(
        &self,
        device_key: &str,
        token_id: &str,
    ) -> Result<Option<StreamTokenRecord>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        conn.query_row(
            "SELECT token_id, token, device_key, client_label, created_at, revoked
             FROM stream_tokens WHERE device_key = ?1 AND token_id = ?2",
            rusqlite::params![device_key, token_id],
            map_stream_token,
        )
        .optional()
        .map_err(StoreError::from)
    }

    fn stream_token_by_token(&self, token: &str) -> Result<Option<StreamTokenRecord>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        conn.query_row(
            "SELECT token_id, token, device_key, client_label, created_at, revoked
             FROM stream_tokens WHERE token = ?1",
            rusqlite::params![token],
            map_stream_token,
        )
        .optional()
        .map_err(StoreError::from)
    }

    fn revoke_stream_token(
        &self,
        device_key: &str,
        token_id: &str,
    ) -> Result<super::RevokeOutcome, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let revoked: Option<bool> = conn
            .query_row(
                "SELECT revoked FROM stream_tokens WHERE device_key = ?1 AND token_id = ?2",
                rusqlite::params![device_key, token_id],
                |row| row.get(0),
            )
            .optional()?;
        match revoked {
            None => Ok(RevokeOutcome::NotFound),
            Some(true) => Ok(RevokeOutcome::AlreadyRevoked),
            Some(false) => {
                conn.execute(
                    "UPDATE stream_tokens SET revoked = 1
                     WHERE device_key = ?1 AND token_id = ?2",
                    rusqlite::params![device_key, token_id],
                )?;
                Ok(RevokeOutcome::Revoked)
            }
        }
    }
}

/// Row mapper shared by the stream-token queries.
fn map_stream_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<StreamTokenRecord> {
    Ok(StreamTokenRecord {
        token_id: row.get(0)?,
        token: row.get(1)?,
        device_key: row.get(2)?,
        client_label: row.get(3)?,
        created_at: row.get(4)?,
        revoked: row.get::<_, i64>(5)? != 0,
    })
}

/// Row mapper for the message-store queries (replay scan, ticket 08).
fn map_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<MessageRecord> {
    Ok(MessageRecord {
        device_key: row.get(0)?,
        id: row.get(1)?,
        title: row.get(2)?,
        subtitle: row.get(3)?,
        body: row.get(4)?,
        ext_params: row.get(5)?,
        created_at: row.get(6)?,
    })
}
