//! SQLite implementation of [`Store`] (rusqlite with the `bundled` feature,
//! ADR-0005). The database is the single file `<data dir>/bark.db` — the same
//! placement and naming upstream uses for its bbolt file.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use super::{DeviceRecord, Store, StoreError};

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (creating if needed) the SQLite file under `data_dir`. The data
    /// directory is created if missing, like upstream's `MkdirAll(0755)`.
    pub fn open(data_dir: &Path) -> Result<Self, StoreError> {
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
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl Store for SqliteStore {
    fn count_devices(&self) -> Result<i64, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(conn.query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?)
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
}
