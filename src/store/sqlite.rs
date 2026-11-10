//! SQLite implementation of [`Store`] (rusqlite with the `bundled` feature,
//! ADR-0005). The database is the single file `<data dir>/bark.db` — the same
//! placement and naming upstream uses for its bbolt file.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::Connection;

use super::{Store, StoreError};

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
}
