//! SQLite store for *non-secret* metadata: the list of known encrypted items, the list of vaults,
//! and the activity log.
//!
//! SQLite is not encrypted here and is never assumed to be. Nothing in this database can unlock
//! anything: no passwords, keys, recovery keys or file contents are stored. Item and vault names
//! and original paths are metadata that *do* reveal what the user protects; "Clear history" and
//! "Remove from history" delete them, and the Data & Privacy settings document this.

use crate::errors::{AppError, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    original_path TEXT,
    encrypted_path TEXT NOT NULL UNIQUE,
    original_size INTEGER NOT NULL,
    encrypted_size INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_opened_at INTEGER,
    format_version INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    has_saved_password INTEGER NOT NULL DEFAULT 0,
    has_recovery INTEGER NOT NULL DEFAULT 0,
    favorite INTEGER NOT NULL DEFAULT 0,
    file_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    icon TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_opened_at INTEGER,
    has_recovery INTEGER NOT NULL DEFAULT 0,
    has_saved_password INTEGER NOT NULL DEFAULT 0,
    favorite INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT,
    outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS activity_ts ON activity(ts DESC);
";

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ItemRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub original_path: Option<String>,
    pub encrypted_path: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub created_at: i64,
    pub last_opened_at: Option<i64>,
    pub format_version: u16,
    pub algorithm: String,
    pub has_saved_password: bool,
    pub has_recovery: bool,
    pub favorite: bool,
    pub file_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultRecord {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub description: String,
    pub created_at: i64,
    pub last_opened_at: Option<i64>,
    pub has_recovery: bool,
    pub has_saved_password: bool,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActivityRecord {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub subject: Option<String>,
    pub outcome: String,
}

pub struct Db {
    conn: Mutex<Connection>,
}

const ITEM_COLS: &str = "id, name, kind, original_path, encrypted_path, original_size, \
    encrypted_size, created_at, last_opened_at, format_version, algorithm, has_saved_password, \
    has_recovery, favorite, file_count";

fn item_from_row(r: &Row<'_>) -> rusqlite::Result<ItemRecord> {
    Ok(ItemRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: r.get(2)?,
        original_path: r.get(3)?,
        encrypted_path: r.get(4)?,
        original_size: r.get::<_, i64>(5)? as u64,
        encrypted_size: r.get::<_, i64>(6)? as u64,
        created_at: r.get(7)?,
        last_opened_at: r.get(8)?,
        format_version: r.get::<_, i64>(9)? as u16,
        algorithm: r.get(10)?,
        has_saved_password: r.get::<_, i64>(11)? != 0,
        has_recovery: r.get::<_, i64>(12)? != 0,
        favorite: r.get::<_, i64>(13)? != 0,
        file_count: r.get::<_, i64>(14)? as u64,
    })
}

const VAULT_COLS: &str = "id, name, icon, description, created_at, last_opened_at, \
    has_recovery, has_saved_password, favorite";

fn vault_from_row(r: &Row<'_>) -> rusqlite::Result<VaultRecord> {
    Ok(VaultRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        icon: r.get(2)?,
        description: r.get(3)?,
        created_at: r.get(4)?,
        last_opened_at: r.get(5)?,
        has_recovery: r.get::<_, i64>(6)? != 0,
        has_saved_password: r.get::<_, i64>(7)? != 0,
        favorite: r.get::<_, i64>(8)? != 0,
    })
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        let stored: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                r.get(0)
            })
            .optional()?;
        match stored {
            None => {
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES('schema', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )?;
            }
            Some(v) if v.parse::<i64>().ok() == Some(SCHEMA_VERSION) => {}
            Some(_) => {
                return Err(AppError::Unsupported(
                    "the metadata database was written by a newer version".into(),
                ))
            }
        }
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| AppError::Internal("database lock poisoned".into()))
    }

    // ---- items -------------------------------------------------------------------------

    /// Insert, or refresh the entry for the same encrypted path (re-encrypting a file keeps its
    /// favourite flag). Returns the stored record.
    pub fn upsert_item(&self, it: &ItemRecord) -> Result<ItemRecord> {
        let c = self.lock()?;
        c.execute(
            "INSERT INTO items(id, name, kind, original_path, encrypted_path, original_size, \
             encrypted_size, created_at, last_opened_at, format_version, algorithm, \
             has_saved_password, has_recovery, favorite, file_count) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15) \
             ON CONFLICT(encrypted_path) DO UPDATE SET name=excluded.name, kind=excluded.kind, \
             original_path=excluded.original_path, original_size=excluded.original_size, \
             encrypted_size=excluded.encrypted_size, created_at=excluded.created_at, \
             format_version=excluded.format_version, algorithm=excluded.algorithm, \
             has_saved_password=excluded.has_saved_password, has_recovery=excluded.has_recovery, \
             file_count=excluded.file_count",
            params![
                it.id,
                it.name,
                it.kind,
                it.original_path,
                it.encrypted_path,
                it.original_size as i64,
                it.encrypted_size as i64,
                it.created_at,
                it.last_opened_at,
                it.format_version as i64,
                it.algorithm,
                it.has_saved_password as i64,
                it.has_recovery as i64,
                it.favorite as i64,
                it.file_count as i64,
            ],
        )?;
        c.query_row(
            &format!("SELECT {ITEM_COLS} FROM items WHERE encrypted_path=?1"),
            params![it.encrypted_path],
            item_from_row,
        )
        .map_err(Into::into)
    }

    pub fn item(&self, id: &str) -> Result<Option<ItemRecord>> {
        let c = self.lock()?;
        Ok(c.query_row(
            &format!("SELECT {ITEM_COLS} FROM items WHERE id=?1"),
            params![id],
            item_from_row,
        )
        .optional()?)
    }

    pub fn item_by_path(&self, path: &str) -> Result<Option<ItemRecord>> {
        let c = self.lock()?;
        Ok(c.query_row(
            &format!("SELECT {ITEM_COLS} FROM items WHERE encrypted_path=?1"),
            params![path],
            item_from_row,
        )
        .optional()?)
    }

    pub fn recent_items(&self, limit: u32) -> Result<Vec<ItemRecord>> {
        let c = self.lock()?;
        let mut st = c.prepare(&format!(
            "SELECT {ITEM_COLS} FROM items ORDER BY COALESCE(last_opened_at, created_at) DESC, \
             rowid DESC LIMIT ?1"
        ))?;
        let rows = st.query_map(params![limit], item_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn favorite_items(&self) -> Result<Vec<ItemRecord>> {
        let c = self.lock()?;
        let mut st = c.prepare(&format!(
            "SELECT {ITEM_COLS} FROM items WHERE favorite=1 ORDER BY name COLLATE NOCASE"
        ))?;
        let rows = st.query_map([], item_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn search_items(&self, needle: &str, limit: u32) -> Result<Vec<ItemRecord>> {
        let c = self.lock()?;
        let like = format!("%{}%", escape_like(needle));
        let mut st = c.prepare(&format!(
            "SELECT {ITEM_COLS} FROM items WHERE name LIKE ?1 ESCAPE '\\' \
             ORDER BY COALESCE(last_opened_at, created_at) DESC LIMIT ?2"
        ))?;
        let rows = st.query_map(params![like, limit], item_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn touch_item(&self, id: &str) -> Result<()> {
        self.lock()?.execute(
            "UPDATE items SET last_opened_at=?2 WHERE id=?1",
            params![id, now()],
        )?;
        Ok(())
    }

    pub fn set_item_favorite(&self, id: &str, fav: bool) -> Result<()> {
        self.lock()?.execute(
            "UPDATE items SET favorite=?2 WHERE id=?1",
            params![id, fav as i64],
        )?;
        Ok(())
    }

    pub fn set_item_path(&self, id: &str, new_path: &str) -> Result<()> {
        self.lock()?.execute(
            "UPDATE items SET encrypted_path=?2 WHERE id=?1",
            params![id, new_path],
        )?;
        Ok(())
    }

    pub fn set_item_saved_password(&self, id: &str, saved: bool) -> Result<()> {
        self.lock()?.execute(
            "UPDATE items SET has_saved_password=?2 WHERE id=?1",
            params![id, saved as i64],
        )?;
        Ok(())
    }

    pub fn set_item_recovery(&self, id: &str, has: bool) -> Result<()> {
        self.lock()?.execute(
            "UPDATE items SET has_recovery=?2 WHERE id=?1",
            params![id, has as i64],
        )?;
        Ok(())
    }

    pub fn delete_item(&self, id: &str) -> Result<()> {
        self.lock()?
            .execute("DELETE FROM items WHERE id=?1", params![id])?;
        Ok(())
    }

    /// Forget every remembered item that is not a favourite.
    pub fn clear_recent_items(&self) -> Result<()> {
        self.lock()?
            .execute("DELETE FROM items WHERE favorite=0", [])?;
        Ok(())
    }

    pub fn item_count(&self) -> Result<u64> {
        let c = self.lock()?;
        Ok(c.query_row("SELECT COUNT(*) FROM items", [], |r| r.get::<_, i64>(0))? as u64)
    }

    // ---- vaults ------------------------------------------------------------------------

    pub fn insert_vault(&self, v: &VaultRecord) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO vaults(id, name, icon, description, created_at, last_opened_at, \
             has_recovery, has_saved_password, favorite) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                v.id,
                v.name,
                v.icon,
                v.description,
                v.created_at,
                v.last_opened_at,
                v.has_recovery as i64,
                v.has_saved_password as i64,
                v.favorite as i64
            ],
        )?;
        Ok(())
    }

    pub fn vault(&self, id: &str) -> Result<Option<VaultRecord>> {
        let c = self.lock()?;
        Ok(c.query_row(
            &format!("SELECT {VAULT_COLS} FROM vaults WHERE id=?1"),
            params![id],
            vault_from_row,
        )
        .optional()?)
    }

    pub fn vaults(&self) -> Result<Vec<VaultRecord>> {
        let c = self.lock()?;
        let mut st = c.prepare(&format!(
            "SELECT {VAULT_COLS} FROM vaults ORDER BY name COLLATE NOCASE"
        ))?;
        let rows = st.query_map([], vault_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn update_vault_info(
        &self,
        id: &str,
        name: &str,
        icon: &str,
        description: &str,
    ) -> Result<()> {
        self.lock()?.execute(
            "UPDATE vaults SET name=?2, icon=?3, description=?4 WHERE id=?1",
            params![id, name, icon, description],
        )?;
        Ok(())
    }

    pub fn touch_vault(&self, id: &str) -> Result<()> {
        self.lock()?.execute(
            "UPDATE vaults SET last_opened_at=?2 WHERE id=?1",
            params![id, now()],
        )?;
        Ok(())
    }

    pub fn set_vault_flags(
        &self,
        id: &str,
        has_recovery: Option<bool>,
        has_saved_password: Option<bool>,
        favorite: Option<bool>,
    ) -> Result<()> {
        let c = self.lock()?;
        if let Some(v) = has_recovery {
            c.execute(
                "UPDATE vaults SET has_recovery=?2 WHERE id=?1",
                params![id, v as i64],
            )?;
        }
        if let Some(v) = has_saved_password {
            c.execute(
                "UPDATE vaults SET has_saved_password=?2 WHERE id=?1",
                params![id, v as i64],
            )?;
        }
        if let Some(v) = favorite {
            c.execute(
                "UPDATE vaults SET favorite=?2 WHERE id=?1",
                params![id, v as i64],
            )?;
        }
        Ok(())
    }

    pub fn delete_vault(&self, id: &str) -> Result<()> {
        self.lock()?
            .execute("DELETE FROM vaults WHERE id=?1", params![id])?;
        Ok(())
    }

    // ---- activity ----------------------------------------------------------------------

    pub fn add_activity(&self, kind: &str, subject: Option<&str>, outcome: &str) -> Result<()> {
        let c = self.lock()?;
        c.execute(
            "INSERT INTO activity(ts, kind, subject, outcome) VALUES (?1,?2,?3,?4)",
            params![now(), kind, subject, outcome],
        )?;
        // Bound the log so it cannot grow without limit.
        c.execute(
            "DELETE FROM activity WHERE id <= (SELECT MAX(id) FROM activity) - 5000",
            [],
        )?;
        Ok(())
    }

    pub fn activity(&self, limit: u32) -> Result<Vec<ActivityRecord>> {
        let c = self.lock()?;
        let mut st = c.prepare(
            "SELECT id, ts, kind, subject, outcome FROM activity ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = st.query_map(params![limit], |r| {
            Ok(ActivityRecord {
                id: r.get(0)?,
                ts: r.get(1)?,
                kind: r.get(2)?,
                subject: r.get(3)?,
                outcome: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn clear_activity(&self) -> Result<()> {
        self.lock()?.execute("DELETE FROM activity", [])?;
        Ok(())
    }

    /// Remove everything this database knows (used by "Reset app").
    pub fn wipe(&self) -> Result<()> {
        let c = self.lock()?;
        c.execute_batch("DELETE FROM items; DELETE FROM vaults; DELETE FROM activity;")?;
        Ok(())
    }
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, path: &str) -> ItemRecord {
        ItemRecord {
            id: id.into(),
            name: format!("name-{id}"),
            kind: "file".into(),
            original_path: Some("C:\\x\\a.txt".into()),
            encrypted_path: path.into(),
            original_size: 10,
            encrypted_size: 600,
            created_at: 1000,
            last_opened_at: None,
            format_version: 1,
            algorithm: "AES-256-GCM".into(),
            has_saved_password: false,
            has_recovery: false,
            favorite: false,
            file_count: 1,
        }
    }

    #[test]
    fn upsert_keeps_favorite_and_id_for_same_path() {
        let db = Db::open_in_memory().unwrap();
        let first = db.upsert_item(&item("a", "p1")).unwrap();
        db.set_item_favorite(&first.id, true).unwrap();
        let mut again = item("b", "p1");
        again.encrypted_size = 999;
        let stored = db.upsert_item(&again).unwrap();
        assert_eq!(stored.id, "a");
        assert!(stored.favorite);
        assert_eq!(stored.encrypted_size, 999);
        assert_eq!(db.item_count().unwrap(), 1);
    }

    #[test]
    fn recent_orders_by_last_opened() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_item(&item("a", "p1")).unwrap();
        let mut b = item("b", "p2");
        b.created_at = 2000;
        db.upsert_item(&b).unwrap();
        assert_eq!(db.recent_items(10).unwrap()[0].id, "b");
        db.touch_item("a").unwrap();
        assert_eq!(db.recent_items(10).unwrap()[0].id, "a");
    }

    #[test]
    fn search_treats_wildcards_literally() {
        let db = Db::open_in_memory().unwrap();
        let mut a = item("a", "p1");
        a.name = "100%_done".into();
        db.upsert_item(&a).unwrap();
        db.upsert_item(&item("b", "p2")).unwrap();
        assert_eq!(db.search_items("%", 10).unwrap().len(), 1);
        assert_eq!(db.search_items("_d", 10).unwrap().len(), 1);
        assert_eq!(db.search_items("zzz", 10).unwrap().len(), 0);
    }

    #[test]
    fn clear_recent_keeps_favorites() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_item(&item("a", "p1")).unwrap();
        db.upsert_item(&item("b", "p2")).unwrap();
        db.set_item_favorite("a", true).unwrap();
        db.clear_recent_items().unwrap();
        let left = db.recent_items(10).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, "a");
    }

    #[test]
    fn vault_crud() {
        let db = Db::open_in_memory().unwrap();
        let v = VaultRecord {
            id: "v1".into(),
            name: "Taxes".into(),
            icon: "briefcase".into(),
            description: String::new(),
            created_at: 5,
            last_opened_at: None,
            has_recovery: false,
            has_saved_password: false,
            favorite: false,
        };
        db.insert_vault(&v).unwrap();
        db.update_vault_info("v1", "Taxes 2026", "folder", "d")
            .unwrap();
        db.set_vault_flags("v1", Some(true), None, Some(true))
            .unwrap();
        let got = db.vault("v1").unwrap().unwrap();
        assert_eq!(got.name, "Taxes 2026");
        assert!(got.has_recovery && got.favorite && !got.has_saved_password);
        db.delete_vault("v1").unwrap();
        assert!(db.vault("v1").unwrap().is_none());
    }

    #[test]
    fn activity_is_ordered_and_clearable() {
        let db = Db::open_in_memory().unwrap();
        db.add_activity("encrypt", Some("a.txt"), "ok").unwrap();
        db.add_activity("decrypt", Some("a.txt"), "WRONG_PASSWORD")
            .unwrap();
        let a = db.activity(10).unwrap();
        assert_eq!(a[0].kind, "decrypt");
        db.clear_activity().unwrap();
        assert!(db.activity(10).unwrap().is_empty());
    }
}
