//! Where the application keeps its files.
//!
//! Everything lives under the per-user data directory (`%APPDATA%` on Windows), never inside the
//! project or installation directory. The sub-directories separate data by sensitivity so that
//! "Clear history" or "empty cache" can never touch key material:
//!
//! * `config/` – non-secret settings (JSON)
//! * `vault/`  – the encrypted credential file and encrypted file vaults
//! * `db/`     – SQLite metadata (recent items, vault list, activity)
//! * `cache/`  – disposable data
//! * `tmp/`    – scratch space; emptied at start-up

use crate::errors::{AppError, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub const APP_DIR_NAME: &str = "app.veilock.desktop";

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub root: PathBuf,
    pub config: PathBuf,
    pub vault: PathBuf,
    pub vaults: PathBuf,
    pub db: PathBuf,
    pub cache: PathBuf,
    pub tmp: PathBuf,
}

impl AppPaths {
    /// Resolve the per-user location and create the directory tree.
    pub fn resolve() -> Result<Self> {
        let base = dirs::data_dir()
            .ok_or_else(|| AppError::Storage("no per-user data directory available".into()))?;
        Self::at(base.join(APP_DIR_NAME))
    }

    /// Use an explicit root (tests use a temp dir).
    pub fn at(root: PathBuf) -> Result<Self> {
        let p = AppPaths {
            config: root.join("config"),
            vault: root.join("vault"),
            vaults: root.join("vault").join("vaults"),
            db: root.join("db"),
            cache: root.join("cache"),
            tmp: root.join("tmp"),
            root,
        };
        for d in [
            &p.root, &p.config, &p.vault, &p.vaults, &p.db, &p.cache, &p.tmp,
        ] {
            fs::create_dir_all(d)?;
        }
        Ok(p)
    }

    pub fn settings_file(&self) -> PathBuf {
        self.config.join("settings.json")
    }

    pub fn credentials_file(&self) -> PathBuf {
        self.vault.join("credentials.vlkc")
    }

    pub fn database_file(&self) -> PathBuf {
        self.db.join("metadata.sqlite3")
    }

    pub fn vault_dir(&self, id: &str) -> PathBuf {
        self.vaults.join(id)
    }

    /// Remove leftovers of interrupted operations. Called once at start-up.
    pub fn clean_tmp(&self) {
        clear_dir(&self.tmp);
    }

    pub fn clear_cache(&self) {
        clear_dir(&self.cache);
    }
}

fn clear_dir(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        // Best effort: a file that is in use simply stays until the next start.
        if p.is_dir() {
            let _ = fs::remove_dir_all(&p);
        } else {
            let _ = fs::remove_file(&p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_separated_directories() {
        let t = TempDir::new().unwrap();
        let p = AppPaths::at(t.path().join("app")).unwrap();
        for d in [&p.config, &p.vault, &p.vaults, &p.db, &p.cache, &p.tmp] {
            assert!(d.is_dir());
        }
        assert_ne!(p.config, p.vault);
        assert_ne!(p.db, p.vault);
    }

    #[test]
    fn clean_tmp_removes_leftovers_only_in_tmp() {
        let t = TempDir::new().unwrap();
        let p = AppPaths::at(t.path().join("app")).unwrap();
        fs::write(p.tmp.join("x.tmp"), b"1").unwrap();
        fs::create_dir(p.tmp.join("d")).unwrap();
        fs::write(p.config.join("keep"), b"1").unwrap();
        p.clean_tmp();
        assert_eq!(fs::read_dir(&p.tmp).unwrap().count(), 0);
        assert!(p.config.join("keep").exists());
    }
}
