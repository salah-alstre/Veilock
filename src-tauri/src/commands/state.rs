//! Shared application state and the helpers every command uses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::crypto::kdf::KdfParams;
use crate::errors::{AppError, Result};
use crate::filesystem::ops::OpControl;
use crate::history::{Event, History};
use crate::security::clipboard::SecureClipboard;
use crate::settings::Settings;
use crate::storage::db::Db;
use crate::storage::paths::AppPaths;
use crate::vault::credentials::CredentialStore;
use crate::vault::files::FileVaults;
use crate::vault::lock_monitor::{Policy, Tracker};

/// Event name the frontend listens on to learn the app was locked (auto, manual or panic).
pub const EVENT_LOCKED: &str = "veilock://locked";
/// Event name for operation progress.
pub const EVENT_PROGRESS: &str = "veilock://progress";

pub struct AppState {
    pub paths: AppPaths,
    pub db: Arc<Db>,
    pub history: History,
    pub creds: Arc<CredentialStore>,
    pub vaults: Arc<FileVaults>,
    pub clipboard: SecureClipboard,
    pub tracker: Arc<Tracker>,
    pub kdf: KdfParams,
    settings: Mutex<Settings>,
    ops: Mutex<HashMap<String, OpControl>>,
}

/// Auto-lock policy derived from settings.
pub fn policy_of(s: &Settings) -> Policy {
    Policy {
        inactivity_secs: s.security.auto_lock_secs,
        background_minutes: s.security.background_lock_minutes,
    }
}

impl AppState {
    /// Production constructor: real KDF cost, system clipboard.
    pub fn new(paths: AppPaths) -> Result<Self> {
        Self::build(paths, KdfParams::DEFAULT, SecureClipboard::system())
    }

    pub fn build(paths: AppPaths, kdf: KdfParams, clipboard: SecureClipboard) -> Result<Self> {
        let settings = Settings::load(&paths.settings_file());
        // Anything left in tmp is a partial result of an interrupted run.
        paths.clean_tmp();
        let db = Arc::new(Db::open(&paths.database_file())?);
        let history = History::new(Arc::clone(&db), settings.history_enabled);
        let creds = Arc::new(CredentialStore::with_kdf(paths.credentials_file(), kdf));
        let vaults = Arc::new(FileVaults::with_kdf(
            paths.vaults.clone(),
            Arc::clone(&db),
            kdf,
        ));
        let tracker = Arc::new(Tracker::new(policy_of(&settings), Instant::now()));
        Ok(AppState {
            paths,
            db,
            history,
            creds,
            vaults,
            clipboard,
            tracker,
            kdf,
            settings: Mutex::new(settings),
            ops: Mutex::new(HashMap::new()),
        })
    }

    // Poisoning only means another command panicked; the data are plain values, so keep going.
    fn settings_guard(&self) -> MutexGuard<'_, Settings> {
        self.settings.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn settings(&self) -> Settings {
        self.settings_guard().clone()
    }

    /// Validate, persist and apply new settings. Returns the sanitized result.
    pub fn apply_settings(&self, mut next: Settings) -> Result<Settings> {
        next.sanitize();
        next.save(&self.paths.settings_file())?;
        self.history.set_enabled(next.history_enabled);
        self.tracker.set_policy(policy_of(&next), Instant::now());
        *self.settings_guard() = next.clone();
        Ok(next)
    }

    /// Mutate settings in place (used for the few fields the backend itself changes).
    pub fn update_settings(&self, f: impl FnOnce(&mut Settings)) -> Result<Settings> {
        let mut next = self.settings();
        f(&mut next);
        self.apply_settings(next)
    }

    /// Record a safe history event. History failures must never fail the operation itself.
    pub fn record(&self, event: Event, subject: Option<&str>, outcome: &str) {
        self.history.record(event, subject, outcome);
    }

    fn ops_guard(&self) -> MutexGuard<'_, HashMap<String, OpControl>> {
        self.ops.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a cancellable operation under a UI-chosen id. The guard unregisters on drop.
    pub fn begin_op(self: &Arc<Self>, op_id: &str) -> Result<OpGuard> {
        if op_id.is_empty()
            || op_id.len() > 64
            || !op_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(AppError::InvalidInput("operation id".into()));
        }
        let mut ops = self.ops_guard();
        if ops.contains_key(op_id) {
            return Err(AppError::Busy);
        }
        let ctl = OpControl::new();
        ops.insert(op_id.to_owned(), ctl.clone());
        Ok(OpGuard {
            state: Arc::clone(self),
            id: op_id.to_owned(),
            ctl,
        })
    }

    pub fn cancel_op(&self, op_id: &str) -> bool {
        match self.ops_guard().get(op_id) {
            Some(c) => {
                c.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                true
            }
            None => false,
        }
    }

    pub fn cancel_all_ops(&self) {
        for c in self.ops_guard().values() {
            c.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    pub fn running_ops(&self) -> usize {
        self.ops_guard().len()
    }

    /// Lock everything that holds keys: credential vault, every file vault, and any clipboard
    /// content this app wrote. Used by manual lock, auto-lock, session lock/sleep and Panic Lock.
    /// Running operations are cancelled so no key stays alive in a worker thread.
    pub fn lock_everything(&self) {
        self.cancel_all_ops();
        self.creds.lock();
        self.vaults.lock_all();
        self.clipboard.clear_if_owned();
    }

    /// `lock_everything`, then tell the UI to show the lock screen.
    pub fn lock_and_notify(&self, app: &AppHandle, event: Event) {
        self.lock_everything();
        self.record(event, None, "ok");
        let _ = app.emit(EVENT_LOCKED, ());
    }
}

/// RAII registration of a running operation.
pub struct OpGuard {
    state: Arc<AppState>,
    id: String,
    pub ctl: OpControl,
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        self.state.ops_guard().remove(&self.id);
    }
}

/// Payload of the progress event.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent<'a> {
    pub op_id: &'a str,
    pub item_index: usize,
    pub item_count: usize,
    #[serde(flatten)]
    pub info: &'a crate::filesystem::ops::ProgressInfo,
}

pub fn emit_progress(app: &AppHandle, ev: &ProgressEvent<'_>) {
    let _ = app.emit(EVENT_PROGRESS, ev);
}
