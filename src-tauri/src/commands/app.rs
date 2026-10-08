//! App status, settings, the Master Password and locking.

use std::fs;
use std::time::Instant;

use serde::Serialize;
use tauri::AppHandle;

use crate::errors::{AppError, Result};
use crate::history::Event;
use crate::settings::{parse_shortcut, Settings};
use crate::vault::credentials::LockPhase;

use super::secret::{require_master, Secret};
use super::state::AppState;
use super::{blocking, St};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    pub version: &'static str,
    pub master_exists: bool,
    pub lock_phase: LockPhase,
    pub unlocked_vaults: usize,
    pub running_ops: usize,
    pub settings: Settings,
}

fn status_of(state: &AppState) -> AppStatus {
    AppStatus {
        version: env!("CARGO_PKG_VERSION"),
        master_exists: state.creds.exists(),
        lock_phase: state.creds.phase(),
        unlocked_vaults: state.vaults.unlocked_ids().len(),
        running_ops: state.running_ops(),
        settings: state.settings(),
    }
}

#[tauri::command]
pub fn app_status(state: St<'_>) -> AppStatus {
    status_of(&state)
}

#[tauri::command]
pub fn settings_update(app: AppHandle, state: St<'_>, settings: Settings) -> Result<Settings> {
    parse_shortcut(&settings.security.panic_shortcut)?;
    let old = state.settings().security.panic_shortcut;
    let saved = state.apply_settings(settings)?;
    if saved.security.panic_shortcut != old {
        // If the OS refuses the new combination (taken by another app), keep the old one rather
        // than leaving the user with no Panic Lock shortcut at all.
        if let Err(e) = crate::integration::shortcut::register(&app, &saved.security.panic_shortcut)
        {
            let _ = state.update_settings(|s| s.security.panic_shortcut = old.clone());
            let _ = crate::integration::shortcut::register(&app, &old);
            return Err(e);
        }
    }
    Ok(saved)
}

/// Finish onboarding. `skip_master` records that the user chose not to set up saved-password
/// features, so the app does not ask again on every launch.
#[tauri::command]
pub fn onboarding_complete(state: St<'_>, skip_master: bool) -> Result<Settings> {
    let master_exists = state.creds.exists();
    state.update_settings(|s| {
        s.onboarded = true;
        s.master_skipped = skip_master && !master_exists;
    })
}

// ----- master password ----------------------------------------------------------------------

#[tauri::command]
pub async fn master_create(state: St<'_>, master: Secret) -> Result<()> {
    blocking(&state, move |s| {
        s.creds.create(master.as_str())?;
        s.update_settings(|st| st.master_skipped = false)?;
        s.tracker.touch(Instant::now());
        s.record(Event::AppUnlock, None, "created");
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn master_unlock(state: St<'_>, master: Secret) -> Result<()> {
    blocking(&state, move |s| {
        let r = s.creds.unlock(master.as_str());
        match &r {
            Ok(()) => {
                s.tracker.touch(Instant::now());
                s.record(Event::AppUnlock, None, "ok");
            }
            Err(e) => s.record(Event::AppUnlock, None, &e.code().to_ascii_lowercase()),
        }
        r
    })
    .await
}

#[tauri::command]
pub fn app_lock(app: AppHandle, state: St<'_>) {
    state.lock_and_notify(&app, Event::AppLock);
}

#[tauri::command]
pub fn panic_lock(app: AppHandle, state: St<'_>) {
    state.lock_and_notify(&app, Event::PanicLock);
}

#[tauri::command]
pub async fn master_verify(state: St<'_>, master: Secret) -> Result<()> {
    blocking(&state, move |s| s.creds.verify_master(master.as_str())).await
}

#[tauri::command]
pub async fn master_change(state: St<'_>, current: Secret, new: Secret) -> Result<()> {
    blocking(&state, move |s| {
        s.creds.change_master(current.as_str(), new.as_str())?;
        s.record(Event::MasterChange, None, "ok");
        Ok(())
    })
    .await
}

/// Ask a running operation to stop. Partial output is cleaned up by the operation itself and the
/// source is left untouched. Returns whether such an operation was running.
#[tauri::command]
pub fn op_cancel(state: St<'_>, op_id: String) -> bool {
    state.cancel_op(&op_id)
}

/// Frontend activity ping. Only ever *delays* an auto-lock.
#[tauri::command]
pub fn activity_touch(state: St<'_>) {
    state.tracker.touch(Instant::now());
}

/// Delete all app data: settings, credential vault, history, metadata and every file vault stored
/// inside the app. Files the user encrypted elsewhere are never touched.
#[tauri::command]
pub async fn app_reset(state: St<'_>, confirm: bool, master: Option<Secret>) -> Result<()> {
    if !confirm {
        return Err(AppError::InvalidInput("confirmation required".into()));
    }
    blocking(&state, move |s| {
        if s.creds.exists() {
            // Prove knowledge of the master password; the vault must be unlocked for that.
            require_master(s, master.as_ref())?;
        }
        s.lock_everything();
        for rec in s.vaults.list()? {
            s.vaults.delete(&rec.record.id)?;
        }
        s.db.wipe()?;
        for p in [s.paths.credentials_file(), s.paths.settings_file()] {
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        s.apply_settings(Settings::default())?;
        s.paths.clear_cache();
        Ok(())
    })
    .await
}

/// Convenience used by the settings page so it can show "Configured / Not configured".
#[tauri::command]
pub fn default_password_status(state: St<'_>) -> Result<bool> {
    state.creds.has_default_password()
}

#[tauri::command]
pub async fn default_password_set(state: St<'_>, password: Secret, master: Secret) -> Result<()> {
    blocking(&state, move |s| {
        s.creds.verify_master(master.as_str())?;
        s.creds.set_default_password(Some(password.as_str()))?;
        s.record(Event::PasswordSaved, Some("default"), "ok");
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn default_password_clear(state: St<'_>, master: Secret) -> Result<()> {
    blocking(&state, move |s| {
        s.creds.verify_master(master.as_str())?;
        s.creds.set_default_password(None)?;
        s.record(Event::PasswordDeleted, Some("default"), "ok");
        Ok(())
    })
    .await
}
