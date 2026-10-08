//! Saved-password commands. The list never contains passwords; revealing or copying one is
//! gated by the "require master password" setting and checked here, not in the UI.

use std::time::Duration;

use crate::errors::{AppError, Result};
use crate::history::Event;
use crate::vault::credentials::{EditableEntry, EntryUpdate, EntryView, NewEntry};

use super::secret::{require_master, Secret};
use super::state::AppState;
use super::{blocking, St};

/// Gate for anything that exposes a saved password's value.
fn authorize_exposure(state: &AppState, master: Option<&Secret>) -> Result<()> {
    if state.settings().security.require_master_to_reveal {
        require_master(state, master)?;
    }
    Ok(())
}

#[tauri::command]
pub fn passwords_list(state: St<'_>) -> Result<Vec<EntryView>> {
    state.creds.list()
}

#[tauri::command]
pub fn password_get(state: St<'_>, id: String) -> Result<EditableEntry> {
    state.creds.entry_for_edit(&id)
}

#[tauri::command]
pub async fn password_add(state: St<'_>, entry: NewEntry) -> Result<EntryView> {
    blocking(&state, move |s| {
        let view = s.creds.add(entry)?;
        s.record(Event::PasswordSaved, Some(&view.name), "ok");
        Ok(view)
    })
    .await
}

#[tauri::command]
pub async fn password_update(state: St<'_>, id: String, update: EntryUpdate) -> Result<EntryView> {
    blocking(&state, move |s| s.creds.update(&id, update)).await
}

#[tauri::command]
pub async fn password_delete(state: St<'_>, id: String, confirm: bool) -> Result<()> {
    if !confirm {
        return Err(AppError::InvalidInput("confirmation required".into()));
    }
    blocking(&state, move |s| {
        s.creds.delete(&id)?;
        s.record(Event::PasswordDeleted, None, "ok");
        Ok(())
    })
    .await
}

/// Returns the saved password for display. This is the one place a saved password crosses to the
/// UI, and only after the master password has been re-checked when the setting asks for it.
#[tauri::command]
pub async fn password_reveal(state: St<'_>, id: String, master: Option<Secret>) -> Result<String> {
    blocking(&state, move |s| {
        authorize_exposure(s, master.as_ref())?;
        let pw = s.creds.reveal(&id)?;
        Ok(pw.to_string())
    })
    .await
}

/// Copy a saved password to the clipboard without it ever reaching the UI. The clipboard is
/// cleared after the configured delay, but only if it still holds this value.
#[tauri::command]
pub async fn password_copy(state: St<'_>, id: String, master: Option<Secret>) -> Result<()> {
    blocking(&state, move |s| {
        authorize_exposure(s, master.as_ref())?;
        let pw = s.creds.use_entry(&id)?;
        let after = s
            .settings()
            .passwords
            .clipboard_clear_secs
            .map(|n| Duration::from_secs(u64::from(n)));
        s.clipboard.copy(pw.as_str(), after)
    })
    .await
}
