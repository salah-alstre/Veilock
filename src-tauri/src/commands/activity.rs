//! Activity history. Entries are safe events only (kind, subject name, outcome code); nothing
//! here can carry a secret because `History::record` is never given one.

use crate::errors::Result;
use crate::storage::db::ActivityRecord;

use super::{blocking, St};

const MAX_LIMIT: u32 = 1000;

#[tauri::command]
pub async fn activity_list(state: St<'_>, limit: Option<u32>) -> Result<Vec<ActivityRecord>> {
    let limit = limit.unwrap_or(200).clamp(1, MAX_LIMIT);
    blocking(&state, move |s| s.history.list(limit)).await
}

/// Irreversible, so the UI asks first; the flag keeps a stray call from wiping the log.
#[tauri::command]
pub async fn activity_clear(state: St<'_>, confirm: bool) -> Result<()> {
    if !confirm {
        return Err(crate::errors::AppError::InvalidInput(
            "confirmation required".into(),
        ));
    }
    blocking(&state, |s| s.history.clear()).await
}
