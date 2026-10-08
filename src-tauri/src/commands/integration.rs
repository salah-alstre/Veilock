//! Settings > Windows Integration: current state and the two optional toggles.

use crate::errors::{AppError, Result};
use crate::integration::windows::{self, IntegrationStatus};

use super::{blocking, St};

fn exe() -> Result<std::path::PathBuf> {
    std::env::current_exe().map_err(|_| AppError::Internal("cannot locate executable".into()))
}

#[tauri::command]
pub async fn integration_status(state: St<'_>) -> Result<IntegrationStatus> {
    blocking(&state, |_| Ok(windows::status(&exe()?))).await
}

#[tauri::command]
pub async fn integration_set_autostart(state: St<'_>, enabled: bool) -> Result<IntegrationStatus> {
    blocking(&state, move |_| {
        let exe = exe()?;
        windows::set_autostart(&exe, enabled)?;
        Ok(windows::status(&exe))
    })
    .await
}

#[tauri::command]
pub async fn integration_set_context_menu(
    state: St<'_>,
    enabled: bool,
) -> Result<IntegrationStatus> {
    blocking(&state, move |_| {
        let exe = exe()?;
        windows::set_context_menu(&exe, enabled)?;
        Ok(windows::status(&exe))
    })
    .await
}
