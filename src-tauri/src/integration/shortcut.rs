//! Global Panic Lock shortcut.

use std::sync::Arc;

use tauri::{AppHandle, Manager};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};

use crate::commands::state::AppState;
use crate::errors::{AppError, Result};
use crate::history::Event;

/// Replace the registered Panic Lock shortcut with `accelerator`.
///
/// The handler only calls `lock_and_notify`, which never depends on the UI being responsive:
/// Panic Lock must work even if the webview is stuck.
pub fn register(app: &AppHandle, accelerator: &str) -> Result<()> {
    let gs = app.global_shortcut();
    gs.unregister_all()
        .map_err(|_| AppError::Internal("shortcut reset failed".into()))?;
    let handle = app.clone();
    gs.on_shortcut(accelerator, move |_app, _shortcut, ev| {
        if ev.state() == ShortcutState::Pressed {
            if let Some(state) = handle.try_state::<Arc<AppState>>() {
                state.lock_and_notify(&handle, Event::PanicLock);
            }
        }
    })
    // Most likely cause: another application already owns this combination.
    .map_err(|_| AppError::InvalidInput("shortcut unavailable".into()))
}
