//! Tauri commands: the only surface the UI can reach. Every command validates its input, does
//! the sensitive work in Rust and returns plain data (never keys, never saved passwords).

use std::sync::Arc;

use tauri::State;

use crate::errors::{AppError, Result};

pub mod activity;
pub mod app;
pub mod files;
pub mod integration;
pub mod items;
pub mod passwords;
pub mod search;
pub mod secret;
pub mod state;
pub mod tools;
pub mod vaults;

use state::AppState;

/// Managed state as commands receive it.
pub type St<'a> = State<'a, Arc<AppState>>;

/// Run slow work (Argon2, file I/O) off the main thread. Sync Tauri commands run on the main
/// thread and would freeze the window.
pub async fn blocking<T, F>(state: &St<'_>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Arc<AppState>) -> Result<T> + Send + 'static,
{
    let s = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || f(&s))
        .await
        .map_err(|_| AppError::Internal("worker failed".into()))?
}
