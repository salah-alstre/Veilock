//! Locks the app when Windows locks the session or goes to sleep.
//!
//! Not implemented yet on this build: `install` is a no-op. The settings `lock_on_session_lock`
//! and `lock_on_sleep` are stored but not yet acted on; see docs/KNOWN_LIMITATIONS in the
//! development notes.

use tauri::AppHandle;

pub fn install(_app: &AppHandle) {}
