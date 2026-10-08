pub mod branding;
pub mod commands;
pub mod crypto;
pub mod errors;
pub mod filesystem;
pub mod history;
pub mod integration;
pub mod security;
pub mod settings;
pub mod storage;
pub mod vault;

use std::sync::Arc;

use tauri::{Emitter, Manager, WindowEvent};

use commands::state::AppState;
use history::Event;
use storage::paths::AppPaths;
use vault::lock_monitor;

/// Event carrying file paths another app instance (or Explorer double-click) asked us to open.
const EVENT_OPEN_FILES: &str = "veilock://open-files";

pub fn run() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        // A second launch (e.g. double-clicking another .veil) must not start a second process
        // holding a second set of unlocked keys; it hands its arguments to the running one.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
            let paths = commands::files::launch_paths(argv);
            if !paths.is_empty() {
                let _ = app.emit(EVENT_OPEN_FILES, paths);
            }
        }))
        .setup(|app| {
            let state = Arc::new(AppState::new(AppPaths::resolve()?)?);
            app.manage(Arc::clone(&state));

            let handle = app.handle().clone();
            let lock_state = Arc::clone(&state);
            let monitor = lock_monitor::spawn(Arc::clone(&state.tracker), move || {
                lock_state.lock_and_notify(&handle, Event::AppLock);
            });
            app.manage(monitor);

            // A taken shortcut must not stop the app from starting; the Settings page shows the
            // current value and the user can pick another.
            let _ = integration::shortcut::register(
                app.handle(),
                &state.settings().security.panic_shortcut,
            );
            integration::session::install(app.handle());

            // "Start minimized" applies to a plain launch; opening a file from Explorer should
            // still show the window the user is about to interact with.
            if state.settings().general.start_minimized
                && commands::files::launch_paths(std::env::args()).is_empty()
            {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.minimize();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            let app = window.app_handle();
            let Some(state) = app.try_state::<Arc<AppState>>() else {
                return;
            };
            let now = std::time::Instant::now();
            match event {
                WindowEvent::Focused(true) => state.tracker.focused(now),
                WindowEvent::Focused(false) => state.tracker.blurred(now),
                WindowEvent::Resized(_) => {
                    if window.is_minimized().unwrap_or(false)
                        && state.settings().general.lock_on_minimize
                    {
                        state.lock_and_notify(app, Event::AppLock);
                    }
                }
                // Keys must not outlive the window.
                WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed => {
                    state.lock_everything();
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app::app_status,
            commands::app::settings_update,
            commands::app::onboarding_complete,
            commands::app::master_create,
            commands::app::master_unlock,
            commands::app::master_verify,
            commands::app::master_change,
            commands::app::app_lock,
            commands::app::panic_lock,
            commands::app::activity_touch,
            commands::app::app_reset,
            commands::app::default_password_status,
            commands::app::default_password_set,
            commands::app::default_password_clear,
            commands::app::op_cancel,
            commands::passwords::passwords_list,
            commands::passwords::password_get,
            commands::passwords::password_add,
            commands::passwords::password_update,
            commands::passwords::password_delete,
            commands::passwords::password_reveal,
            commands::passwords::password_copy,
            commands::files::take_launch_paths,
            commands::files::inspect_paths,
            commands::files::encrypt_run,
            commands::files::decrypt_run,
            commands::items::items_recent,
            commands::items::items_favorites,
            commands::items::item_get,
            commands::items::item_for_path,
            commands::items::item_favorite,
            commands::items::item_remove_from_history,
            commands::items::recent_clear,
            commands::items::item_rename,
            commands::items::item_move,
            commands::items::item_delete_file,
            commands::items::item_reveal_in_folder,
            commands::items::item_change_password,
            commands::items::item_set_recovery,
            commands::items::item_remove_recovery,
            commands::tools::generate_password,
            commands::tools::password_strength,
            commands::tools::clipboard_copy,
            commands::tools::clipboard_clear_owned,
            commands::tools::save_text_file,
            commands::vaults::vaults_list,
            commands::vaults::vault_get,
            commands::vaults::vault_items,
            commands::vaults::vault_create,
            commands::vaults::vault_unlock,
            commands::vaults::vault_lock,
            commands::vaults::vault_rename,
            commands::vaults::vault_favorite,
            commands::vaults::vault_change_password,
            commands::vaults::vault_set_recovery,
            commands::vaults::vault_remove_recovery,
            commands::vaults::vault_delete,
            commands::vaults::vault_add_items,
            commands::vaults::vault_extract_item,
            commands::vaults::vault_remove_item,
            commands::vaults::vault_export,
            commands::vaults::vault_import,
            commands::activity::activity_list,
            commands::activity::activity_clear,
            commands::search::search_all,
            commands::integration::integration_status,
            commands::integration::integration_set_autostart,
            commands::integration::integration_set_context_menu,
        ])
        .run(tauri::generate_context!());
    if result.is_err() {
        // There is no UI yet to report to; the process exits non-zero so the failure is visible
        // to the installer / launcher.
        std::process::exit(1);
    }
}
