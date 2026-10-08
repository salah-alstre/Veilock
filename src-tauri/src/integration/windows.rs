//! Optional per-user Windows integration: "start with Windows" and Explorer context-menu verbs.
//!
//! Everything lives under HKCU, so no administrator rights are needed and nothing outside the
//! user's own hive is touched. The registry key names below must match the cleanup in
//! `windows/installer-hooks.nsh`; a unit test checks that they do.

use std::path::Path;

use serde::Serialize;

use crate::branding;
use crate::errors::{AppError, Result};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntegrationStatus {
    /// False on platforms where none of this applies.
    pub supported: bool,
    pub autostart: bool,
    pub context_menu: bool,
    pub file_association: bool,
}

/// One Explorer verb: where it lives and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verb {
    pub key: String,
    pub label: String,
}

/// Verb name shared by every entry, e.g. `Veilock.Encrypt`.
fn verb_name(suffix: &str) -> String {
    format!("{}.{suffix}", branding::get().app_name)
}

pub fn verbs() -> Vec<Verb> {
    let app = &branding::get().app_name;
    let ext = &branding::get().file_extension;
    vec![
        Verb {
            key: format!(r"Software\Classes\*\shell\{}", verb_name("Encrypt")),
            label: format!("Protect with {app}"),
        },
        Verb {
            key: format!(r"Software\Classes\Directory\shell\{}", verb_name("Encrypt")),
            label: format!("Protect with {app}"),
        },
        Verb {
            key: format!(r"Software\Classes\.{ext}\shell\{}", verb_name("Open")),
            label: format!("Unlock with {app}"),
        },
    ]
}

/// Value name under the Run key.
pub fn run_value_name() -> String {
    branding::get().app_name.clone()
}

/// `"C:\path\app.exe"` — quoted so a path with spaces is one argument. A path containing a quote
/// cannot be represented safely and is rejected.
pub fn quote_exe(exe: &Path) -> Result<String> {
    let s = exe.to_string_lossy();
    if s.contains('"') || s.contains('\0') || s.is_empty() {
        return Err(AppError::InvalidInput("unsupported executable path".into()));
    }
    Ok(format!("\"{s}\""))
}

/// Command line for an Explorer verb: the item is passed as the first argument.
pub fn verb_command(exe: &Path) -> Result<String> {
    Ok(format!("{} \"%1\"", quote_exe(exe)?))
}

pub fn autostart_command(exe: &Path) -> Result<String> {
    quote_exe(exe)
}

#[cfg(windows)]
mod imp {
    use std::io;

    use winreg::enums::{HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    use super::*;

    fn hkcu() -> RegKey {
        RegKey::predef(HKEY_CURRENT_USER)
    }

    fn ignore_missing(r: io::Result<()>) -> io::Result<()> {
        match r {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    pub fn status(exe: &Path) -> IntegrationStatus {
        let autostart = autostart_command(exe)
            .ok()
            .and_then(|want| {
                let run = hkcu().open_subkey_with_flags(RUN_KEY, KEY_READ).ok()?;
                let got: String = run.get_value(run_value_name()).ok()?;
                Some(got == want)
            })
            .unwrap_or(false);

        let context_menu = verb_command(exe)
            .ok()
            .map(|want| {
                verbs().iter().all(|v| {
                    hkcu()
                        .open_subkey_with_flags(format!(r"{}\command", v.key), KEY_READ)
                        .ok()
                        .and_then(|k| k.get_value::<String, _>("").ok())
                        .is_some_and(|got| got == want)
                })
            })
            .unwrap_or(false);

        let file_association = RegKey::predef(HKEY_CLASSES_ROOT)
            .open_subkey_with_flags(format!(".{}", branding::get().file_extension), KEY_READ)
            .is_ok();

        IntegrationStatus {
            supported: true,
            autostart,
            context_menu,
            file_association,
        }
    }

    pub fn set_autostart(exe: &Path, enabled: bool) -> Result<()> {
        let run = hkcu().create_subkey_with_flags(RUN_KEY, KEY_WRITE)?.0;
        if enabled {
            run.set_value(run_value_name(), &autostart_command(exe)?)?;
        } else {
            ignore_missing(run.delete_value(run_value_name()))?;
        }
        Ok(())
    }

    pub fn set_context_menu(exe: &Path, enabled: bool) -> Result<()> {
        if enabled {
            let command = verb_command(exe)?;
            let icon = format!("{},0", exe.to_string_lossy());
            for v in verbs() {
                let (key, _) = hkcu().create_subkey(&v.key)?;
                key.set_value("", &v.label)?;
                key.set_value("Icon", &icon)?;
                let (cmd, _) = hkcu().create_subkey(format!(r"{}\command", v.key))?;
                cmd.set_value("", &command)?;
            }
        } else {
            for v in verbs() {
                ignore_missing(hkcu().delete_subkey_all(&v.key))?;
            }
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn status(_exe: &Path) -> IntegrationStatus {
        IntegrationStatus {
            supported: false,
            autostart: false,
            context_menu: false,
            file_association: false,
        }
    }

    pub fn set_autostart(_exe: &Path, _enabled: bool) -> Result<()> {
        Err(AppError::Unsupported("windows integration".into()))
    }

    pub fn set_context_menu(_exe: &Path, _enabled: bool) -> Result<()> {
        Err(AppError::Unsupported("windows integration".into()))
    }
}

pub use imp::{set_autostart, set_context_menu, status};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn exe_paths_are_quoted_and_quotes_rejected() {
        let p = PathBuf::from(r"C:\Program Files\Veilock\veilock.exe");
        assert_eq!(
            quote_exe(&p).unwrap(),
            r#""C:\Program Files\Veilock\veilock.exe""#
        );
        assert_eq!(
            verb_command(&p).unwrap(),
            r#""C:\Program Files\Veilock\veilock.exe" "%1""#
        );
        assert!(quote_exe(&PathBuf::from("C:\\bad\"name.exe")).is_err());
        assert!(quote_exe(&PathBuf::new()).is_err());
    }

    #[test]
    fn verbs_target_hkcu_classes_for_files_folders_and_containers() {
        let v = verbs();
        assert_eq!(v.len(), 3);
        assert!(v.iter().all(|x| x.key.starts_with(r"Software\Classes\")));
        assert!(v[0].key.contains(r"\*\shell\"));
        assert!(v[1].key.contains(r"\Directory\shell\"));
        assert!(v[2]
            .key
            .contains(&format!(".{}", branding::get().file_extension)));
    }

    #[test]
    fn installer_uninstall_hook_removes_exactly_these_keys() {
        let hooks = include_str!("../../windows/installer-hooks.nsh");
        for v in verbs() {
            assert!(
                hooks.contains(&v.key),
                "uninstall hook is missing {}",
                v.key
            );
        }
        assert!(hooks.contains(RUN_KEY));
        assert!(hooks.contains(&run_value_name()));
    }

    #[cfg(windows)]
    #[test]
    fn registry_round_trip_uses_only_the_current_user_hive() {
        // Uses a throw-away executable path so the test never touches the real registrations of an
        // installed copy: both toggles are restored to "off" at the end, which is also the default.
        let before = status(Path::new(r"C:\veilock-test\veilock.exe"));
        if before.autostart || before.context_menu {
            return; // a real install is configured; do not disturb it
        }
        let exe = Path::new(r"C:\veilock-test\veilock.exe");
        set_context_menu(exe, true).unwrap();
        assert!(status(exe).context_menu);
        set_context_menu(exe, false).unwrap();
        assert!(!status(exe).context_menu);
        set_context_menu(exe, false).unwrap(); // idempotent
        set_autostart(exe, true).unwrap();
        assert!(status(exe).autostart);
        set_autostart(exe, false).unwrap();
        assert!(!status(exe).autostart);
    }
}
