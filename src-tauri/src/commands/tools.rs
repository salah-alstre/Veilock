//! Password generator, strength meter and clipboard helpers.

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::errors::{AppError, Result};
use crate::security::generator::{generate, GeneratorOptions};
use crate::security::strength::{estimate, StrengthReport};
use crate::storage::atomic::write_atomic;

use super::secret::Secret;
use super::{blocking, St};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateRequest {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

/// Generate a password with the OS CSPRNG. The value is returned to the UI because the user has to
/// see and choose it; it is not stored anywhere by this command.
#[tauri::command]
pub fn generate_password(req: GenerateRequest) -> Result<String> {
    let pw = generate(&GeneratorOptions {
        length: req.length,
        upper: req.upper,
        lower: req.lower,
        digits: req.digits,
        symbols: req.symbols,
        avoid_ambiguous: req.avoid_ambiguous,
    })?;
    Ok(pw.to_string())
}

/// Strength is computed in Rust so the meter and the generator agree.
#[tauri::command]
pub fn password_strength(password: Secret) -> StrengthReport {
    estimate(password.as_str())
}

/// Copy text the UI already shows (e.g. a generated password or a recovery key). Cleared after the
/// configured delay if the clipboard still holds it.
#[tauri::command]
pub fn clipboard_copy(state: St<'_>, text: Secret) -> Result<()> {
    let after = state
        .settings()
        .passwords
        .clipboard_clear_secs
        .map(|n| Duration::from_secs(u64::from(n)));
    state.clipboard.copy(text.as_str(), after)
}

/// Clear the clipboard if (and only if) this app put the current content there.
#[tauri::command]
pub fn clipboard_clear_owned(state: St<'_>) -> bool {
    state.clipboard.clear_if_owned()
}

/// Largest text a user-initiated export may write. A recovery key is ~70 bytes; this only exists
/// so the command cannot be turned into an arbitrary-size file writer.
const MAX_EXPORT_TEXT: usize = 64 * 1024;

/// Write `text` to a path the user picked in the native "Save as" dialog (used for saving a
/// recovery key). The dialog has already asked about overwriting; we still refuse directories and
/// relative paths, and write atomically so a crash never leaves a half-written key file.
fn write_text_export(path: &Path, text: &str) -> Result<()> {
    if text.len() > MAX_EXPORT_TEXT {
        return Err(AppError::InvalidInput("export text too large".into()));
    }
    if !path.is_absolute() {
        return Err(AppError::UnsafePath("export path must be absolute".into()));
    }
    if path.is_dir() {
        return Err(AppError::InvalidInput("export path is a directory".into()));
    }
    let dir_ok = path.parent().is_some_and(Path::is_dir);
    if !dir_ok {
        return Err(AppError::NotFound("export directory does not exist".into()));
    }
    write_atomic(path, text.as_bytes())
}

/// Save secret text (never logged) to a user-chosen file.
#[tauri::command]
pub async fn save_text_file(state: St<'_>, path: String, text: Secret) -> Result<()> {
    blocking(&state, move |_| {
        write_text_export(Path::new(&path), text.as_str())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn writes_text_exactly() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("key.txt");
        write_text_export(&p, "ABCDE-FGHIJ\nمفتاح").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "ABCDE-FGHIJ\nمفتاح");
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 1);
    }

    #[test]
    fn rejects_relative_directory_missing_parent_and_oversize() {
        let t = TempDir::new().unwrap();
        assert!(write_text_export(Path::new("rel.txt"), "x").is_err());
        assert!(write_text_export(t.path(), "x").is_err());
        assert!(write_text_export(&t.path().join("nope").join("k.txt"), "x").is_err());
        let big = "a".repeat(MAX_EXPORT_TEXT + 1);
        assert!(write_text_export(&t.path().join("k.txt"), &big).is_err());
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 0);
    }
}
