//! Non-secret application settings, stored as JSON in `config/settings.json`.
//!
//! Nothing secret ever belongs here: the default encryption password lives inside the encrypted
//! credential vault, and this file only records *how* it may be used. The file is validated on
//! load so a hand-edited or corrupted config cannot put the app in an unsafe state (for example
//! a negative timeout or an unparsable shortcut); out-of-range values fall back to defaults.

use crate::errors::{AppError, Result};
use crate::storage::atomic::write_atomic;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_PANIC_SHORTCUT: &str = "Ctrl+Shift+L";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    System,
    Dark,
    Light,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    En,
    Ar,
}

/// What to do with the source after a verified encryption.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PostEncrypt {
    KeepOriginal,
    RemoveOriginal,
}

/// How the default encryption password may be used.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DefaultPasswordMode {
    Auto,
    Ask,
    RequireMaster,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct General {
    pub start_minimized: bool,
    pub lock_on_minimize: bool,
    pub remember_window_size: bool,
    pub window_width: Option<u32>,
    pub window_height: Option<u32>,
}

impl Default for General {
    fn default() -> Self {
        General {
            start_minimized: false,
            lock_on_minimize: false,
            remember_window_size: true,
            window_width: None,
            window_height: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Security {
    /// Seconds of inactivity before the app locks. `Some(0)` = as soon as the window loses focus,
    /// `None` = never (until the app closes).
    pub auto_lock_secs: Option<u32>,
    pub lock_on_session_lock: bool,
    pub lock_on_sleep: bool,
    pub panic_shortcut: String,
    pub require_master_for_sensitive: bool,
    pub require_master_to_reveal: bool,
    /// Lock vaults after the window has been in the background this long. `None` = disabled.
    pub background_lock_minutes: Option<u32>,
}

impl Default for Security {
    fn default() -> Self {
        Security {
            auto_lock_secs: Some(300),
            lock_on_session_lock: true,
            lock_on_sleep: true,
            panic_shortcut: DEFAULT_PANIC_SHORTCUT.to_string(),
            require_master_for_sensitive: true,
            require_master_to_reveal: true,
            background_lock_minutes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Encryption {
    pub default_output_dir: Option<String>,
    pub post_encrypt: PostEncrypt,
    pub default_password_mode: DefaultPasswordMode,
}

impl Default for Encryption {
    fn default() -> Self {
        Encryption {
            default_output_dir: None,
            post_encrypt: PostEncrypt::KeepOriginal,
            default_password_mode: DefaultPasswordMode::Ask,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Passwords {
    pub generator_length: u32,
    pub generator_upper: bool,
    pub generator_lower: bool,
    pub generator_digits: bool,
    pub generator_symbols: bool,
    pub generator_avoid_ambiguous: bool,
    /// Seconds until the clipboard is cleared. `None` = never.
    pub clipboard_clear_secs: Option<u32>,
}

impl Default for Passwords {
    fn default() -> Self {
        Passwords {
            generator_length: 20,
            generator_upper: true,
            generator_lower: true,
            generator_digits: true,
            generator_symbols: true,
            generator_avoid_ambiguous: false,
            clipboard_clear_secs: Some(30),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub version: u32,
    pub theme: Theme,
    pub language: Language,
    pub history_enabled: bool,
    pub onboarded: bool,
    /// The user chose "skip" at master-password setup.
    pub master_skipped: bool,
    pub general: General,
    pub security: Security,
    pub encryption: Encryption,
    pub passwords: Passwords,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            version: 1,
            theme: Theme::System,
            language: Language::En,
            history_enabled: true,
            onboarded: false,
            master_skipped: false,
            general: General::default(),
            security: Security::default(),
            encryption: Encryption::default(),
            passwords: Passwords::default(),
        }
    }
}

/// Auto-lock choices the UI offers; anything else is clamped on validate.
const MAX_LOCK_SECS: u32 = 24 * 3600;
const MAX_BACKGROUND_MINUTES: u32 = 24 * 60;

impl Settings {
    /// Bring every field into its legal range. Never fails: a bad value becomes the default.
    pub fn sanitize(&mut self) {
        let def = Settings::default();
        if let Some(s) = self.security.auto_lock_secs {
            if s > MAX_LOCK_SECS {
                self.security.auto_lock_secs = def.security.auto_lock_secs;
            }
        }
        if let Some(m) = self.security.background_lock_minutes {
            if m == 0 || m > MAX_BACKGROUND_MINUTES {
                self.security.background_lock_minutes = def.security.background_lock_minutes;
            }
        }
        if let Some(c) = self.passwords.clipboard_clear_secs {
            if c == 0 || c > 3600 {
                self.passwords.clipboard_clear_secs = def.passwords.clipboard_clear_secs;
            }
        }
        if !(8..=128).contains(&self.passwords.generator_length) {
            self.passwords.generator_length = def.passwords.generator_length;
        }
        let p = &mut self.passwords;
        // At least one character class must stay selected or the generator has no alphabet.
        if !(p.generator_upper || p.generator_lower || p.generator_digits || p.generator_symbols) {
            p.generator_lower = true;
        }
        if parse_shortcut(&self.security.panic_shortcut).is_err() {
            self.security.panic_shortcut = def.security.panic_shortcut;
        }
        for (w, lo, hi) in [
            (&mut self.general.window_width, 640, 10_000),
            (&mut self.general.window_height, 480, 10_000),
        ] {
            if let Some(v) = *w {
                if !(lo..=hi).contains(&v) {
                    *w = None;
                }
            }
        }
        if let Some(d) = &self.encryption.default_output_dir {
            if d.is_empty() || d.contains('\0') {
                self.encryption.default_output_dir = None;
            }
        }
    }

    /// Load settings; a missing file yields defaults, a damaged file is moved aside (so the user
    /// can inspect it) and defaults are used instead of refusing to start.
    pub fn load(path: &Path) -> Settings {
        let read = || -> Result<Settings> {
            let meta = fs::metadata(path)?;
            if meta.len() > MAX_CONFIG_BYTES {
                return Err(AppError::Corrupted("settings file too large".into()));
            }
            let bytes = fs::read(path)?;
            Ok(serde_json::from_slice(&bytes)?)
        };
        match read() {
            Ok(mut s) => {
                s.sanitize();
                s
            }
            Err(AppError::NotFound(_)) => Settings::default(),
            Err(_) if !path.exists() => Settings::default(),
            Err(_) => {
                let _ = fs::rename(path, path.with_extension("json.damaged"));
                Settings::default()
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut copy = self.clone();
        copy.sanitize();
        let bytes = serde_json::to_vec_pretty(&copy)?;
        write_atomic(path, &bytes)
    }
}

/// A global shortcut as `Mod+Mod+Key`. We validate the shape ourselves so the config can never
/// hold something the shortcut plugin would reject at start-up.
pub fn parse_shortcut(s: &str) -> Result<()> {
    let parts: Vec<&str> = s.split('+').map(str::trim).collect();
    if parts.len() < 2 || parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return Err(AppError::InvalidInput("shortcut".into()));
    }
    let (key, mods) = parts.split_last().expect("length checked above");
    let mut has_primary = false;
    for m in mods {
        match m.to_ascii_lowercase().as_str() {
            "ctrl" | "control" | "alt" | "shift" | "super" | "cmd" | "meta" => {
                if !matches!(m.to_ascii_lowercase().as_str(), "shift") {
                    has_primary = true;
                }
            }
            _ => return Err(AppError::InvalidInput("shortcut modifier".into())),
        }
    }
    // A bare Shift+Key would fire while typing capitals.
    if !has_primary {
        return Err(AppError::InvalidInput("shortcut needs Ctrl or Alt".into()));
    }
    let ok_key = key.len() == 1 && key.chars().all(|c| c.is_ascii_alphanumeric())
        || matches!(
            key.to_ascii_uppercase().as_str(),
            "F1" | "F2"
                | "F3"
                | "F4"
                | "F5"
                | "F6"
                | "F7"
                | "F8"
                | "F9"
                | "F10"
                | "F11"
                | "F12"
                | "SPACE"
                | "ESCAPE"
                | "HOME"
                | "END"
                | "PAGEUP"
                | "PAGEDOWN"
                | "INSERT"
                | "DELETE"
        );
    if !ok_key {
        return Err(AppError::InvalidInput("shortcut key".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn defaults_are_secure() {
        let s = Settings::default();
        assert_eq!(s.security.auto_lock_secs, Some(300));
        assert!(s.security.require_master_to_reveal);
        assert_eq!(s.encryption.post_encrypt, PostEncrypt::KeepOriginal);
        assert_eq!(s.theme, Theme::System);
        assert_eq!(s.security.panic_shortcut, "Ctrl+Shift+L");
    }

    #[test]
    fn round_trip_through_disk() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("settings.json");
        let mut s = Settings {
            theme: Theme::Dark,
            language: Language::Ar,
            ..Settings::default()
        };
        s.security.auto_lock_secs = None;
        s.save(&p).unwrap();
        assert_eq!(Settings::load(&p), s);
    }

    #[test]
    fn missing_file_gives_defaults() {
        let t = TempDir::new().unwrap();
        assert_eq!(
            Settings::load(&t.path().join("none.json")),
            Settings::default()
        );
    }

    #[test]
    fn partial_file_fills_missing_fields() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("s.json");
        fs::write(&p, br#"{"theme":"light"}"#).unwrap();
        let s = Settings::load(&p);
        assert_eq!(s.theme, Theme::Light);
        assert_eq!(s.security, Security::default());
    }

    #[test]
    fn damaged_file_is_moved_aside() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("s.json");
        fs::write(&p, b"{ not json").unwrap();
        assert_eq!(Settings::load(&p), Settings::default());
        assert!(!p.exists());
        assert!(t.path().join("s.json.damaged").exists());
    }

    #[test]
    fn hostile_values_are_sanitized() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("s.json");
        fs::write(
            &p,
            br#"{"security":{"autoLockSecs":999999999,"panicShortcut":"nonsense"},
                 "passwords":{"generatorLength":1,"generatorUpper":false,"generatorLower":false,
                 "generatorDigits":false,"generatorSymbols":false,"clipboardClearSecs":0}}"#,
        )
        .unwrap();
        let s = Settings::load(&p);
        assert_eq!(s.security.auto_lock_secs, Some(300));
        assert_eq!(s.security.panic_shortcut, "Ctrl+Shift+L");
        assert_eq!(s.passwords.generator_length, 20);
        assert!(s.passwords.generator_lower);
        assert_eq!(s.passwords.clipboard_clear_secs, Some(30));
    }

    #[test]
    fn shortcut_validation() {
        assert!(parse_shortcut("Ctrl+Shift+L").is_ok());
        assert!(parse_shortcut("Alt+F4").is_ok());
        assert!(parse_shortcut("L").is_err());
        assert!(parse_shortcut("Shift+L").is_err());
        assert!(parse_shortcut("Ctrl+").is_err());
        assert!(parse_shortcut("Ctrl+Foo").is_err());
        assert!(parse_shortcut("Hyper+L").is_err());
    }
}
