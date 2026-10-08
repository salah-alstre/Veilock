//! Clipboard handling with auto-clear.
//!
//! Secrets are written to the clipboard from Rust, so they never pass through the webview. The
//! app remembers only a *salted SHA-256* of what it wrote (never the value) and a generation
//! counter. When the timer fires, or Panic Lock runs, the clipboard is cleared only if it still
//! holds exactly what we wrote: if the user has since copied something else, that is left alone.
//!
//! Limitation: other programs (and Windows clipboard history, if the user has enabled it and the
//! exclusion hint is ignored) can read the clipboard while the secret is on it.

use crate::errors::{AppError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;
use subtle::ConstantTimeEq;

pub trait ClipboardBackend: Send + Sync {
    /// Place text on the clipboard, asking the OS to keep it out of history/cloud sync where it
    /// supports that.
    fn write(&self, text: &str) -> Result<()>;
    fn read(&self) -> Result<Option<String>>;
    fn clear(&self) -> Result<()>;
}

/// The real system clipboard.
pub struct SystemClipboard;

fn cb_err(_: arboard::Error) -> AppError {
    // The arboard error text is not useful to the user and may vary by platform.
    AppError::Io("clipboard unavailable".into())
}

impl ClipboardBackend for SystemClipboard {
    fn write(&self, text: &str) -> Result<()> {
        let mut cb = arboard::Clipboard::new().map_err(cb_err)?;
        #[cfg(windows)]
        {
            use arboard::SetExtWindows;
            cb.set()
                .exclude_from_history()
                .exclude_from_cloud()
                .text(text.to_owned())
                .map_err(cb_err)
        }
        #[cfg(not(windows))]
        {
            cb.set_text(text.to_owned()).map_err(cb_err)
        }
    }

    fn read(&self) -> Result<Option<String>> {
        let mut cb = arboard::Clipboard::new().map_err(cb_err)?;
        match cb.get_text() {
            Ok(t) => Ok(Some(t)),
            // Empty or non-text clipboard: nothing of ours is on it.
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(cb_err(e)),
        }
    }

    fn clear(&self) -> Result<()> {
        let mut cb = arboard::Clipboard::new().map_err(cb_err)?;
        cb.clear().map_err(cb_err)
    }
}

struct State {
    generation: u64,
    owned: Option<[u8; 32]>,
}

pub struct SecureClipboard {
    backend: Arc<dyn ClipboardBackend>,
    state: Arc<Mutex<State>>,
    /// Per-process salt so the stored digest can't be matched against a precomputed table.
    salt: [u8; 16],
}

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    // A poisoned lock only means another thread panicked; the data is still consistent.
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl SecureClipboard {
    pub fn new(backend: Arc<dyn ClipboardBackend>) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        SecureClipboard {
            backend,
            state: Arc::new(Mutex::new(State {
                generation: 0,
                owned: None,
            })),
            salt,
        }
    }

    pub fn system() -> Self {
        Self::new(Arc::new(SystemClipboard))
    }

    fn digest(&self, text: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.salt);
        h.update(text.as_bytes());
        h.finalize().into()
    }

    /// Copy `text` and, if `clear_after` is set, schedule clearing it.
    pub fn copy(&self, text: &str, clear_after: Option<Duration>) -> Result<()> {
        let generation = {
            let mut st = lock(&self.state);
            self.backend.write(text)?;
            st.generation += 1;
            st.owned = Some(self.digest(text));
            st.generation
        };
        if let Some(delay) = clear_after {
            let backend = Arc::clone(&self.backend);
            let state = Arc::clone(&self.state);
            let salt = self.salt;
            thread::spawn(move || {
                thread::sleep(delay);
                let mut st = lock(&state);
                // A newer copy (or an explicit clear) superseded this timer.
                if st.generation != generation {
                    return;
                }
                clear_if_owned(&mut st, &*backend, &salt);
            });
        }
        Ok(())
    }

    /// Clear the clipboard if it still holds what the app wrote. Used by Panic Lock and by the
    /// lock screen. Returns whether anything was cleared.
    pub fn clear_if_owned(&self) -> bool {
        let mut st = lock(&self.state);
        st.generation += 1; // cancels any pending timer
        clear_if_owned(&mut st, &*self.backend, &self.salt)
    }
}

fn clear_if_owned(st: &mut State, backend: &dyn ClipboardBackend, salt: &[u8; 16]) -> bool {
    let Some(owned) = st.owned.take() else {
        return false;
    };
    let Ok(Some(current)) = backend.read() else {
        return false;
    };
    let mut h = Sha256::new();
    h.update(salt);
    h.update(current.as_bytes());
    let now: [u8; 32] = h.finalize().into();
    if bool::from(now.ct_eq(&owned)) {
        backend.clear().is_ok()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Mock(Mutex<Option<String>>);

    impl ClipboardBackend for Mock {
        fn write(&self, t: &str) -> Result<()> {
            *self.0.lock().unwrap() = Some(t.to_owned());
            Ok(())
        }
        fn read(&self) -> Result<Option<String>> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn clear(&self) -> Result<()> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    fn setup() -> (Arc<Mock>, SecureClipboard) {
        let m = Arc::new(Mock::default());
        (m.clone(), SecureClipboard::new(m))
    }

    const SHORT: Duration = Duration::from_millis(60);
    const WAIT: Duration = Duration::from_millis(400);

    #[test]
    fn clears_after_timeout() {
        let (m, c) = setup();
        c.copy("s3cret", Some(SHORT)).unwrap();
        assert_eq!(m.read().unwrap().as_deref(), Some("s3cret"));
        thread::sleep(WAIT);
        assert_eq!(m.read().unwrap(), None);
    }

    #[test]
    fn leaves_foreign_content_alone() {
        let (m, c) = setup();
        c.copy("s3cret", Some(SHORT)).unwrap();
        m.write("something the user copied").unwrap();
        thread::sleep(WAIT);
        assert_eq!(
            m.read().unwrap().as_deref(),
            Some("something the user copied")
        );
    }

    #[test]
    fn newer_copy_supersedes_older_timer() {
        let (m, c) = setup();
        c.copy("first", Some(SHORT)).unwrap();
        c.copy("second", None).unwrap();
        thread::sleep(WAIT);
        assert_eq!(m.read().unwrap().as_deref(), Some("second"));
    }

    #[test]
    fn never_mode_does_not_clear() {
        let (m, c) = setup();
        c.copy("keep", None).unwrap();
        thread::sleep(WAIT);
        assert_eq!(m.read().unwrap().as_deref(), Some("keep"));
    }

    #[test]
    fn explicit_clear_only_when_owned() {
        let (m, c) = setup();
        assert!(!c.clear_if_owned());
        c.copy("mine", None).unwrap();
        assert!(c.clear_if_owned());
        assert_eq!(m.read().unwrap(), None);

        c.copy("mine", None).unwrap();
        m.write("other").unwrap();
        assert!(!c.clear_if_owned());
        assert_eq!(m.read().unwrap().as_deref(), Some("other"));
    }

    #[test]
    fn explicit_clear_cancels_pending_timer() {
        let (m, c) = setup();
        c.copy("mine", Some(SHORT)).unwrap();
        assert!(c.clear_if_owned());
        // The user copies something new before the old timer would have fired.
        m.write("newer").unwrap();
        thread::sleep(WAIT);
        assert_eq!(m.read().unwrap().as_deref(), Some("newer"));
    }
}
