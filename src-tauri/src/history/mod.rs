//! Activity history: a log of *safe* events only.
//!
//! An event records what happened (kind), to which item name, and whether it worked (an outcome
//! code such as `ok` or `WRONG_PASSWORD`). There is deliberately no free-text field: nothing a
//! caller could accidentally pass in (a password, a path, key material) has anywhere to go.

use crate::errors::Result;
use crate::storage::db::{ActivityRecord, Db};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Closed set of event kinds. Using an enum keeps arbitrary strings out of the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Encrypt,
    Decrypt,
    VaultCreate,
    VaultOpen,
    VaultLock,
    VaultDelete,
    VaultImport,
    VaultExport,
    PasswordChange,
    RecoveryKeyCreate,
    AppUnlock,
    AppLock,
    PanicLock,
    PasswordSaved,
    PasswordDeleted,
    MasterChange,
    VaultRename,
    VaultItemAdd,
    VaultItemExtract,
    VaultItemRemove,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Event::Encrypt => "encrypt",
            Event::Decrypt => "decrypt",
            Event::VaultCreate => "vault_create",
            Event::VaultOpen => "vault_open",
            Event::VaultLock => "vault_lock",
            Event::VaultDelete => "vault_delete",
            Event::VaultImport => "vault_import",
            Event::VaultExport => "vault_export",
            Event::PasswordChange => "password_change",
            Event::RecoveryKeyCreate => "recovery_key_create",
            Event::AppUnlock => "app_unlock",
            Event::AppLock => "app_lock",
            Event::PanicLock => "panic_lock",
            Event::PasswordSaved => "password_saved",
            Event::PasswordDeleted => "password_deleted",
            Event::MasterChange => "master_change",
            Event::VaultRename => "vault_rename",
            Event::VaultItemAdd => "vault_item_add",
            Event::VaultItemExtract => "vault_item_extract",
            Event::VaultItemRemove => "vault_item_remove",
        }
    }
}

pub struct History {
    db: Arc<Db>,
    enabled: AtomicBool,
}

impl History {
    pub fn new(db: Arc<Db>, enabled: bool) -> Self {
        History {
            db,
            enabled: AtomicBool::new(enabled),
        }
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Record an event. Failures to log never fail the operation being logged.
    pub fn record(&self, event: Event, subject: Option<&str>, outcome: &str) {
        if !self.is_enabled() {
            return;
        }
        // Outcome is a short code; cap it so a bug can't smuggle long text in.
        let outcome: String = outcome.chars().take(40).collect();
        let subject = subject.map(|s| s.chars().take(255).collect::<String>());
        if self
            .db
            .add_activity(event.as_str(), subject.as_deref(), &outcome)
            .is_err()
        {
            log::warn!("could not write activity entry");
        }
    }

    pub fn list(&self, limit: u32) -> Result<Vec<ActivityRecord>> {
        self.db.activity(limit.min(1000))
    }

    pub fn clear(&self) -> Result<()> {
        self.db.clear_activity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history(enabled: bool) -> History {
        History::new(Arc::new(Db::open_in_memory().unwrap()), enabled)
    }

    #[test]
    fn records_and_lists_newest_first() {
        let h = history(true);
        h.record(Event::Encrypt, Some("a.txt"), "ok");
        h.record(Event::Decrypt, Some("a.txt"), "WRONG_PASSWORD");
        let l = h.list(10).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].kind, "decrypt");
        assert_eq!(l[0].outcome, "WRONG_PASSWORD");
    }

    #[test]
    fn disabled_records_nothing() {
        let h = history(false);
        h.record(Event::Encrypt, Some("a.txt"), "ok");
        assert!(h.list(10).unwrap().is_empty());
        h.set_enabled(true);
        h.record(Event::Encrypt, None, "ok");
        assert_eq!(h.list(10).unwrap().len(), 1);
    }

    #[test]
    fn clear_empties_log_and_long_text_is_capped() {
        let h = history(true);
        h.record(Event::Encrypt, Some(&"x".repeat(1000)), &"y".repeat(1000));
        let l = h.list(10).unwrap();
        assert_eq!(l[0].subject.as_ref().unwrap().len(), 255);
        assert_eq!(l[0].outcome.len(), 40);
        h.clear().unwrap();
        assert!(h.list(10).unwrap().is_empty());
    }
}
