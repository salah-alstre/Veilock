//! Secrets as they arrive from the UI, and how a "password source" is resolved in Rust.
//!
//! The UI never receives a saved or default password back: it asks Rust to *use* one
//! (`PasswordSource::Saved` / `Default`) and Rust resolves it right where it is needed.

use std::fmt;

use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

use crate::crypto::container::Unlock;
use crate::crypto::recovery::RecoveryKey;
use crate::errors::{AppError, Result};
use crate::settings::DefaultPasswordMode;

use super::state::AppState;

/// A string that is wiped on drop and never printed.
///
/// serde_json parses into a temporary buffer before this type takes ownership, so a transient
/// copy can exist in the IPC layer; that is outside our control and is documented as a limit.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d).map(|s| Secret(Zeroizing::new(s)))
    }
}

/// Where the password for an operation comes from.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PasswordSource {
    /// Typed by the user just now.
    Typed { password: Secret },
    /// The entry saved for this very file/vault in the credential vault.
    Saved,
    /// The optional default encryption password.
    Default,
    /// A recovery key (decrypt/unlock only).
    Recovery { key: Secret },
}

/// A resolved credential, ready to hand to the crypto layer.
pub enum Resolved {
    Password(Zeroizing<String>),
    Recovery(RecoveryKey),
}

impl Resolved {
    pub fn as_unlock(&self) -> Unlock<'_> {
        match self {
            Resolved::Password(p) => Unlock::Password(p.as_str()),
            Resolved::Recovery(k) => Unlock::Recovery(k),
        }
    }

    /// The password, if this is one. Recovery keys cannot be used to *encrypt*.
    pub fn password(&self) -> Result<&str> {
        match self {
            Resolved::Password(p) => Ok(p.as_str()),
            Resolved::Recovery(_) => Err(AppError::InvalidInput("recovery key not allowed".into())),
        }
    }
}

/// Resolve a [`PasswordSource`].
///
/// `saved_key` is the key under which a saved entry is looked up (the encrypted file's path, or
/// `vault://<id>` for a file vault). `master` is the master password the user re-typed for this
/// action; it is verified in Rust and never stored.
pub fn resolve(
    state: &AppState,
    source: &PasswordSource,
    saved_key: Option<&str>,
    master: Option<&Secret>,
) -> Result<Resolved> {
    match source {
        PasswordSource::Typed { password } => {
            if password.is_empty() {
                return Err(AppError::InvalidInput("empty password".into()));
            }
            Ok(Resolved::Password(Zeroizing::new(
                password.as_str().to_owned(),
            )))
        }
        PasswordSource::Recovery { key } => {
            Ok(Resolved::Recovery(RecoveryKey::parse(key.as_str())?))
        }
        PasswordSource::Saved => {
            let key = saved_key.ok_or_else(|| AppError::InvalidInput("no saved key".into()))?;
            state
                .creds
                .use_for_path(key)?
                .map(Resolved::Password)
                .ok_or_else(|| AppError::NotFound("saved password".into()))
        }
        PasswordSource::Default => {
            // "Require master password" mode: the user must prove they know the master password
            // for *this* use, even though the credential vault is already unlocked.
            if state.settings().encryption.default_password_mode
                == DefaultPasswordMode::RequireMaster
            {
                require_master(state, master)?;
            }
            state
                .creds
                .default_password()?
                .map(Resolved::Password)
                .ok_or_else(|| AppError::NotFound("default password".into()))
        }
    }
}

/// Verify a re-typed master password (used before sensitive actions).
pub fn require_master(state: &AppState, master: Option<&Secret>) -> Result<()> {
    let m = master.ok_or(AppError::WrongPassword)?;
    state.creds.verify_master(m.as_str())
}
