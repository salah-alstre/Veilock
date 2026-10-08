//! Application error type.
//!
//! Errors cross the IPC boundary as `{ code, details }`. The frontend maps `code` to a localized,
//! human-readable message; `details` is technical text shown only behind "Show details".
//! Nothing placed in `details` may contain secrets (passwords, keys, plaintext) or Rust backtraces.

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::io;

/// Marker carried inside an `io::Error` so cancellation survives passing through `Read`/`Write`
/// adapters, whose signatures only allow `io::Error`.
#[derive(Debug)]
pub struct CancelledIo;
impl std::fmt::Display for CancelledIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operation cancelled")
    }
}
impl std::error::Error for CancelledIo {}

/// Marker for an AEAD authentication failure raised inside a streaming adapter.
#[derive(Debug)]
pub struct AuthFailedIo;
impl std::fmt::Display for AuthFailedIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authentication failed")
    }
}
impl std::error::Error for AuthFailedIo {}

/// Marker for a structurally malformed container discovered mid-stream.
#[derive(Debug)]
pub struct MalformedIo(pub &'static str);
impl std::fmt::Display for MalformedIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for MalformedIo {}

/// Marker for "the source file changed while we were reading it".
#[derive(Debug)]
pub struct SourceChangedIo;
impl std::fmt::Display for SourceChangedIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("source changed while it was being read")
    }
}
impl std::error::Error for SourceChangedIo {}

pub fn source_changed_io() -> io::Error {
    io::Error::other(SourceChangedIo)
}

pub fn cancelled_io() -> io::Error {
    io::Error::other(CancelledIo)
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("incorrect password")]
    WrongPassword,
    #[error("invalid recovery key")]
    InvalidRecoveryKey,
    #[error("corrupted or tampered data: {0}")]
    Corrupted(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("not a recognised encrypted file")]
    NotAContainer,
    #[error("not enough disk space")]
    NoSpace,
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("file is in use: {0}")]
    FileInUse(String),
    #[error("output already exists: {0}")]
    OutputExists(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("vault is locked")]
    VaultLocked,
    #[error("operation cancelled")]
    Cancelled,
    /// The freshly written output did not decrypt back to exactly the source data. The source is
    /// never removed when this is raised.
    #[error("verification of the encrypted output failed")]
    VerificationFailed,
    /// The source was modified while it was being encrypted, so the output may not match it.
    /// Nothing is deleted when this is raised.
    #[error("the source changed while it was being processed")]
    SourceChanged,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unsafe path rejected: {0}")]
    UnsafePath(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("another operation is already running")]
    Busy,
    #[error("input/output error: {0}")]
    Io(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AppError>;

impl AppError {
    /// Stable machine-readable code consumed by the frontend i18n layer.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::WrongPassword => "WRONG_PASSWORD",
            AppError::InvalidRecoveryKey => "INVALID_RECOVERY_KEY",
            AppError::Corrupted(_) => "CORRUPTED",
            AppError::Unsupported(_) => "UNSUPPORTED",
            AppError::NotAContainer => "NOT_A_CONTAINER",
            AppError::NoSpace => "NO_SPACE",
            AppError::PermissionDenied(_) => "PERMISSION_DENIED",
            AppError::FileInUse(_) => "FILE_IN_USE",
            AppError::OutputExists(_) => "OUTPUT_EXISTS",
            AppError::NotFound(_) => "NOT_FOUND",
            AppError::VaultLocked => "VAULT_LOCKED",
            AppError::Cancelled => "CANCELLED",
            AppError::VerificationFailed => "VERIFICATION_FAILED",
            AppError::SourceChanged => "SOURCE_CHANGED",
            AppError::InvalidInput(_) => "INVALID_INPUT",
            AppError::UnsafePath(_) => "UNSAFE_PATH",
            AppError::Storage(_) => "STORAGE",
            AppError::Busy => "BUSY",
            AppError::Io(_) => "IO",
            AppError::Internal(_) => "INTERNAL",
        }
    }

    fn details(&self) -> Option<String> {
        match self {
            AppError::Corrupted(d)
            | AppError::Unsupported(d)
            | AppError::PermissionDenied(d)
            | AppError::FileInUse(d)
            | AppError::OutputExists(d)
            | AppError::NotFound(d)
            | AppError::InvalidInput(d)
            | AppError::UnsafePath(d)
            | AppError::Storage(d)
            | AppError::Io(d)
            | AppError::Internal(d) => Some(d.clone()),
            _ => None,
        }
    }
}

impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("AppError", 2)?;
        st.serialize_field("code", self.code())?;
        st.serialize_field("details", &self.details())?;
        st.end()
    }
}

// Windows system error codes we translate into user-meaningful categories.
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;
const ERROR_HANDLE_DISK_FULL: i32 = 39;
const ERROR_DISK_FULL: i32 = 112;
const ENOSPC: i32 = 28;

impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self {
        if let Some(inner) = e.get_ref() {
            if inner.is::<CancelledIo>() {
                return AppError::Cancelled;
            }
            if inner.is::<SourceChangedIo>() {
                return AppError::SourceChanged;
            }
            if inner.is::<AuthFailedIo>() {
                return AppError::Corrupted("authentication failed".into());
            }
            if let Some(m) = inner.downcast_ref::<MalformedIo>() {
                return AppError::Corrupted(m.0.into());
            }
        }
        match e.raw_os_error() {
            Some(ERROR_DISK_FULL) | Some(ERROR_HANDLE_DISK_FULL) | Some(ENOSPC) => {
                return AppError::NoSpace
            }
            Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION) => {
                return AppError::FileInUse(os_summary(&e))
            }
            _ => {}
        }
        match e.kind() {
            io::ErrorKind::PermissionDenied => AppError::PermissionDenied(os_summary(&e)),
            io::ErrorKind::NotFound => AppError::NotFound(os_summary(&e)),
            io::ErrorKind::AlreadyExists => AppError::OutputExists(os_summary(&e)),
            io::ErrorKind::StorageFull => AppError::NoSpace,
            io::ErrorKind::UnexpectedEof => AppError::Corrupted("unexpected end of data".into()),
            _ => AppError::Io(os_summary(&e)),
        }
    }
}

/// Short, path-free description of an OS error (the OS message can embed paths on some APIs).
fn os_summary(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("os error {code}"),
        None => format!("{:?}", e.kind()),
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Corrupted(format!("invalid structured data: {}", e.classify_name()))
    }
}

trait ClassifyName {
    fn classify_name(&self) -> &'static str;
}
impl ClassifyName for serde_json::Error {
    fn classify_name(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_marker_survives_io_boundary() {
        let e: AppError = cancelled_io().into();
        assert!(matches!(e, AppError::Cancelled));
    }

    #[test]
    fn disk_full_is_mapped() {
        let e: AppError = io::Error::from_raw_os_error(ERROR_DISK_FULL).into();
        assert!(matches!(e, AppError::NoSpace));
    }

    #[test]
    fn serialised_error_has_code_and_no_backtrace() {
        let v = serde_json::to_value(AppError::Corrupted("x".into())).unwrap();
        assert_eq!(v["code"], "CORRUPTED");
        assert_eq!(v["details"], "x");
    }
}
