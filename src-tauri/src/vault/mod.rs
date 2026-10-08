//! Encrypted stores that hold secrets at rest: the Master Password credential vault and the
//! user-facing file vaults.

pub mod credentials;
pub mod files;
pub mod lock_monitor;
