//! Filesystem-facing logic: safe names, the folder archive format and the encrypt/decrypt
//! operations that wrap the crypto core with temp-file, verification and atomic-publish handling.

pub mod archive;
pub mod names;
pub mod ops;
