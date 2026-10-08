//! Cryptographic core. Everything security-sensitive lives here, in Rust; the frontend never sees
//! a key, a password hash or plaintext.

pub mod container;
pub mod header;
pub mod kdf;
pub mod keyslot;
pub mod metadata;
pub mod params;
pub mod password;
pub mod recovery;
pub mod stream;
