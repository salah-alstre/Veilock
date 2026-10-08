//! Constants and identifiers of container format v1. See `docs/FORMAT.md`.

use crate::errors::{AppError, Result};

/// `\x89 V E I L \r \n \x1a` — the PNG-style signature: the high bit defeats 7-bit text
/// detection, the CR/LF pair detects line-ending mangling, 0x1A stops DOS `type`.
pub const MAGIC: [u8; 8] = [0x89, b'V', b'E', b'I', b'L', 0x0D, 0x0A, 0x1A];
pub const FORMAT_VERSION: u16 = 1;

pub const CORE_HEADER_LEN: usize = 48;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;
pub const FILE_ID_LEN: usize = 16;
pub const NONCE_PREFIX_LEN: usize = 8;

pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
pub const MIN_CHUNK_SIZE: u32 = 4096;
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

/// Upper bound on the encrypted metadata block. Checked *before* allocating, so a hostile file
/// cannot make us allocate gigabytes by lying about a length field.
pub const MAX_METADATA_CT_LEN: u32 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContainerKind {
    File = 1,
    Archive = 2,
}

impl TryFrom<u8> for ContainerKind {
    type Error = AppError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::File),
            2 => Ok(Self::Archive),
            _ => Err(AppError::Unsupported(format!("container kind {v}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherId {
    Aes256Gcm = 1,
}

impl CipherId {
    pub fn name(self) -> &'static str {
        match self {
            CipherId::Aes256Gcm => "AES-256-GCM",
        }
    }
}

impl TryFrom<u8> for CipherId {
    type Error = AppError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Aes256Gcm),
            _ => Err(AppError::Unsupported(format!("cipher id {v}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KdfId {
    /// Slot key is already high-entropy (recovery key); no stretching needed.
    None = 0,
    Argon2id = 1,
}

impl TryFrom<u8> for KdfId {
    type Error = AppError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Argon2id),
            _ => Err(AppError::Unsupported(format!("kdf id {v}"))),
        }
    }
}
