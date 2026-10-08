//! The 48-byte immutable core header.
//!
//! Layout (little-endian):
//! ```text
//!  0..8   magic
//!  8..10  format version
//! 10      container kind (1 file, 2 archive)
//! 11      cipher id
//! 12..16  chunk size (plaintext bytes per chunk)
//! 16..32  file id (random; binds every chunk and key slot to this file)
//! 32..40  nonce prefix (random; chunk nonce = prefix || u32 counter)
//! 40..44  flags (must be 0 in v1)
//! 44..48  reserved (must be 0 in v1)
//! ```
//! The SHA-256 of these 48 bytes is mixed into the AAD of every key-slot wrap, the metadata block
//! and every data chunk. Flipping any header bit therefore breaks authentication everywhere,
//! even though the header itself is stored in the clear (it must be readable before unlocking).

use super::params::*;
use crate::errors::{AppError, Result};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreHeader {
    pub version: u16,
    pub kind: ContainerKind,
    pub cipher: CipherId,
    pub chunk_size: u32,
    pub file_id: [u8; FILE_ID_LEN],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl CoreHeader {
    pub fn to_bytes(&self) -> [u8; CORE_HEADER_LEN] {
        let mut b = [0u8; CORE_HEADER_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&self.version.to_le_bytes());
        b[10] = self.kind as u8;
        b[11] = self.cipher as u8;
        b[12..16].copy_from_slice(&self.chunk_size.to_le_bytes());
        b[16..32].copy_from_slice(&self.file_id);
        b[32..40].copy_from_slice(&self.nonce_prefix);
        // 40..48 flags + reserved stay zero.
        b
    }

    /// Parse and structurally validate. Order matters: magic first (so non-Veilock files get a
    /// clean "not a container" error), then version (so a newer file gets "unsupported" rather
    /// than a confusing "corrupted"), then everything else.
    pub fn parse(b: &[u8; CORE_HEADER_LEN]) -> Result<Self> {
        if b[0..8] != MAGIC {
            return Err(AppError::NotAContainer);
        }
        let version = u16::from_le_bytes([b[8], b[9]]);
        if version == 0 {
            return Err(AppError::Corrupted("format version 0".into()));
        }
        if version > FORMAT_VERSION {
            return Err(AppError::Unsupported(format!(
                "container format version {version} (this build reads up to {FORMAT_VERSION})"
            )));
        }
        let kind = ContainerKind::try_from(b[10])?;
        let cipher = CipherId::try_from(b[11])?;
        let chunk_size = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(AppError::Corrupted("chunk size out of range".into()));
        }
        if b[40..48].iter().any(|&x| x != 0) {
            return Err(AppError::Unsupported("unknown header flags".into()));
        }
        let mut file_id = [0u8; FILE_ID_LEN];
        file_id.copy_from_slice(&b[16..32]);
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&b[32..40]);
        Ok(Self {
            version,
            kind,
            cipher,
            chunk_size,
            file_id,
            nonce_prefix,
        })
    }

    pub fn hash(raw: &[u8; CORE_HEADER_LEN]) -> [u8; 32] {
        Sha256::digest(raw).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CoreHeader {
        CoreHeader {
            version: FORMAT_VERSION,
            kind: ContainerKind::File,
            cipher: CipherId::Aes256Gcm,
            chunk_size: DEFAULT_CHUNK_SIZE,
            file_id: [1; 16],
            nonce_prefix: [2; 8],
        }
    }

    #[test]
    fn roundtrip() {
        let h = sample();
        assert_eq!(CoreHeader::parse(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn rejects_bad_magic_future_version_and_bad_chunk_size() {
        let mut b = sample().to_bytes();
        b[0] ^= 1;
        assert!(matches!(
            CoreHeader::parse(&b),
            Err(AppError::NotAContainer)
        ));

        let mut b = sample().to_bytes();
        b[8] = 9;
        assert!(matches!(
            CoreHeader::parse(&b),
            Err(AppError::Unsupported(_))
        ));

        let mut b = sample().to_bytes();
        b[12..16].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(CoreHeader::parse(&b), Err(AppError::Corrupted(_))));

        let mut b = sample().to_bytes();
        b[44] = 1;
        assert!(matches!(
            CoreHeader::parse(&b),
            Err(AppError::Unsupported(_))
        ));
    }
}
