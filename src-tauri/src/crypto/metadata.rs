//! Encrypted metadata block (original name, sizes, timestamps).
//!
//! Stored as `u32 ct_len || 12-byte nonce || ciphertext`. The length is attacker-controlled until
//! the block authenticates, so it is range-checked *before* any buffer is allocated. Nothing in
//! here is interpreted until AES-GCM has verified it.

use super::params::*;
use crate::errors::{AppError, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::Read;

use super::kdf::Key32;

const META_AAD_TAG: &[u8] = b"meta";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// Original file or folder name (no path).
    pub name: String,
    /// "file" or "folder".
    pub kind: String,
    /// Sum of plaintext bytes (for folders: all file contents).
    pub original_size: u64,
    /// Unix seconds when the container was created.
    pub created_at: i64,
    pub file_count: u64,
    pub dir_count: u64,
    /// App version that wrote the container; informational.
    pub app_version: String,
}

fn aad(core_hash: &[u8; 32]) -> Vec<u8> {
    let mut a = Vec::with_capacity(32 + META_AAD_TAG.len());
    a.extend_from_slice(core_hash);
    a.extend_from_slice(META_AAD_TAG);
    a
}

impl Metadata {
    pub fn seal(&self, meta_key: &Key32, core_hash: &[u8; 32]) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self)?;
        let cipher = Aes256Gcm::new_from_slice(&**meta_key)
            .map_err(|_| AppError::Internal("meta key length".into()))?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &json,
                    aad: &aad(core_hash),
                },
            )
            .map_err(|_| AppError::Internal("metadata encryption failed".into()))?;
        let ct_len = u32::try_from(ct.len())
            .ok()
            .filter(|&n| n <= MAX_METADATA_CT_LEN)
            .ok_or_else(|| AppError::InvalidInput("metadata too large".into()))?;
        let mut out = Vec::with_capacity(4 + NONCE_LEN + ct.len());
        out.extend_from_slice(&ct_len.to_le_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Read the raw (still encrypted) block. Returns `nonce || ciphertext`.
    pub fn read_block<R: Read>(r: &mut R) -> Result<Vec<u8>> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len).map_err(truncated)?;
        let ct_len = u32::from_le_bytes(len);
        if !(TAG_LEN as u32..=MAX_METADATA_CT_LEN).contains(&ct_len) {
            return Err(AppError::Corrupted("metadata length out of range".into()));
        }
        let mut block = vec![0u8; NONCE_LEN + ct_len as usize];
        r.read_exact(&mut block).map_err(truncated)?;
        Ok(block)
    }

    pub fn open(block: &[u8], meta_key: &Key32, core_hash: &[u8; 32]) -> Result<Self> {
        if block.len() < NONCE_LEN + TAG_LEN {
            return Err(AppError::Corrupted("metadata block too short".into()));
        }
        let (nonce, ct) = block.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(&**meta_key)
            .map_err(|_| AppError::Internal("meta key length".into()))?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &aad(core_hash),
                },
            )
            .map_err(|_| AppError::Corrupted("metadata failed authentication".into()))?;
        let pt = zeroize::Zeroizing::new(pt);
        serde_json::from_slice(&pt).map_err(|_| AppError::Corrupted("metadata is malformed".into()))
    }
}

fn truncated(e: std::io::Error) -> AppError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        AppError::Corrupted("file is truncated".into())
    } else {
        e.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn sample() -> Metadata {
        Metadata {
            name: "تقرير.pdf".into(),
            kind: "file".into(),
            original_size: 42,
            created_at: 1_700_000_000,
            file_count: 1,
            dir_count: 0,
            app_version: "0.1.0".into(),
        }
    }

    #[test]
    fn roundtrip() {
        let key: Key32 = Zeroizing::new([5u8; 32]);
        let hash = [1u8; 32];
        let bytes = sample().seal(&key, &hash).unwrap();
        let block = Metadata::read_block(&mut &bytes[..]).unwrap();
        assert_eq!(Metadata::open(&block, &key, &hash).unwrap(), sample());
    }

    #[test]
    fn tamper_and_wrong_context_fail() {
        let key: Key32 = Zeroizing::new([5u8; 32]);
        let hash = [1u8; 32];
        let bytes = sample().seal(&key, &hash).unwrap();
        let mut block = Metadata::read_block(&mut &bytes[..]).unwrap();
        assert!(Metadata::open(&block, &key, &[2u8; 32]).is_err());
        let last = block.len() - 1;
        block[last] ^= 1;
        assert!(Metadata::open(&block, &key, &hash).is_err());
    }

    #[test]
    fn oversized_length_is_rejected_before_allocation() {
        let mut evil = Vec::new();
        evil.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Metadata::read_block(&mut &evil[..]),
            Err(AppError::Corrupted(_))
        ));
        let mut small = Vec::new();
        small.extend_from_slice(&3u32.to_le_bytes());
        assert!(Metadata::read_block(&mut &small[..]).is_err());
    }
}
