//! Key slots: the DEK wrapped under a password-derived key and (optionally) a recovery key.
//!
//! The region is four fixed-size records: `[password primary][password shadow][recovery primary]
//! [recovery shadow]`. Fixed offsets mean a password change is an in-place overwrite of a few
//! hundred bytes - the multi-gigabyte data section is never touched.
//!
//! Why a shadow copy: overwriting a record is not atomic. If power fails mid-write, a single copy
//! could be left half old / half new, i.e. unusable, and the user would lose access to the data
//! although they know the password. We therefore always write the shadow first (fsync), then the
//! primary (fsync). At any instant at least one copy is complete. Each record carries a checksum
//! so the reader can tell a torn record from an intact one. The checksum is NOT a security
//! feature - authenticity comes from the AEAD wrap - it only detects torn writes and bit-rot.
//!
//! Record layout (108 bytes):
//! ```text
//!  0       state   0 = empty, 1 = in use
//!  1       slot kind (1 password, 2 recovery)
//!  2       kdf id (0 none, 1 argon2id)
//!  3       reserved (0)
//!  4..8    m_cost KiB   } argon2id parameters, zero for kdf none
//!  8..12   t_cost       }
//! 12..16   p_cost       }
//! 16..32   salt
//! 32..44   wrap nonce
//! 44..92   wrapped DEK  (32 bytes ciphertext + 16 byte tag)
//! 92..108  checksum = SHA-256(record[0..92])[..16]
//! ```
//! Wrap AAD = SHA-256(core header) || slot kind, so a slot can neither be transplanted into
//! another file nor have its role changed.

use super::header::CoreHeader;
use super::kdf::{derive_password_kek, hkdf32, KdfParams, Key32};
use super::params::*;
use super::recovery::RecoveryKey;
use crate::errors::{AppError, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SLOT_RECORD_LEN: usize = 108;
pub const SLOT_COUNT: usize = 4;
pub const SLOT_REGION_LEN: usize = SLOT_RECORD_LEN * SLOT_COUNT;

const BODY_LEN: usize = 92;
const WRAPPED_LEN: usize = KEY_LEN + TAG_LEN;

const RECOVERY_KEK_INFO: &[u8] = b"veilock/recovery-kek";

pub type Record = [u8; SLOT_RECORD_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotKind {
    Password = 1,
    Recovery = 2,
}

impl SlotKind {
    /// Byte offsets of (primary, shadow) *within the slot region*.
    pub fn offsets(self) -> (usize, usize) {
        match self {
            SlotKind::Password => (0, SLOT_RECORD_LEN),
            SlotKind::Recovery => (2 * SLOT_RECORD_LEN, 3 * SLOT_RECORD_LEN),
        }
    }

    fn wrong_secret(self) -> AppError {
        match self {
            SlotKind::Password => AppError::WrongPassword,
            SlotKind::Recovery => AppError::InvalidRecoveryKey,
        }
    }
}

enum Classified {
    Empty,
    Damaged,
    Valid(Parsed),
}

#[derive(Clone)]
struct Parsed {
    raw: Record,
    kdf: KdfId,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
}

fn checksum(body: &[u8]) -> [u8; 16] {
    let d = Sha256::digest(body);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

fn classify(rec: &Record, expect: SlotKind) -> Classified {
    if rec.iter().all(|&b| b == 0) {
        return Classified::Empty;
    }
    if checksum(&rec[..BODY_LEN]) != rec[BODY_LEN..] {
        return Classified::Damaged;
    }
    if rec[0] != 1 || rec[1] != expect as u8 || rec[3] != 0 {
        return Classified::Damaged;
    }
    let Ok(kdf) = KdfId::try_from(rec[2]) else {
        return Classified::Damaged;
    };
    let params = KdfParams {
        m_cost_kib: u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]),
        t_cost: u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]),
        p_cost: u32::from_le_bytes([rec[12], rec[13], rec[14], rec[15]]),
    };
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&rec[16..32]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&rec[32..44]);
    let mut wrapped = [0u8; WRAPPED_LEN];
    wrapped.copy_from_slice(&rec[44..92]);
    Classified::Valid(Parsed {
        raw: *rec,
        kdf,
        params,
        salt,
        nonce,
        wrapped,
    })
}

fn wrap_aad(core_hash: &[u8; 32], kind: SlotKind) -> [u8; 33] {
    let mut aad = [0u8; 33];
    aad[..32].copy_from_slice(core_hash);
    aad[32] = kind as u8;
    aad
}

fn build_record(
    kind: SlotKind,
    kdf: KdfId,
    params: KdfParams,
    salt: &[u8; SALT_LEN],
    kek: &Key32,
    dek: &Key32,
    core_hash: &[u8; 32],
) -> Result<Record> {
    // A fresh random nonce per wrap. The KEK is also fresh per wrap (fresh salt), so a
    // (key, nonce) pair is never reused.
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher =
        Aes256Gcm::new_from_slice(&**kek).map_err(|_| AppError::Internal("kek length".into()))?;
    let wrapped = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &**dek,
                aad: &wrap_aad(core_hash, kind),
            },
        )
        .map_err(|_| AppError::Internal("key wrap failed".into()))?;
    debug_assert_eq!(wrapped.len(), WRAPPED_LEN);

    let mut rec = [0u8; SLOT_RECORD_LEN];
    rec[0] = 1;
    rec[1] = kind as u8;
    rec[2] = kdf as u8;
    rec[4..8].copy_from_slice(&params.m_cost_kib.to_le_bytes());
    rec[8..12].copy_from_slice(&params.t_cost.to_le_bytes());
    rec[12..16].copy_from_slice(&params.p_cost.to_le_bytes());
    rec[16..32].copy_from_slice(&salt[..]);
    rec[32..44].copy_from_slice(&nonce);
    rec[44..92].copy_from_slice(&wrapped);
    let sum = checksum(&rec[..BODY_LEN]);
    rec[BODY_LEN..].copy_from_slice(&sum);
    Ok(rec)
}

/// Wrap `dek` under a key derived from `password` (already normalised).
pub fn new_password_record(
    password: &[u8],
    params: KdfParams,
    dek: &Key32,
    header: &CoreHeader,
) -> Result<Record> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let kek = derive_password_kek(password, &salt, &params)?;
    let core_hash = CoreHeader::hash(&header.to_bytes());
    build_record(
        SlotKind::Password,
        KdfId::Argon2id,
        params,
        &salt,
        &kek,
        dek,
        &core_hash,
    )
}

/// Wrap `dek` under the recovery key. The recovery key is already 256 random bits, so HKDF (not
/// Argon2) is the right derivation; stretching would only slow down recovery.
pub fn new_recovery_record(
    recovery: &RecoveryKey,
    dek: &Key32,
    header: &CoreHeader,
) -> Result<Record> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let kek = hkdf32(recovery.as_bytes(), &salt, RECOVERY_KEK_INFO);
    let core_hash = CoreHeader::hash(&header.to_bytes());
    build_record(
        SlotKind::Recovery,
        KdfId::None,
        KdfParams {
            m_cost_kib: 0,
            t_cost: 0,
            p_cost: 0,
        },
        &salt,
        &kek,
        dek,
        &core_hash,
    )
}

/// The raw 432 bytes of the slot region as stored in the file.
#[derive(Clone)]
pub struct SlotRegion {
    raw: [u8; SLOT_REGION_LEN],
}

impl SlotRegion {
    pub fn empty() -> Self {
        Self {
            raw: [0u8; SLOT_REGION_LEN],
        }
    }

    pub fn from_bytes(raw: [u8; SLOT_REGION_LEN]) -> Self {
        Self { raw }
    }

    pub fn as_bytes(&self) -> &[u8; SLOT_REGION_LEN] {
        &self.raw
    }

    /// Write one record into both its primary and shadow position (used when creating a file).
    pub fn set_both(&mut self, kind: SlotKind, rec: &Record) {
        let (p, s) = kind.offsets();
        self.raw[p..p + SLOT_RECORD_LEN].copy_from_slice(rec);
        self.raw[s..s + SLOT_RECORD_LEN].copy_from_slice(rec);
    }

    fn record(&self, offset: usize) -> Record {
        let mut r = [0u8; SLOT_RECORD_LEN];
        r.copy_from_slice(&self.raw[offset..offset + SLOT_RECORD_LEN]);
        r
    }

    /// True if any record of this kind is present (even a damaged one - the slot exists, it just
    /// might not be usable).
    pub fn has(&self, kind: SlotKind) -> bool {
        let (p, s) = kind.offsets();
        !self.record(p).iter().all(|&b| b == 0) || !self.record(s).iter().all(|&b| b == 0)
    }

    /// Try every intact copy until one unwraps. Wrong secret and tampered slot are deliberately
    /// indistinguishable to the caller: an AEAD failure cannot tell them apart anyway, and
    /// pretending otherwise would be an oracle.
    fn unwrap_with(
        &self,
        kind: SlotKind,
        header: &CoreHeader,
        derive: &dyn Fn(&Parsed) -> Result<Key32>,
    ) -> Result<Key32> {
        let (p, s) = kind.offsets();
        let copies = [self.record(p), self.record(s)];

        let mut valid: Vec<Parsed> = Vec::with_capacity(2);
        let mut damaged = false;
        for rec in &copies {
            match classify(rec, kind) {
                Classified::Valid(parsed) => {
                    // In the normal state both copies are identical; deriving twice would double
                    // the Argon2 time for a wrong password.
                    if !valid.iter().any(|v| v.raw == parsed.raw) {
                        valid.push(parsed);
                    }
                }
                Classified::Damaged => damaged = true,
                Classified::Empty => {}
            }
        }
        if valid.is_empty() {
            return Err(AppError::Corrupted(if damaged {
                "key slot is damaged".into()
            } else {
                "key slot is missing".into()
            }));
        }

        let core_hash = CoreHeader::hash(&header.to_bytes());
        let aad = wrap_aad(&core_hash, kind);
        let mut usable_attempted = false;
        for slot in &valid {
            let kek = match derive(slot) {
                Ok(k) => k,
                // Hostile / unsupported parameters: skip this copy, try the other.
                Err(AppError::Corrupted(_)) | Err(AppError::Unsupported(_)) => continue,
                Err(e) => return Err(e),
            };
            usable_attempted = true;
            let cipher = Aes256Gcm::new_from_slice(&*kek)
                .map_err(|_| AppError::Internal("kek length".into()))?;
            if let Ok(pt) = cipher.decrypt(
                Nonce::from_slice(&slot.nonce),
                Payload {
                    msg: &slot.wrapped,
                    aad: &aad,
                },
            ) {
                let pt = Zeroizing::new(pt);
                if pt.len() == KEY_LEN {
                    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
                    dek.copy_from_slice(&pt);
                    return Ok(dek);
                }
            }
        }
        if usable_attempted {
            Err(kind.wrong_secret())
        } else {
            Err(AppError::Corrupted(
                "key slot parameters are invalid".into(),
            ))
        }
    }

    pub fn unwrap_password(&self, password: &[u8], header: &CoreHeader) -> Result<Key32> {
        self.unwrap_with(SlotKind::Password, header, &|slot| {
            if slot.kdf != KdfId::Argon2id {
                return Err(AppError::Unsupported("password slot kdf".into()));
            }
            derive_password_kek(password, &slot.salt, &slot.params)
        })
    }

    pub fn unwrap_recovery(&self, key: &RecoveryKey, header: &CoreHeader) -> Result<Key32> {
        self.unwrap_with(SlotKind::Recovery, header, &|slot| {
            if slot.kdf != KdfId::None {
                return Err(AppError::Unsupported("recovery slot kdf".into()));
            }
            Ok(hkdf32(key.as_bytes(), &slot.salt, RECOVERY_KEK_INFO))
        })
    }

    /// KDF parameters of the (first intact) password slot, for display / "needs rehash" checks.
    /// Unauthenticated, so informational only.
    pub fn password_params(&self) -> Option<KdfParams> {
        let (p, s) = SlotKind::Password.offsets();
        [self.record(p), self.record(s)].iter().find_map(|r| {
            match classify(r, SlotKind::Password) {
                Classified::Valid(v) => Some(v.params),
                _ => None,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> CoreHeader {
        CoreHeader {
            version: FORMAT_VERSION,
            kind: ContainerKind::File,
            cipher: CipherId::Aes256Gcm,
            chunk_size: DEFAULT_CHUNK_SIZE,
            file_id: [9; 16],
            nonce_prefix: [3; 8],
        }
    }

    fn dek() -> Key32 {
        let mut d = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *d);
        d
    }

    fn region_with_password(pw: &[u8], dek: &Key32) -> SlotRegion {
        let mut r = SlotRegion::empty();
        let rec = new_password_record(pw, KdfParams::FLOOR, dek, &header()).unwrap();
        r.set_both(SlotKind::Password, &rec);
        r
    }

    #[test]
    fn password_roundtrip_and_wrong_password() {
        let d = dek();
        let r = region_with_password(b"pw", &d);
        assert_eq!(*r.unwrap_password(b"pw", &header()).unwrap(), *d);
        assert!(matches!(
            r.unwrap_password(b"px", &header()),
            Err(AppError::WrongPassword)
        ));
    }

    #[test]
    fn slot_is_bound_to_its_file() {
        let d = dek();
        let r = region_with_password(b"pw", &d);
        let mut other = header();
        other.file_id = [8; 16];
        assert!(matches!(
            r.unwrap_password(b"pw", &other),
            Err(AppError::WrongPassword)
        ));
    }

    #[test]
    fn torn_primary_falls_back_to_shadow() {
        let d = dek();
        let mut r = region_with_password(b"pw", &d);
        // Simulate a torn write of the primary copy.
        for b in &mut r.raw[10..60] {
            *b ^= 0xA5;
        }
        assert_eq!(*r.unwrap_password(b"pw", &header()).unwrap(), *d);
    }

    #[test]
    fn both_copies_damaged_is_corrupted_not_wrong_password() {
        let d = dek();
        let mut r = region_with_password(b"pw", &d);
        r.raw[20] ^= 1;
        r.raw[SLOT_RECORD_LEN + 20] ^= 1;
        assert!(matches!(
            r.unwrap_password(b"pw", &header()),
            Err(AppError::Corrupted(_))
        ));
    }

    #[test]
    fn forged_checksum_with_tampered_wrap_fails_authentication() {
        let d = dek();
        let mut r = region_with_password(b"pw", &d);
        for off in [0, SLOT_RECORD_LEN] {
            r.raw[off + 50] ^= 1;
            let sum = checksum(&r.raw[off..off + BODY_LEN]);
            r.raw[off + BODY_LEN..off + SLOT_RECORD_LEN].copy_from_slice(&sum);
        }
        assert!(matches!(
            r.unwrap_password(b"pw", &header()),
            Err(AppError::WrongPassword)
        ));
    }

    #[test]
    fn hostile_kdf_params_are_rejected_without_deriving() {
        let d = dek();
        let mut r = region_with_password(b"pw", &d);
        for off in [0, SLOT_RECORD_LEN] {
            r.raw[off + 4..off + 8].copy_from_slice(&u32::MAX.to_le_bytes());
            let sum = checksum(&r.raw[off..off + BODY_LEN]);
            r.raw[off + BODY_LEN..off + SLOT_RECORD_LEN].copy_from_slice(&sum);
        }
        assert!(matches!(
            r.unwrap_password(b"pw", &header()),
            Err(AppError::Corrupted(_))
        ));
    }

    #[test]
    fn recovery_roundtrip_and_wrong_key() {
        let d = dek();
        let rk = RecoveryKey::generate();
        let mut r = SlotRegion::empty();
        let rec = new_recovery_record(&rk, &d, &header()).unwrap();
        r.set_both(SlotKind::Recovery, &rec);
        assert!(r.has(SlotKind::Recovery));
        assert!(!r.has(SlotKind::Password));
        assert_eq!(*r.unwrap_recovery(&rk, &header()).unwrap(), *d);
        let other = RecoveryKey::generate();
        assert!(matches!(
            r.unwrap_recovery(&other, &header()),
            Err(AppError::InvalidRecoveryKey)
        ));
    }

    #[test]
    fn password_slot_cannot_be_used_as_recovery_slot() {
        let d = dek();
        let mut r = SlotRegion::empty();
        let rec = new_password_record(b"pw", KdfParams::FLOOR, &d, &header()).unwrap();
        // Move the password record into the recovery position.
        r.set_both(SlotKind::Recovery, &rec);
        let rk = RecoveryKey::generate();
        assert!(r.unwrap_recovery(&rk, &header()).is_err());
    }
}
