//! Key derivation: Argon2id for passwords, HKDF-SHA256 for already-random inputs.

use super::params::{KEY_LEN, SALT_LEN};
use crate::errors::{AppError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub type Key32 = Zeroizing<[u8; KEY_LEN]>;

/// Argon2id cost parameters. Stored in every password slot so they can be raised later without
/// breaking old files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes, 4 lanes. Comfortably above the OWASP minimum (19 MiB / t=2 / p=1) while
    /// staying around one second on a mid-range laptop and fitting low-memory machines.
    pub const DEFAULT: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 4,
    };

    /// Cheapest parameters the reader accepts. Used only by tests; the writer never emits
    /// anything below `DEFAULT` outside tests.
    pub const FLOOR: KdfParams = KdfParams {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    };

    const MAX_M_KIB: u32 = 1024 * 1024; // 1 GiB
    const MAX_T: u32 = 16;
    const MAX_P: u32 = 16;

    /// Validate parameters read from an *untrusted* file. The upper bounds are the important part:
    /// without them a crafted file could demand terabytes of memory the moment the user types a
    /// password.
    pub fn validate_untrusted(&self) -> Result<()> {
        if self.m_cost_kib < Self::FLOOR.m_cost_kib
            || self.m_cost_kib > Self::MAX_M_KIB
            || self.t_cost < Self::FLOOR.t_cost
            || self.t_cost > Self::MAX_T
            || self.p_cost < 1
            || self.p_cost > Self::MAX_P
            || self.m_cost_kib < 8 * self.p_cost
        {
            return Err(AppError::Corrupted(
                "key-derivation parameters out of range".into(),
            ));
        }
        Ok(())
    }
}

/// Derive a 256-bit key-encryption key from a (normalised) password.
pub fn derive_password_kek(password: &[u8], salt: &[u8; SALT_LEN], p: &KdfParams) -> Result<Key32> {
    p.validate_untrusted()?;
    let params = Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(KEY_LEN))
        .map_err(|e| AppError::Internal(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut *out)
        .map_err(|e| AppError::Internal(format!("argon2: {e}")))?;
    Ok(out)
}

/// HKDF-SHA256 expand into 32 bytes. `info` provides domain separation so one secret can never be
/// reused in two roles.
pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    // Expanding 32 bytes from SHA-256 HKDF can never exceed the 255*HashLen limit.
    hk.expand(info, &mut *out)
        .expect("hkdf output length is statically valid");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_inputs_and_distinct_for_different() {
        let salt = [7u8; SALT_LEN];
        let a = derive_password_kek(b"correct horse", &salt, &KdfParams::FLOOR).unwrap();
        let b = derive_password_kek(b"correct horse", &salt, &KdfParams::FLOOR).unwrap();
        let c = derive_password_kek(b"correct horsf", &salt, &KdfParams::FLOOR).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn hostile_parameters_are_rejected_before_allocation() {
        let bomb = KdfParams {
            m_cost_kib: u32::MAX,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(bomb.validate_untrusted().is_err());
        let weak = KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(weak.validate_untrusted().is_err());
    }
}
