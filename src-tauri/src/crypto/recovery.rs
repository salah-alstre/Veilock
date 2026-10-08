//! Recovery key: 256 random bits shown to the user exactly once.
//!
//! Text form: 34 bytes (32 key + 2 check) in unpadded base32 -> 55 characters, grouped as 11x5
//! with dashes. The check bytes only catch typos early with a clear message; they add no
//! security. The key itself is never persisted by the app.

use super::params::KEY_LEN;
use crate::errors::{AppError, Result};
use base32::Alphabet;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const ALPHABET: Alphabet = Alphabet::Rfc4648 { padding: false };
const CHECK_LEN: usize = 2;

pub struct RecoveryKey(Zeroizing<[u8; KEY_LEN]>);

impl RecoveryKey {
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        rand::rngs::OsRng.fill_bytes(&mut *k);
        Self(k)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn check(key: &[u8]) -> [u8; CHECK_LEN] {
        let mut h = Sha256::new();
        h.update(b"veilock/recovery-check/v1");
        h.update(key);
        let d = h.finalize();
        [d[0], d[1]]
    }

    /// Human-transcribable form. The returned string is secret; callers must treat it as such.
    pub fn to_display_string(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new(Vec::with_capacity(KEY_LEN + CHECK_LEN));
        raw.extend_from_slice(&*self.0);
        raw.extend_from_slice(&Self::check(&*self.0));
        let flat = Zeroizing::new(base32::encode(ALPHABET, &raw));
        let mut out = String::with_capacity(flat.len() + flat.len() / 5);
        for (i, c) in flat.chars().enumerate() {
            if i > 0 && i % 5 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        Zeroizing::new(out)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut cleaned = Zeroizing::new(String::with_capacity(text.len()));
        for c in text.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            cleaned.push(c.to_ascii_uppercase());
        }
        let decoded = base32::decode(ALPHABET, &cleaned).ok_or(AppError::InvalidRecoveryKey)?;
        let mut decoded = Zeroizing::new(decoded);
        if decoded.len() != KEY_LEN + CHECK_LEN {
            return Err(AppError::InvalidRecoveryKey);
        }
        let (key, chk) = decoded.split_at(KEY_LEN);
        if Self::check(key) != chk {
            return Err(AppError::InvalidRecoveryKey);
        }
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        k.copy_from_slice(key);
        decoded.zeroize();
        Ok(Self(k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_formatting() {
        let k = RecoveryKey::generate();
        let s = k.to_display_string();
        assert_eq!(s.len(), 55 + 10);
        let back = RecoveryKey::parse(&s).unwrap();
        assert_eq!(back.as_bytes(), k.as_bytes());
        // Tolerates lowercase and stray whitespace.
        let sloppy = format!(" {} ", s.to_lowercase().replace('-', " "));
        assert_eq!(
            RecoveryKey::parse(&sloppy).unwrap().as_bytes(),
            k.as_bytes()
        );
    }

    #[test]
    fn typo_and_garbage_are_rejected() {
        let k = RecoveryKey::generate();
        let mut s: Vec<char> = k.to_display_string().chars().collect();
        s[0] = if s[0] == 'A' { 'B' } else { 'A' };
        let typo: String = s.into_iter().collect();
        assert!(matches!(
            RecoveryKey::parse(&typo),
            Err(AppError::InvalidRecoveryKey)
        ));
        assert!(RecoveryKey::parse("hello").is_err());
        assert!(RecoveryKey::parse("").is_err());
    }
}
