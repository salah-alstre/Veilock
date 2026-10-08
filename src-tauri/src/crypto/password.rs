//! Password normalisation.
//!
//! The same visible password can be produced by different Unicode sequences (e.g. precomposed
//! vs. combining accents, common in Arabic and European input methods). Without normalisation a
//! user could encrypt on one keyboard and be locked out on another. We apply NFKC before
//! hashing. This is part of the format: v1 files are keyed from NFKC(password) as UTF-8.

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub fn normalize(password: &str) -> Zeroizing<Vec<u8>> {
    let s: Zeroizing<String> = Zeroizing::new(password.nfkc().collect());
    Zeroizing::new(s.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composed_and_decomposed_forms_match() {
        let composed = "caf\u{00e9}";
        let decomposed = "cafe\u{0301}";
        assert_eq!(*normalize(composed), *normalize(decomposed));
    }

    #[test]
    fn arabic_is_stable() {
        let pw = "كلمة-السر-١٢٣";
        assert_eq!(*normalize(pw), *normalize(pw));
        assert!(!normalize(pw).is_empty());
    }
}
