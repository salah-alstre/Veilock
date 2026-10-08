//! Cryptographically secure password generator.
//!
//! Randomness comes from the operating system CSPRNG (`OsRng`). Characters are drawn with
//! `gen_range`, which uses rejection sampling, so there is no modulo bias towards the first
//! characters of the alphabet. Every selected class is guaranteed to appear at least once, and the
//! result is then shuffled with a Fisher-Yates pass so the guaranteed characters do not sit in
//! predictable positions.

use crate::errors::{AppError, Result};
use rand::rngs::OsRng;
use rand::Rng;
use zeroize::Zeroizing;

pub const MIN_LEN: usize = 8;
pub const MAX_LEN: usize = 128;

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/~";
/// Characters that are easily confused when read or typed by hand.
const AMBIGUOUS: &str = "O0oIl1|`'\"";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorOptions {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

fn class_chars(set: &str, avoid_ambiguous: bool) -> Vec<char> {
    set.chars()
        .filter(|c| !(avoid_ambiguous && AMBIGUOUS.contains(*c)))
        .collect()
}

pub fn generate(opts: &GeneratorOptions) -> Result<Zeroizing<String>> {
    if !(MIN_LEN..=MAX_LEN).contains(&opts.length) {
        return Err(AppError::InvalidInput("password length".into()));
    }
    let classes: Vec<Vec<char>> = [
        (opts.upper, UPPER),
        (opts.lower, LOWER),
        (opts.digits, DIGITS),
        (opts.symbols, SYMBOLS),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, s)| class_chars(s, opts.avoid_ambiguous))
    .collect();
    if classes.is_empty() {
        return Err(AppError::InvalidInput("no character class selected".into()));
    }
    let all: Vec<char> = classes.iter().flatten().copied().collect();

    let mut rng = OsRng;
    let mut out: Vec<char> = Vec::with_capacity(opts.length);
    for class in &classes {
        out.push(class[rng.gen_range(0..class.len())]);
    }
    while out.len() < opts.length {
        out.push(all[rng.gen_range(0..all.len())]);
    }
    for i in (1..out.len()).rev() {
        let j = rng.gen_range(0..=i);
        out.swap(i, j);
    }
    let s: String = out.iter().collect();
    // The intermediate Vec<char> held the secret too.
    out.iter_mut().for_each(|c| *c = '\0');
    Ok(Zeroizing::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> GeneratorOptions {
        GeneratorOptions {
            length: 24,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }

    #[test]
    fn honours_length_and_classes() {
        for _ in 0..200 {
            let p = generate(&opts()).unwrap();
            assert_eq!(p.chars().count(), 24);
            assert!(p.chars().any(|c| UPPER.contains(c)));
            assert!(p.chars().any(|c| LOWER.contains(c)));
            assert!(p.chars().any(|c| DIGITS.contains(c)));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn single_class_only_uses_that_class() {
        let o = GeneratorOptions {
            upper: false,
            lower: false,
            symbols: false,
            ..opts()
        };
        assert!(generate(&o).unwrap().chars().all(|c| DIGITS.contains(c)));
    }

    #[test]
    fn avoids_ambiguous_characters() {
        let o = GeneratorOptions {
            avoid_ambiguous: true,
            length: 128,
            ..opts()
        };
        for _ in 0..50 {
            assert!(!generate(&o).unwrap().chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn rejects_bad_options() {
        assert!(generate(&GeneratorOptions {
            length: 4,
            ..opts()
        })
        .is_err());
        assert!(generate(&GeneratorOptions {
            length: 500,
            ..opts()
        })
        .is_err());
        let none = GeneratorOptions {
            upper: false,
            lower: false,
            digits: false,
            symbols: false,
            ..opts()
        };
        assert!(generate(&none).is_err());
    }

    #[test]
    fn outputs_differ_and_are_roughly_uniform() {
        let a = generate(&opts()).unwrap();
        let b = generate(&opts()).unwrap();
        assert_ne!(*a, *b);
        // Digits-only over many draws: every digit should show up with similar frequency.
        let o = GeneratorOptions {
            upper: false,
            lower: false,
            symbols: false,
            length: 128,
            ..opts()
        };
        let mut counts = [0usize; 10];
        for _ in 0..200 {
            for c in generate(&o).unwrap().chars() {
                counts[c.to_digit(10).unwrap() as usize] += 1;
            }
        }
        let expected = 200 * 128 / 10;
        for c in counts {
            assert!(
                c > expected * 9 / 10 && c < expected * 11 / 10,
                "{counts:?}"
            );
        }
    }
}
