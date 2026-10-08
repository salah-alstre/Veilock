//! Password strength estimation.
//!
//! This is a heuristic, not a guarantee. It estimates entropy from the character pool and length,
//! discounts repeated characters and ascending/descending runs, and caps the score for passwords
//! that are in a small built-in list of very common choices. It is computed locally; the password
//! is never sent anywhere.

use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StrengthReport {
    pub level: Strength,
    pub bits: f64,
    /// 0..=4, convenient for a meter.
    pub score: u8,
}

const COMMON: &[&str] = &[
    "password",
    "passw0rd",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwertyuiop",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "master",
    "login",
    "princess",
    "sunshine",
    "trustno1",
    "111111",
    "000000",
    "password1",
    "p@ssw0rd",
    "changeme",
    "secret",
];

pub fn estimate(pw: &str) -> StrengthReport {
    let chars: Vec<char> = pw.chars().collect();
    if chars.is_empty() {
        return report(0.0, false);
    }
    let lower = pw.to_lowercase();
    let common = COMMON.iter().any(|c| lower == *c)
        || COMMON
            .iter()
            .any(|c| lower.starts_with(c) && chars.len() <= c.len() + 3);

    let mut pool = 0f64;
    if chars.iter().any(|c| c.is_ascii_lowercase()) {
        pool += 26.0;
    }
    if chars.iter().any(|c| c.is_ascii_uppercase()) {
        pool += 26.0;
    }
    if chars.iter().any(|c| c.is_ascii_digit()) {
        pool += 10.0;
    }
    if chars
        .iter()
        .any(|c| c.is_ascii() && !c.is_ascii_alphanumeric())
    {
        pool += 33.0;
    }
    if chars.iter().any(|c| !c.is_ascii()) {
        pool += 100.0;
    }

    // Count only characters that add information: a repeat of the previous character or a step
    // along a run ("abcd", "4321") is nearly free for an attacker to guess.
    let mut effective = 1.0f64;
    for w in chars.windows(2) {
        let (a, b) = (w[0] as i64, w[1] as i64);
        if a == b {
            effective += 0.1;
        } else if (b - a).abs() == 1 {
            effective += 0.3;
        } else {
            effective += 1.0;
        }
    }
    // Few distinct characters in a long string is still weak.
    let distinct = chars.iter().collect::<HashSet<_>>().len() as f64;
    effective = effective.min(distinct * 2.0 + 1.0).max(1.0);

    let bits = effective * pool.max(2.0).log2();
    report(bits, common)
}

fn report(bits: f64, common: bool) -> StrengthReport {
    let bits = if common { bits.min(10.0) } else { bits };
    let (level, score) = match bits {
        b if b < 28.0 => (Strength::VeryWeak, 0),
        b if b < 40.0 => (Strength::Weak, 1),
        b if b < 60.0 => (Strength::Medium, 2),
        b if b < 80.0 => (Strength::Strong, 3),
        _ => (Strength::VeryStrong, 4),
    };
    StrengthReport { level, bits, score }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::generator::{generate, GeneratorOptions};

    #[test]
    fn empty_and_common_are_very_weak() {
        assert_eq!(estimate("").level, Strength::VeryWeak);
        assert_eq!(estimate("password").level, Strength::VeryWeak);
        assert_eq!(estimate("Password1").level, Strength::VeryWeak);
        assert_eq!(estimate("123456").level, Strength::VeryWeak);
    }

    #[test]
    fn repeats_and_runs_are_discounted() {
        assert!(estimate("aaaaaaaaaaaaaaaa").level <= Strength::Weak);
        assert!(estimate("abcdefghijklmnop").bits < estimate("kqzvmxbtwjhrcyug").bits);
    }

    #[test]
    fn longer_and_richer_is_stronger() {
        let a = estimate("Tr1cky!").bits;
        let b = estimate("Tr1cky!Tr0ub4dor&3").bits;
        assert!(b > a);
    }

    #[test]
    fn generated_passwords_rate_strong_or_better() {
        let o = GeneratorOptions {
            length: 20,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        };
        for _ in 0..50 {
            let p = generate(&o).unwrap();
            assert!(estimate(&p).level >= Strength::Strong);
        }
    }

    #[test]
    fn unicode_counts() {
        assert!(estimate("كلمةسرمعقدةجدا").level >= Strength::Medium);
    }
}
