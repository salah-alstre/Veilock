//! Validation of names and relative paths that come out of a container.
//!
//! Metadata and archive paths are authenticated, but authenticated is not the same as safe: a
//! malicious (or buggy) producer can still encrypt an archive containing `..\..\Startup\x.exe`.
//! Everything extracted is therefore validated component by component, and the caller joins the
//! result onto a staging directory it controls.

use crate::errors::{AppError, Result};

/// Longest single path component Windows accepts.
pub const MAX_COMPONENT_LEN: usize = 255;
/// Deepest relative path we will extract; bounds recursion and path-length games.
pub const MAX_DEPTH: usize = 64;
/// Longest relative path (in bytes) accepted from an archive.
pub const MAX_REL_PATH_LEN: usize = 32 * 1024;

const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

const FORBIDDEN_CHARS: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

fn unsafe_path(why: &str) -> AppError {
    AppError::UnsafePath(why.to_string())
}

/// Validate one path component (a file or directory name).
pub fn validate_component(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(unsafe_path("empty name"));
    }
    if name == "." || name == ".." {
        return Err(unsafe_path("relative path component"));
    }
    if name.chars().count() > MAX_COMPONENT_LEN {
        return Err(unsafe_path("name too long"));
    }
    if name
        .chars()
        .any(|c| c.is_control() || FORBIDDEN_CHARS.contains(&c))
    {
        return Err(unsafe_path("name contains forbidden characters"));
    }
    // Windows silently strips trailing dots and spaces, which would let "x. " alias "x".
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(unsafe_path("name ends with a dot or space"));
    }
    // "CON", "con.txt", "NUL.tar.gz" are all device names on Windows.
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
        return Err(unsafe_path("reserved device name"));
    }
    Ok(())
}

/// Validate an archive-relative path (`/`-separated) and return its components.
pub fn validate_rel_path(path: &str) -> Result<Vec<&str>> {
    if path.is_empty() || path.len() > MAX_REL_PATH_LEN {
        return Err(unsafe_path("invalid path length"));
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(unsafe_path("absolute or backslash path"));
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_DEPTH {
        return Err(unsafe_path("path too deep"));
    }
    for p in &parts {
        validate_component(p)?;
    }
    Ok(parts)
}

/// Turn the (authenticated) original name from metadata into a safe file name. Only the final
/// component is used so a hostile name can never steer output outside the chosen directory.
pub fn safe_output_name(original: &str) -> Result<String> {
    let last = original
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(original)
        .trim_end_matches(['.', ' ']);
    validate_component(last)?;
    Ok(last.to_string())
}

/// Make a name acceptable to Windows when it is *our own* choice (e.g. a source name we are
/// reusing). Replaces forbidden characters rather than failing.
pub fn sanitize_for_output(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_control() || FORBIDDEN_CHARS.contains(&c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    if s.is_empty() {
        s.push_str("item");
    }
    let stem = s.split('.').next().unwrap_or(&s).to_string();
    if RESERVED
        .iter()
        .any(|r| r.eq_ignore_ascii_case(stem.trim_end()))
    {
        s.insert(0, '_');
    }
    if s.chars().count() > MAX_COMPONENT_LEN {
        s = s.chars().take(MAX_COMPONENT_LEN).collect();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_absolute() {
        for bad in [
            "..", ".", "../x", "a/../b", "/abs", "C:/x", "C:\\x", "a\\b", "a//b", "a/", "", "x:y",
        ] {
            assert!(
                validate_rel_path(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_reserved_and_trailing() {
        for bad in [
            "CON",
            "con.txt",
            "NUL.tar.gz",
            "Com1",
            "lpt9.x",
            "a.",
            "a ",
            "a|b",
            "a\u{0}b",
        ] {
            assert!(validate_component(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn accepts_unicode_arabic_and_spaces() {
        for ok in [
            "photo.jpg",
            "My Private Photos",
            "ملف سري.txt",
            "日本語フォルダ",
            "émoji 🙂.txt",
            "console.txt",
            "a.b.c",
        ] {
            assert!(validate_component(ok).is_ok(), "{ok:?}");
        }
        assert_eq!(
            validate_rel_path("ملفات/صور/a.png").unwrap(),
            vec!["ملفات", "صور", "a.png"]
        );
    }

    #[test]
    fn depth_and_length_limits() {
        let deep = vec!["d"; MAX_DEPTH + 1].join("/");
        assert!(validate_rel_path(&deep).is_err());
        let long = "x".repeat(MAX_COMPONENT_LEN + 1);
        assert!(validate_component(&long).is_err());
    }

    #[test]
    fn output_name_uses_last_component_only() {
        assert_eq!(safe_output_name("..\\..\\evil.txt").unwrap(), "evil.txt");
        assert_eq!(safe_output_name("a/b/c.txt").unwrap(), "c.txt");
        assert!(safe_output_name("..").is_err());
        assert!(safe_output_name("CON").is_err());
    }

    #[test]
    fn sanitize_never_yields_invalid_names() {
        for s in ["a:b", "CON", "x. ", "", "???", "ok.txt"] {
            let out = sanitize_for_output(s);
            assert!(validate_component(&out).is_ok(), "{s:?} -> {out:?}");
        }
    }
}
