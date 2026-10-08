//! Crash-safe whole-file writes.
//!
//! A credential file or index that is half-written is as bad as a lost one. We write the new
//! content to a sibling temp file, flush it to disk, and then rename it over the target. On
//! Windows `std::fs::rename` uses `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`, so readers see either
//! the old or the new file, never a mixture.

use crate::errors::Result;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| crate::errors::AppError::Internal("path has no parent".into()))?;
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let mut suffix = [0u8; 6];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut suffix);
    tmp_name.push(format!(
        ".{}.tmp",
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let tmp = dir.join(tmp_name);

    let result = (|| -> Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        // Without this the rename could be persisted before the data on a power loss.
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn replaces_existing_content_and_leaves_no_temp() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("f.bin");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two-two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two-two");
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
    }

    #[test]
    fn failure_cleans_temp() {
        let t = TempDir::new().unwrap();
        // Target is a directory: the rename must fail and leave nothing behind.
        let p = t.path().join("dir");
        fs::create_dir(&p).unwrap();
        fs::write(p.join("inner"), b"x").unwrap();
        assert!(write_atomic(&p, b"data").is_err());
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
    }
}
