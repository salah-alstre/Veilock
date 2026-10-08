//! Encrypted files the app knows about: the Recent and Favorites lists and the item details
//! screen (rename, move, delete, change password, recovery key).
//!
//! The database row is only a *bookmark*. Before any command touches the file on disk it re-probes
//! it, so a path that has since been replaced by some other file is never renamed, moved or
//! deleted on the strength of a stale row.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::crypto::container;
use crate::errors::{AppError, Result};
use crate::filesystem::names::validate_component;
use crate::filesystem::ops::{probe_container, publish, temp_name, ConflictPolicy, CONTAINER_EXT};
use crate::history::Event;
use crate::storage::db::ItemRecord;
use crate::vault::credentials::{path_matches, EntryUpdate};

use super::secret::{require_master, resolve, PasswordSource, Secret};
use super::state::AppState;
use super::{blocking, St};

const MAX_LIST: u32 = 200;

/// A bookmarked item plus what the filesystem says about it right now.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDetail {
    #[serde(flatten)]
    pub record: ItemRecord,
    /// False when the file has been moved or deleted outside the app.
    pub exists: bool,
}

fn detail(rec: ItemRecord) -> ItemDetail {
    let exists = fs::symlink_metadata(&rec.encrypted_path).is_ok_and(|m| m.is_file());
    ItemDetail {
        record: rec,
        exists,
    }
}

/// How the saved password for a file stands after an operation that could have changed it.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPasswordState {
    /// No password was saved for this file.
    None,
    /// The saved entry was updated to match.
    Updated,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChanged {
    pub saved_password: SavedPasswordState,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveResult {
    pub item: ItemRecord,
    /// A cross-volume move copies first; if the original could not be removed afterwards both
    /// copies exist and the user should know.
    pub original_left_behind: bool,
}

// ----- helpers ------------------------------------------------------------------------------

fn load(s: &AppState, id: &str) -> Result<(ItemRecord, PathBuf)> {
    let rec =
        s.db.item(id)?
            .ok_or_else(|| AppError::NotFound("item".into()))?;
    let path = PathBuf::from(&rec.encrypted_path);
    Ok((rec, path))
}

/// Load an item and confirm the file at its path is still a container before acting on it.
fn load_verified(s: &AppState, id: &str) -> Result<(ItemRecord, PathBuf)> {
    let (rec, path) = load(s, id)?;
    let md = fs::symlink_metadata(&path)?;
    if md.file_type().is_symlink() {
        return Err(AppError::UnsafePath("symlink".into()));
    }
    probe_container(&path)?;
    Ok((rec, path))
}

/// Master re-entry for sensitive actions, when the user has asked for it and a master exists.
pub(super) fn sensitive_gate(s: &AppState, master: Option<&Secret>) -> Result<()> {
    if s.settings().security.require_master_for_sensitive && s.creds.exists() {
        require_master(s, master)?;
    }
    Ok(())
}

/// Items with a saved password need the credential vault open so the saved entry can be kept in
/// step; otherwise it would silently point at a file that is no longer there.
fn need_creds_for(s: &AppState, rec: &ItemRecord) -> Result<()> {
    if rec.has_saved_password && !s.creds.is_unlocked() {
        return Err(AppError::VaultLocked);
    }
    Ok(())
}

fn saved_entry_id(s: &AppState, encrypted_path: &str) -> Result<Option<String>> {
    Ok(s.creds
        .list()?
        .into_iter()
        .find(|e| path_matches(e.encrypted_path.as_deref(), encrypted_path))
        .map(|e| e.id))
}

fn file_name_of(p: &Path) -> Result<String> {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| AppError::InvalidInput("path".into()))
}

fn parent_of(p: &Path) -> Result<&Path> {
    p.parent()
        .ok_or_else(|| AppError::InvalidInput("path".into()))
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn sha256_file(p: &Path) -> io::Result<[u8; 32]> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

fn with_ext(name: &str) -> String {
    let has = Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(CONTAINER_EXT));
    if has {
        name.to_owned()
    } else {
        format!("{name}.{CONTAINER_EXT}")
    }
}

// ----- lists --------------------------------------------------------------------------------

#[tauri::command]
pub async fn items_recent(state: St<'_>, limit: Option<u32>) -> Result<Vec<ItemDetail>> {
    blocking(&state, move |s| {
        let n = limit.unwrap_or(50).clamp(1, MAX_LIST);
        Ok(s.db.recent_items(n)?.into_iter().map(detail).collect())
    })
    .await
}

#[tauri::command]
pub async fn items_favorites(state: St<'_>) -> Result<Vec<ItemDetail>> {
    blocking(&state, |s| {
        Ok(s.db.favorite_items()?.into_iter().map(detail).collect())
    })
    .await
}

#[tauri::command]
pub async fn item_get(state: St<'_>, id: String) -> Result<ItemDetail> {
    blocking(&state, move |s| Ok(detail(load(s, &id)?.0))).await
}

/// Look an item up by file path (used when a file is opened by double-click or drag-and-drop).
#[tauri::command]
pub async fn item_for_path(state: St<'_>, path: String) -> Result<Option<ItemDetail>> {
    blocking(&state, move |s| Ok(s.db.item_by_path(&path)?.map(detail))).await
}

#[tauri::command]
pub fn item_favorite(state: St<'_>, id: String, favorite: bool) -> Result<()> {
    state.db.set_item_favorite(&id, favorite)
}

/// Forget an item in the app. The encrypted file itself is not touched.
#[tauri::command]
pub fn item_remove_from_history(state: St<'_>, id: String) -> Result<()> {
    state.db.delete_item(&id)
}

#[tauri::command]
pub fn recent_clear(state: St<'_>) -> Result<()> {
    state.db.clear_recent_items()
}

// ----- file operations ----------------------------------------------------------------------

/// Rename the encrypted file on disk. Never overwrites an existing file.
#[tauri::command]
pub async fn item_rename(state: St<'_>, id: String, new_name: String) -> Result<ItemRecord> {
    blocking(&state, move |s| {
        validate_component(&new_name)?;
        let new_name = with_ext(new_name.trim());
        validate_component(&new_name)?;
        let (rec, path) = load_verified(s, &id)?;
        need_creds_for(s, &rec)?;
        let dir = parent_of(&path)?;
        let old_name = file_name_of(&path)?;
        if new_name == old_name {
            return Ok(rec);
        }
        let new_path = if new_name.to_lowercase() == old_name.to_lowercase() {
            // Case-only change: the "no clobber" publish would see the file itself as a clash.
            let dst = dir.join(&new_name);
            fs::rename(&path, &dst)?;
            dst
        } else {
            publish(&path, dir, &new_name, false, ConflictPolicy::Fail)?
        };
        finish_relocation(s, &id, &rec, &new_path)?;
        s.db.item(&id)?
            .ok_or_else(|| AppError::NotFound("item".into()))
    })
    .await
}

/// Move the encrypted file to another folder. Same volume: an atomic rename. Different volume:
/// copy, compare hashes, then remove the original.
#[tauri::command]
pub async fn item_move(state: St<'_>, id: String, dest_dir: String) -> Result<MoveResult> {
    blocking(&state, move |s| {
        let (rec, path) = load_verified(s, &id)?;
        need_creds_for(s, &rec)?;
        let dest = PathBuf::from(&dest_dir);
        if !fs::metadata(&dest)?.is_dir() {
            return Err(AppError::InvalidInput("destination is not a folder".into()));
        }
        let name = file_name_of(&path)?;
        let same_dir = parent_of(&path)
            .ok()
            .and_then(|p| Some((fs::canonicalize(p).ok()?, fs::canonicalize(&dest).ok()?)))
            .is_some_and(|(a, b)| a == b);
        if same_dir {
            return Ok(MoveResult {
                item: rec,
                original_left_behind: false,
            });
        }

        let mut left_behind = false;
        let new_path = match publish(&path, &dest, &name, false, ConflictPolicy::Fail) {
            Ok(p) => p,
            Err(AppError::OutputExists(n)) => return Err(AppError::OutputExists(n)),
            Err(_) => {
                // Most likely a different volume. Copy to a temp in the destination, prove the
                // copy is identical, publish it without clobbering, and only then remove the
                // original.
                let tmp = dest.join(temp_name("mv"));
                let copied = copy_verified(&path, &tmp)
                    .and_then(|()| publish(&tmp, &dest, &name, false, ConflictPolicy::Fail));
                if copied.is_err() {
                    let _ = fs::remove_file(&tmp);
                }
                let published = copied?;
                left_behind = fs::remove_file(&path).is_err();
                published
            }
        };
        finish_relocation(s, &id, &rec, &new_path)?;
        let item =
            s.db.item(&id)?
                .ok_or_else(|| AppError::NotFound("item".into()))?;
        Ok(MoveResult {
            item,
            original_left_behind: left_behind,
        })
    })
    .await
}

fn copy_verified(src: &Path, tmp: &Path) -> Result<()> {
    fs::copy(src, tmp)?;
    OpenOptions::new().write(true).open(tmp)?.sync_all()?;
    if sha256_file(src)? != sha256_file(tmp)? {
        return Err(AppError::VerificationFailed);
    }
    Ok(())
}

/// Point the bookmark and any saved password at the file's new location.
fn finish_relocation(s: &AppState, id: &str, rec: &ItemRecord, new_path: &Path) -> Result<()> {
    let new = path_str(new_path);
    s.db.set_item_path(id, &new)?;
    if rec.has_saved_password {
        s.creds.repoint_path(&rec.encrypted_path, &new)?;
    }
    Ok(())
}

/// Permanently delete the encrypted file. This is a real deletion and, as with any file deletion,
/// the data may remain recoverable from the disk until overwritten.
#[tauri::command]
pub async fn item_delete_file(
    state: St<'_>,
    id: String,
    confirm: bool,
    master: Option<Secret>,
) -> Result<()> {
    if !confirm {
        return Err(AppError::InvalidInput("confirmation required".into()));
    }
    blocking(&state, move |s| {
        sensitive_gate(s, master.as_ref())?;
        let (rec, path) = load_verified(s, &id)?;
        need_creds_for(s, &rec)?;
        fs::remove_file(&path)?;
        s.db.delete_item(&id)?;
        if rec.has_saved_password {
            if let Some(entry) = saved_entry_id(s, &rec.encrypted_path)? {
                s.creds.delete(&entry)?;
            }
        }
        s.record(Event::PasswordDeleted, Some(&rec.name), "file_deleted");
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn item_reveal_in_folder(state: St<'_>, id: String) -> Result<()> {
    blocking(&state, move |s| {
        // The path comes from our own database, never from the UI.
        let (_, path) = load(s, &id)?;
        fs::symlink_metadata(&path)?;
        reveal(&path)
    })
    .await
}

#[cfg(windows)]
fn reveal(path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    // `/select,"path"` must reach Explorer unmangled, hence raw_arg. A Windows path cannot
    // contain a double quote, so the quoting cannot be broken out of.
    std::process::Command::new("explorer.exe")
        .raw_arg(format!("/select,\"{}\"", path.display()))
        .spawn()?;
    Ok(())
}

#[cfg(not(windows))]
fn reveal(_path: &Path) -> Result<()> {
    Err(AppError::Unsupported("reveal in folder".into()))
}

// ----- password and recovery key ------------------------------------------------------------

/// Re-wrap the file's key under a new password. The encrypted data is not rewritten.
#[tauri::command]
pub async fn item_change_password(
    state: St<'_>,
    id: String,
    current: PasswordSource,
    new_password: Secret,
    master: Option<Secret>,
) -> Result<PasswordChanged> {
    blocking(&state, move |s| {
        if new_password.is_empty() {
            return Err(AppError::InvalidInput("empty password".into()));
        }
        sensitive_gate(s, master.as_ref())?;
        let (rec, path) = load_verified(s, &id)?;
        need_creds_for(s, &rec)?;
        let key = path_str(&path);
        let resolved = resolve(s, &current, Some(&key), master.as_ref())?;
        let mut f = OpenOptions::new().read(true).write(true).open(&path)?;
        let r =
            container::change_password(&mut f, &resolved.as_unlock(), new_password.as_str(), s.kdf);
        s.record(
            Event::PasswordChange,
            Some(&rec.name),
            r.as_ref()
                .map_or_else(|e| e.code().to_ascii_lowercase(), |()| "ok".to_owned())
                .as_str(),
        );
        r?;

        let saved = match saved_entry_id(s, &key)? {
            Some(entry) if rec.has_saved_password => {
                // EntryUpdate zeroizes on drop, so it cannot use struct-update syntax.
                let mut upd = EntryUpdate::default();
                upd.password = Some(new_password.as_str().to_owned());
                s.creds.update(&entry, upd)?;
                SavedPasswordState::Updated
            }
            _ => SavedPasswordState::None,
        };
        Ok(PasswordChanged {
            saved_password: saved,
        })
    })
    .await
}

/// Create (or replace) the recovery key. The returned text is shown to the user once; the app
/// keeps no copy of it.
#[tauri::command]
pub async fn item_set_recovery(
    state: St<'_>,
    id: String,
    current: PasswordSource,
    master: Option<Secret>,
) -> Result<String> {
    blocking(&state, move |s| {
        sensitive_gate(s, master.as_ref())?;
        let (rec, path) = load_verified(s, &id)?;
        let key = path_str(&path);
        let resolved = resolve(s, &current, Some(&key), master.as_ref())?;
        let mut f = OpenOptions::new().read(true).write(true).open(&path)?;
        let recovery = container::set_recovery(&mut f, &resolved.as_unlock())?;
        s.db.set_item_recovery(&id, true)?;
        s.record(Event::RecoveryKeyCreate, Some(&rec.name), "ok");
        Ok(recovery.to_display_string().to_string())
    })
    .await
}

#[tauri::command]
pub async fn item_remove_recovery(
    state: St<'_>,
    id: String,
    current: PasswordSource,
    master: Option<Secret>,
) -> Result<()> {
    blocking(&state, move |s| {
        sensitive_gate(s, master.as_ref())?;
        let (rec, path) = load_verified(s, &id)?;
        let key = path_str(&path);
        let resolved = resolve(s, &current, Some(&key), master.as_ref())?;
        let mut f = OpenOptions::new().read(true).write(true).open(&path)?;
        container::remove_recovery(&mut f, &resolved.as_unlock())?;
        s.db.set_item_recovery(&id, false)?;
        s.record(Event::RecoveryKeyCreate, Some(&rec.name), "removed");
        Ok(())
    })
    .await
}
