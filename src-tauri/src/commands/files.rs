//! Encrypt / decrypt commands and launch-argument handling.
//!
//! A batch never fails as a whole: every path gets its own result, so one unreadable file does not
//! hide what happened to the others. Secrets arrive as `Secret`/`PasswordSource` and are resolved
//! here in Rust; saved and default passwords never travel back to the UI.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::crypto::params::{CipherId, ContainerKind, DEFAULT_CHUNK_SIZE, FORMAT_VERSION};
use crate::errors::{AppError, Result};
use crate::filesystem::archive::scan_folder;
use crate::filesystem::ops::{
    decrypt_path, encrypt_path, probe_container, ConflictPolicy, DecryptRequest, EncryptRequest,
    ProgressInfo, Removal,
};
use crate::history::Event;
use crate::storage::db::{now, ItemRecord};
use crate::vault::credentials::NewEntry;

use super::secret::{resolve, PasswordSource, Secret};
use super::state::{emit_progress, AppState, ProgressEvent};
use super::{blocking, St};

/// Pick the paths out of a process command line (Explorer double-click or a context-menu verb
/// passes the item as an argument). The first element is the executable itself. Only paths that
/// exist are accepted; flags and anything else are ignored rather than trusted. The UI then
/// decides, from the file contents, whether each path is a container to unlock or an item to
/// protect.
pub fn launch_paths<I>(argv: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    argv.into_iter()
        .skip(1)
        .filter(|a| !a.starts_with("--") && Path::new(a).exists())
        .collect()
}

/// Files passed on the command line at start-up. Returned once; a second call gets nothing, so a
/// UI reload does not re-open the same file.
#[tauri::command]
pub fn take_launch_paths() -> Vec<String> {
    static TAKEN: AtomicBool = AtomicBool::new(false);
    if TAKEN.swap(true, Ordering::SeqCst) {
        return Vec::new();
    }
    launch_paths(std::env::args())
}

pub fn kind_str(kind: ContainerKind) -> &'static str {
    match kind {
        ContainerKind::File => "file",
        ContainerKind::Archive => "folder",
    }
}

fn unix_secs(t: Option<std::time::SystemTime>) -> Option<i64> {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_secs()).ok())
}

fn display_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string_lossy().into_owned())
}

// ----- inspect ------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerInfo {
    pub version: u16,
    pub kind: &'static str,
    pub cipher: &'static str,
    pub has_password_slot: bool,
    pub has_recovery_slot: bool,
    /// File modification time: the closest thing to an "encrypted on" date that does not require
    /// trusting anything inside the file.
    pub modified_at: Option<i64>,
    pub has_saved_password: bool,
    pub item_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathInfo {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub file_count: u64,
    pub dir_count: u64,
    pub container: Option<ContainerInfo>,
    pub error: Option<AppError>,
}

fn inspect_one(s: &AppState, path: &str) -> PathInfo {
    let p = Path::new(path);
    let mut info = PathInfo {
        path: path.to_owned(),
        name: display_name(p),
        is_dir: false,
        size: 0,
        file_count: 0,
        dir_count: 0,
        container: None,
        error: None,
    };
    let md = match std::fs::symlink_metadata(p) {
        Ok(md) => md,
        Err(e) => {
            info.error = Some(e.into());
            return info;
        }
    };
    if md.file_type().is_symlink() {
        info.error = Some(AppError::UnsafePath(
            "the item is a symbolic link or junction".into(),
        ));
        return info;
    }
    if md.is_dir() {
        info.is_dir = true;
        match scan_folder(p, &AtomicBool::new(false)) {
            Ok(scan) => {
                info.size = scan.content_bytes;
                info.file_count = scan.file_count;
                info.dir_count = scan.dir_count;
            }
            Err(e) => info.error = Some(e),
        }
        return info;
    }
    if !md.is_file() {
        info.error = Some(AppError::InvalidInput("not a regular file".into()));
        return info;
    }
    info.size = md.len();
    info.file_count = 1;
    match probe_container(p) {
        Ok(probe) => {
            let item = s.db.item_by_path(path).ok().flatten();
            info.container = Some(ContainerInfo {
                version: probe.inspection.version,
                kind: kind_str(probe.inspection.kind),
                cipher: probe.inspection.cipher,
                has_password_slot: probe.inspection.has_password_slot,
                has_recovery_slot: probe.inspection.has_recovery_slot,
                modified_at: unix_secs(probe.modified),
                // Locked credential vault: report "no" rather than failing the whole inspection.
                has_saved_password: s.creds.has_for_path(path).unwrap_or(false),
                item_id: item.map(|i| i.id),
            });
        }
        // A plain file that is simply not one of ours.
        Err(AppError::NotAContainer) => {}
        Err(e) => info.error = Some(e),
    }
    info
}

/// Describe dropped/selected paths before anything is encrypted: size, counts, and whether a file
/// is already one of our containers. Read-only; nothing here is authenticated.
#[tauri::command]
pub async fn inspect_paths(state: St<'_>, paths: Vec<String>) -> Result<Vec<PathInfo>> {
    if paths.len() > 10_000 {
        return Err(AppError::InvalidInput("too many items".into()));
    }
    blocking(&state, move |s| {
        Ok(paths.iter().map(|p| inspect_one(s, p)).collect())
    })
    .await
}

// ----- encrypt ------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptJob {
    pub op_id: String,
    pub paths: Vec<String>,
    pub password: PasswordSource,
    #[serde(default)]
    pub master: Option<Secret>,
    #[serde(default)]
    pub out_dir: Option<String>,
    pub on_conflict: ConflictPolicy,
    #[serde(default)]
    pub remove_original: bool,
    #[serde(default)]
    pub with_recovery: bool,
    #[serde(default)]
    pub save_password: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptItemResult {
    pub path: String,
    pub ok: bool,
    pub output: Option<String>,
    pub name: Option<String>,
    pub kind: Option<&'static str>,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub file_count: u64,
    pub removal: Option<Removal>,
    /// Shown to the user once. Rust keeps no copy.
    pub recovery_key: Option<String>,
    pub password_saved: bool,
    pub password_save_error: Option<AppError>,
    pub error: Option<AppError>,
}

impl EncryptItemResult {
    fn failed(path: &str, e: AppError) -> Self {
        EncryptItemResult {
            path: path.to_owned(),
            ok: false,
            output: None,
            name: None,
            kind: None,
            original_size: 0,
            encrypted_size: 0,
            file_count: 0,
            removal: None,
            recovery_key: None,
            password_saved: false,
            password_save_error: None,
            error: Some(e),
        }
    }
}

struct EncryptCtx<'a> {
    app: &'a AppHandle,
    op_id: &'a str,
    item_index: usize,
    item_count: usize,
    ctl: &'a crate::filesystem::ops::OpControl,
    out_dir: Option<&'a Path>,
    password: &'a str,
    /// Whether the password was typed (only then may it be saved for this file).
    typed: bool,
    job: &'a EncryptJob,
}

fn encrypt_one(s: &AppState, cx: &EncryptCtx<'_>, src: &str) -> Result<EncryptItemResult> {
    let req = EncryptRequest {
        source: Path::new(src),
        out_dir: cx.out_dir,
        password: cx.password,
        kdf: s.kdf,
        chunk_size: DEFAULT_CHUNK_SIZE,
        with_recovery: cx.job.with_recovery,
        on_conflict: cx.job.on_conflict,
        remove_original: cx.job.remove_original,
        out_name: None,
    };
    let mut emit = |info: &ProgressInfo| {
        emit_progress(
            cx.app,
            &ProgressEvent {
                op_id: cx.op_id,
                item_index: cx.item_index,
                item_count: cx.item_count,
                info,
            },
        );
    };
    let out = encrypt_path(&req, cx.ctl, &mut emit)?;

    let output = out.output.to_string_lossy().into_owned();
    let kind = kind_str(out.kind);
    let record = ItemRecord {
        id: uuid::Uuid::new_v4().to_string(),
        name: out.name.clone(),
        kind: kind.to_owned(),
        original_path: Some(src.to_owned()),
        encrypted_path: output.clone(),
        original_size: out.original_size,
        encrypted_size: out.encrypted_size,
        created_at: out.created_at,
        last_opened_at: None,
        format_version: FORMAT_VERSION,
        algorithm: CipherId::Aes256Gcm.name().to_owned(),
        has_saved_password: false,
        has_recovery: out.recovery_key.is_some(),
        favorite: false,
        file_count: out.file_count,
    };
    // The encrypted file already exists and is valid; a bookkeeping failure must not turn a
    // successful encryption into an error (and must never trigger anything destructive).
    let item = s.db.upsert_item(&record).ok();

    let mut password_saved = false;
    let mut password_save_error = None;
    if cx.job.save_password && cx.typed {
        let saved = s.creds.upsert_for_path(NewEntry {
            name: out.name.clone(),
            kind: kind.to_owned(),
            original_path: Some(src.to_owned()),
            encrypted_path: Some(output.clone()),
            password: cx.password.to_owned(),
            notes: String::new(),
            item_id: item.as_ref().map(|i| i.id.clone()),
        });
        match saved {
            Ok(_) => {
                password_saved = true;
                if let Some(i) = &item {
                    let _ = s.db.set_item_saved_password(&i.id, true);
                }
                s.record(Event::PasswordSaved, Some(&out.name), "ok");
            }
            Err(e) => password_save_error = Some(e),
        }
    }

    s.record(Event::Encrypt, Some(&out.name), "ok");
    if out.recovery_key.is_some() {
        s.record(Event::RecoveryKeyCreate, Some(&out.name), "ok");
    }

    Ok(EncryptItemResult {
        path: src.to_owned(),
        ok: true,
        output: Some(output),
        name: Some(out.name),
        kind: Some(kind),
        original_size: out.original_size,
        encrypted_size: out.encrypted_size,
        file_count: out.file_count,
        removal: Some(out.removal),
        recovery_key: out
            .recovery_key
            .as_ref()
            .map(|k| k.to_display_string().to_string()),
        password_saved,
        password_save_error,
        error: None,
    })
}

/// Encrypt one or more files/folders, each into its own container.
#[tauri::command]
pub async fn encrypt_run(
    app: AppHandle,
    state: St<'_>,
    job: EncryptJob,
) -> Result<Vec<EncryptItemResult>> {
    blocking(&state, move |s| {
        if job.paths.is_empty() || job.paths.len() > 10_000 {
            return Err(AppError::InvalidInput("no items".into()));
        }
        let typed = match &job.password {
            PasswordSource::Typed { .. } => true,
            PasswordSource::Default => false,
            // A saved password belongs to an existing container; a recovery key cannot encrypt.
            _ => return Err(AppError::InvalidInput("password source".into())),
        };
        if job.save_password && !typed {
            return Err(AppError::InvalidInput(
                "only a typed password can be saved".into(),
            ));
        }
        // Fail up front so "save password" is never silently skipped after the work is done.
        if job.save_password && !s.creds.is_unlocked() {
            return Err(AppError::VaultLocked);
        }

        let guard = s.begin_op(&job.op_id)?;
        let resolved = resolve(s, &job.password, None, job.master.as_ref())?;
        let password = resolved.password()?;

        let out_dir: Option<PathBuf> = job
            .out_dir
            .clone()
            .or_else(|| s.settings().encryption.default_output_dir)
            .map(PathBuf::from);
        if let Some(d) = &out_dir {
            if !d.is_dir() {
                return Err(AppError::NotFound("output folder".into()));
            }
        }

        let count = job.paths.len();
        let mut results = Vec::with_capacity(count);
        for (index, src) in job.paths.iter().enumerate() {
            if guard.ctl.is_cancelled() {
                results.push(EncryptItemResult::failed(src, AppError::Cancelled));
                continue;
            }
            let cx = EncryptCtx {
                app: &app,
                op_id: &job.op_id,
                item_index: index,
                item_count: count,
                ctl: &guard.ctl,
                out_dir: out_dir.as_deref(),
                password,
                typed,
                job: &job,
            };
            match encrypt_one(s, &cx, src) {
                Ok(r) => results.push(r),
                Err(e) => {
                    s.record(
                        Event::Encrypt,
                        Some(&display_name(Path::new(src))),
                        &e.code().to_ascii_lowercase(),
                    );
                    results.push(EncryptItemResult::failed(src, e));
                }
            }
        }
        Ok(results)
    })
    .await
}

// ----- decrypt ------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptJob {
    pub op_id: String,
    pub path: String,
    pub password: PasswordSource,
    #[serde(default)]
    pub master: Option<Secret>,
    #[serde(default)]
    pub out_dir: Option<String>,
    pub on_conflict: ConflictPolicy,
    #[serde(default)]
    pub save_password: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptResult {
    pub output: String,
    pub name: String,
    pub kind: &'static str,
    pub bytes: u64,
    pub file_count: u64,
    pub dir_count: u64,
    pub password_saved: bool,
    pub password_save_error: Option<AppError>,
}

fn decrypt_inner(
    s: &AppState,
    app: &AppHandle,
    guard: &super::state::OpGuard,
    job: &DecryptJob,
) -> Result<DecryptResult> {
    let src = Path::new(&job.path);
    let probe = probe_container(src)?;
    let resolved = resolve(s, &job.password, Some(&job.path), job.master.as_ref())?;
    let typed_pw = match &job.password {
        PasswordSource::Typed { password } => Some(password.as_str().to_owned()),
        _ => None,
    };

    let out_dir = job.out_dir.as_deref().map(Path::new);
    if let Some(d) = out_dir {
        if !d.is_dir() {
            return Err(AppError::NotFound("output folder".into()));
        }
    }
    let req = DecryptRequest {
        source: src,
        out_dir,
        unlock: resolved.as_unlock(),
        on_conflict: job.on_conflict,
    };
    let mut emit = |info: &ProgressInfo| {
        emit_progress(
            app,
            &ProgressEvent {
                op_id: &job.op_id,
                item_index: 0,
                item_count: 1,
                info,
            },
        );
    };
    let out = decrypt_path(&req, &guard.ctl, &mut emit)?;
    let kind = kind_str(out.kind);

    // Track the file so it shows up in Recent. Bookkeeping only; failures are not fatal.
    let item_id = match s.db.item_by_path(&job.path) {
        Ok(Some(existing)) => {
            let _ = s.db.touch_item(&existing.id);
            Some(existing.id)
        }
        _ => {
            s.db.upsert_item(&ItemRecord {
                id: uuid::Uuid::new_v4().to_string(),
                name: out.name.clone(),
                kind: kind.to_owned(),
                original_path: None,
                encrypted_path: job.path.clone(),
                original_size: out.bytes,
                encrypted_size: probe.size,
                created_at: unix_secs(probe.modified).unwrap_or_else(now),
                last_opened_at: Some(now()),
                format_version: probe.inspection.version,
                algorithm: probe.inspection.cipher.to_owned(),
                has_saved_password: s.creds.has_for_path(&job.path).unwrap_or(false),
                has_recovery: probe.inspection.has_recovery_slot,
                favorite: false,
                file_count: out.file_count,
            })
            .ok()
            .map(|i| i.id)
        }
    };

    let mut password_saved = false;
    let mut password_save_error = None;
    if job.save_password {
        match typed_pw {
            Some(pw) => {
                let saved = s.creds.upsert_for_path(NewEntry {
                    name: out.name.clone(),
                    kind: kind.to_owned(),
                    original_path: None,
                    encrypted_path: Some(job.path.clone()),
                    password: pw,
                    notes: String::new(),
                    item_id: item_id.clone(),
                });
                match saved {
                    Ok(_) => {
                        password_saved = true;
                        if let Some(id) = &item_id {
                            let _ = s.db.set_item_saved_password(id, true);
                        }
                        s.record(Event::PasswordSaved, Some(&out.name), "ok");
                    }
                    Err(e) => password_save_error = Some(e),
                }
            }
            None => {
                password_save_error = Some(AppError::InvalidInput(
                    "only a typed password can be saved".into(),
                ))
            }
        }
    }

    s.record(Event::Decrypt, Some(&out.name), "ok");
    Ok(DecryptResult {
        output: out.output.to_string_lossy().into_owned(),
        name: out.name,
        kind,
        bytes: out.bytes,
        file_count: out.file_count,
        dir_count: out.dir_count,
        password_saved,
        password_save_error,
    })
}

/// Unlock one container and restore its contents next to it (or in `out_dir`). A wrong password
/// fails before any output exists and never modifies the encrypted file.
#[tauri::command]
pub async fn decrypt_run(app: AppHandle, state: St<'_>, job: DecryptJob) -> Result<DecryptResult> {
    blocking(&state, move |s| {
        if job.save_password && !s.creds.is_unlocked() {
            return Err(AppError::VaultLocked);
        }
        let guard = s.begin_op(&job.op_id)?;
        let result = decrypt_inner(s, &app, &guard, &job);
        if let Err(e) = &result {
            let name = display_name(Path::new(&job.path));
            s.record(Event::Decrypt, Some(&name), &e.code().to_ascii_lowercase());
        }
        result
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_existing_paths_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("a.veil");
        let other = dir.path().join("b.txt");
        std::fs::write(&good, b"x").unwrap();
        std::fs::write(&other, b"x").unwrap();
        let missing = dir.path().join("missing.veil");
        let folder = dir.path().join("docs");
        std::fs::create_dir(&folder).unwrap();
        let argv = vec![
            "veilock.exe".to_string(),
            good.to_string_lossy().into_owned(),
            other.to_string_lossy().into_owned(),
            folder.to_string_lossy().into_owned(),
            missing.to_string_lossy().into_owned(),
            "--flag".to_string(),
        ];
        assert_eq!(
            launch_paths(argv),
            vec![
                good.to_string_lossy().into_owned(),
                other.to_string_lossy().into_owned(),
                folder.to_string_lossy().into_owned(),
            ]
        );
    }
}
