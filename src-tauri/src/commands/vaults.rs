//! Encrypted file vaults: create, unlock, lock, manage and fill them.
//!
//! A vault's password is only ever handled here as a `Secret`/`PasswordSource`. A "saved" vault
//! password is an ordinary credential-vault entry keyed `vault://<id>`, so it is protected by the
//! Master Password exactly like the saved passwords of single files.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::errors::{AppError, Result};
use crate::filesystem::ops::{ConflictPolicy, ProgressInfo, Removal};
use crate::history::Event;
use crate::vault::credentials::{EntryUpdate, NewEntry};
use crate::vault::files::{ItemView, VaultView, DEFAULT_ICON};

use super::items::sensitive_gate;
use super::secret::{resolve, PasswordSource, Secret};
use super::state::{emit_progress, AppState, ProgressEvent};
use super::{blocking, St};

fn saved_key(id: &str) -> String {
    format!("vault://{id}")
}

fn saved_entry_id(s: &AppState, id: &str) -> Result<Option<String>> {
    let key = saved_key(id);
    Ok(s.creds
        .list()?
        .into_iter()
        .find(|e| e.encrypted_path.as_deref() == Some(key.as_str()))
        .map(|e| e.id))
}

/// Store (or replace) the vault's password in the credential vault.
fn save_vault_password(s: &AppState, view: &VaultView, password: &str) -> Result<()> {
    let id = &view.record.id;
    s.creds.upsert_for_path(NewEntry {
        name: view.record.name.clone(),
        kind: "vault".into(),
        original_path: None,
        encrypted_path: Some(saved_key(id)),
        password: password.to_owned(),
        notes: String::new(),
        item_id: Some(id.clone()),
    })?;
    s.db.set_vault_flags(id, None, Some(true), None)?;
    s.record(Event::PasswordSaved, Some(&view.record.name), "ok");
    Ok(())
}

fn outcome_code<T>(r: &Result<T>) -> String {
    match r {
        Ok(_) => "ok".to_owned(),
        Err(e) => e.code().to_ascii_lowercase(),
    }
}

// ----- listing ------------------------------------------------------------------------------

#[tauri::command]
pub async fn vaults_list(state: St<'_>) -> Result<Vec<VaultView>> {
    blocking(&state, |s| s.vaults.list()).await
}

#[tauri::command]
pub async fn vault_get(state: St<'_>, id: String) -> Result<VaultView> {
    blocking(&state, move |s| s.vaults.get(&id)).await
}

/// Items of an unlocked vault, newest first. A locked vault reveals nothing.
#[tauri::command]
pub async fn vault_items(state: St<'_>, id: String) -> Result<Vec<ItemView>> {
    blocking(&state, move |s| s.vaults.list_items(&id)).await
}

// ----- create / unlock / lock ---------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateJob {
    pub name: String,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub description: String,
    pub password: Secret,
    #[serde(default)]
    pub with_recovery: bool,
    #[serde(default)]
    pub save_password: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResult {
    pub vault: VaultView,
    /// Shown once; the app keeps no copy.
    pub recovery_key: Option<String>,
    pub password_saved: bool,
    pub password_save_error: Option<AppError>,
}

#[tauri::command]
pub async fn vault_create(state: St<'_>, job: CreateJob) -> Result<CreateResult> {
    blocking(&state, move |s| {
        if job.password.is_empty() {
            return Err(AppError::InvalidInput("empty password".into()));
        }
        // Checked up front so the user is not left with a vault whose password they asked to
        // save but which could not be saved.
        if job.save_password && !s.creds.is_unlocked() {
            return Err(AppError::VaultLocked);
        }
        let created = s.vaults.create(
            &job.name,
            job.icon.as_deref().unwrap_or(DEFAULT_ICON),
            &job.description,
            job.password.as_str(),
            job.with_recovery,
        )?;
        s.record(Event::VaultCreate, Some(&created.vault.record.name), "ok");
        if created.recovery_key.is_some() {
            s.record(
                Event::RecoveryKeyCreate,
                Some(&created.vault.record.name),
                "ok",
            );
        }

        let mut vault = created.vault;
        let mut password_saved = false;
        let mut password_save_error = None;
        if job.save_password {
            match save_vault_password(s, &vault, job.password.as_str()) {
                Ok(()) => {
                    password_saved = true;
                    vault.record.has_saved_password = true;
                }
                Err(e) => password_save_error = Some(e),
            }
        }
        Ok(CreateResult {
            vault,
            recovery_key: created
                .recovery_key
                .as_ref()
                .map(|k| k.to_display_string().to_string()),
            password_saved,
            password_save_error,
        })
    })
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockJob {
    pub id: String,
    pub password: PasswordSource,
    #[serde(default)]
    pub master: Option<Secret>,
    #[serde(default)]
    pub save_password: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResult {
    pub vault: VaultView,
    pub password_saved: bool,
    pub password_save_error: Option<AppError>,
}

#[tauri::command]
pub async fn vault_unlock(state: St<'_>, job: UnlockJob) -> Result<UnlockResult> {
    blocking(&state, move |s| {
        let before = s.vaults.get(&job.id)?;
        let name = before.record.name.clone();
        if job.save_password && !s.creds.is_unlocked() {
            return Err(AppError::VaultLocked);
        }
        let key = saved_key(&job.id);
        let resolved = resolve(s, &job.password, Some(&key), job.master.as_ref())?;
        let r = s.vaults.unlock(&job.id, &resolved.as_unlock());
        s.record(Event::VaultOpen, Some(&name), &outcome_code(&r));
        r?;

        let mut password_saved = false;
        let mut password_save_error = None;
        if job.save_password {
            match &job.password {
                PasswordSource::Typed { password } => {
                    match save_vault_password(s, &before, password.as_str()) {
                        Ok(()) => password_saved = true,
                        Err(e) => password_save_error = Some(e),
                    }
                }
                _ => {
                    password_save_error = Some(AppError::InvalidInput(
                        "only a typed password can be saved".into(),
                    ))
                }
            }
        }
        Ok(UnlockResult {
            vault: s.vaults.get(&job.id)?,
            password_saved,
            password_save_error,
        })
    })
    .await
}

/// Forget the vault's key. Fast (no I/O beyond one DB read), so it stays a plain command.
#[tauri::command]
pub fn vault_lock(state: St<'_>, id: String) -> Result<()> {
    let view = state.vaults.get(&id)?;
    state.vaults.lock(&id);
    state.record(Event::VaultLock, Some(&view.record.name), "ok");
    Ok(())
}

// ----- vault settings -----------------------------------------------------------------------

#[tauri::command]
pub async fn vault_rename(
    state: St<'_>,
    id: String,
    name: String,
    icon: Option<String>,
    description: String,
) -> Result<VaultView> {
    blocking(&state, move |s| {
        let old = s.vaults.get(&id)?;
        let view = s.vaults.rename(
            &id,
            &name,
            icon.as_deref().unwrap_or(&old.record.icon),
            &description,
        )?;
        s.record(Event::VaultRename, Some(&view.record.name), "ok");
        // Keep the saved entry's label in step when the credential vault happens to be open. If it
        // is not, the label is merely stale; the password itself is unaffected.
        if view.record.has_saved_password && s.creds.is_unlocked() {
            if let Ok(Some(entry)) = saved_entry_id(s, &id) {
                let mut upd = EntryUpdate::default();
                upd.name = Some(view.record.name.clone());
                let _ = s.creds.update(&entry, upd);
            }
        }
        Ok(view)
    })
    .await
}

#[tauri::command]
pub async fn vault_favorite(state: St<'_>, id: String, favorite: bool) -> Result<VaultView> {
    blocking(&state, move |s| {
        s.vaults.get(&id)?;
        s.db.set_vault_flags(&id, None, None, Some(favorite))?;
        s.vaults.get(&id)
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPasswordChanged {
    pub saved_password_updated: bool,
}

#[tauri::command]
pub async fn vault_change_password(
    state: St<'_>,
    id: String,
    current: PasswordSource,
    new_password: Secret,
    master: Option<Secret>,
) -> Result<VaultPasswordChanged> {
    blocking(&state, move |s| {
        if new_password.is_empty() {
            return Err(AppError::InvalidInput("empty password".into()));
        }
        sensitive_gate(s, master.as_ref())?;
        let view = s.vaults.get(&id)?;
        // A stale saved password would silently stop working, so the credential vault must be
        // open to update it before anything is changed.
        if view.record.has_saved_password && !s.creds.is_unlocked() {
            return Err(AppError::VaultLocked);
        }
        let key = saved_key(&id);
        let resolved = resolve(s, &current, Some(&key), master.as_ref())?;
        let r = s
            .vaults
            .change_password(&id, &resolved.as_unlock(), new_password.as_str());
        s.record(
            Event::PasswordChange,
            Some(&view.record.name),
            &outcome_code(&r),
        );
        r?;

        let mut updated = false;
        if view.record.has_saved_password {
            if let Some(entry) = saved_entry_id(s, &id)? {
                let mut upd = EntryUpdate::default();
                upd.password = Some(new_password.as_str().to_owned());
                s.creds.update(&entry, upd)?;
                updated = true;
            }
        }
        Ok(VaultPasswordChanged {
            saved_password_updated: updated,
        })
    })
    .await
}

#[tauri::command]
pub async fn vault_set_recovery(
    state: St<'_>,
    id: String,
    current: PasswordSource,
    master: Option<Secret>,
) -> Result<String> {
    blocking(&state, move |s| {
        sensitive_gate(s, master.as_ref())?;
        let view = s.vaults.get(&id)?;
        let key = saved_key(&id);
        let resolved = resolve(s, &current, Some(&key), master.as_ref())?;
        let rk = s.vaults.set_recovery(&id, &resolved.as_unlock())?;
        s.record(Event::RecoveryKeyCreate, Some(&view.record.name), "ok");
        Ok(rk.to_display_string().to_string())
    })
    .await
}

#[tauri::command]
pub async fn vault_remove_recovery(
    state: St<'_>,
    id: String,
    current: PasswordSource,
    master: Option<Secret>,
) -> Result<()> {
    blocking(&state, move |s| {
        sensitive_gate(s, master.as_ref())?;
        let view = s.vaults.get(&id)?;
        let key = saved_key(&id);
        let resolved = resolve(s, &current, Some(&key), master.as_ref())?;
        s.vaults.remove_recovery(&id, &resolved.as_unlock())?;
        s.record(Event::RecoveryKeyCreate, Some(&view.record.name), "removed");
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn vault_delete(
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
        let view = s.vaults.get(&id)?;
        if view.record.has_saved_password && !s.creds.is_unlocked() {
            return Err(AppError::VaultLocked);
        }
        let r = s.vaults.delete(&id);
        s.record(
            Event::VaultDelete,
            Some(&view.record.name),
            &outcome_code(&r),
        );
        r?;
        // The vault is gone; a saved password for it would only be a dangling secret.
        if view.record.has_saved_password {
            if let Some(entry) = saved_entry_id(s, &id)? {
                s.creds.delete(&entry)?;
                s.record(Event::PasswordDeleted, Some(&view.record.name), "ok");
            }
        }
        Ok(())
    })
    .await
}

// ----- contents -----------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddJob {
    pub op_id: String,
    pub vault_id: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub remove_original: bool,
    #[serde(default)]
    pub master: Option<Secret>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddResult {
    pub path: String,
    pub ok: bool,
    pub item: Option<ItemView>,
    pub removal: Option<Removal>,
    pub error: Option<AppError>,
}

impl AddResult {
    fn failed(path: &str, e: AppError) -> Self {
        Self {
            path: path.to_owned(),
            ok: false,
            item: None,
            removal: None,
            error: Some(e),
        }
    }
}

fn display_name(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map_or_else(|| p.to_owned(), |n| n.to_string_lossy().into_owned())
}

/// Move files and folders into an unlocked vault. Each path gets its own result.
#[tauri::command]
pub async fn vault_add_items(app: AppHandle, state: St<'_>, job: AddJob) -> Result<Vec<AddResult>> {
    blocking(&state, move |s| {
        if job.paths.is_empty() {
            return Err(AppError::InvalidInput("nothing selected".into()));
        }
        if job.remove_original {
            sensitive_gate(s, job.master.as_ref())?;
        }
        if !s.vaults.is_unlocked(&job.vault_id) {
            // get() also validates the id so the error is NotFound for unknown vaults.
            s.vaults.get(&job.vault_id)?;
            return Err(AppError::VaultLocked);
        }
        let guard = s.begin_op(&job.op_id)?;
        let count = job.paths.len();
        let mut results = Vec::with_capacity(count);
        for (index, src) in job.paths.iter().enumerate() {
            if guard.ctl.is_cancelled() {
                results.push(AddResult::failed(src, AppError::Cancelled));
                continue;
            }
            let mut emit = |info: &ProgressInfo| {
                emit_progress(
                    &app,
                    &ProgressEvent {
                        op_id: &job.op_id,
                        item_index: index,
                        item_count: count,
                        info,
                    },
                );
            };
            let r = s.vaults.add_item(
                &job.vault_id,
                Path::new(src),
                job.remove_original,
                &guard.ctl,
                &mut emit,
            );
            s.record(
                Event::VaultItemAdd,
                Some(&display_name(src)),
                &outcome_code(&r),
            );
            results.push(match r {
                Ok(out) => AddResult {
                    path: src.clone(),
                    ok: true,
                    item: Some(out.item),
                    removal: Some(out.removal),
                    error: None,
                },
                Err(e) => AddResult::failed(src, e),
            });
        }
        Ok(results)
    })
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractJob {
    pub op_id: String,
    pub vault_id: String,
    pub item_id: String,
    pub out_dir: String,
    pub on_conflict: ConflictPolicy,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractResult {
    pub output: String,
    pub name: String,
    pub kind: &'static str,
    pub bytes: u64,
    pub file_count: u64,
    pub dir_count: u64,
}

/// Restore one item from an unlocked vault into `out_dir`. The item stays in the vault.
#[tauri::command]
pub async fn vault_extract_item(
    app: AppHandle,
    state: St<'_>,
    job: ExtractJob,
) -> Result<ExtractResult> {
    blocking(&state, move |s| {
        let out_dir = Path::new(&job.out_dir);
        if !out_dir.is_dir() {
            return Err(AppError::NotFound("output folder".into()));
        }
        let guard = s.begin_op(&job.op_id)?;
        let mut emit = |info: &ProgressInfo| {
            emit_progress(
                &app,
                &ProgressEvent {
                    op_id: &job.op_id,
                    item_index: 0,
                    item_count: 1,
                    info,
                },
            );
        };
        let r = s.vaults.extract_item(
            &job.vault_id,
            &job.item_id,
            out_dir,
            job.on_conflict,
            &guard.ctl,
            &mut emit,
        );
        match r {
            Ok(out) => {
                s.record(Event::VaultItemExtract, Some(&out.name), "ok");
                Ok(ExtractResult {
                    output: out.output.to_string_lossy().into_owned(),
                    kind: super::files::kind_str(out.kind),
                    name: out.name,
                    bytes: out.bytes,
                    file_count: out.file_count,
                    dir_count: out.dir_count,
                })
            }
            Err(e) => {
                s.record(
                    Event::VaultItemExtract,
                    None,
                    &e.code().to_ascii_lowercase(),
                );
                Err(e)
            }
        }
    })
    .await
}

/// Delete one item from a vault. Irreversible, so the UI must have asked.
#[tauri::command]
pub async fn vault_remove_item(
    state: St<'_>,
    vault_id: String,
    item_id: String,
    confirm: bool,
    master: Option<Secret>,
) -> Result<()> {
    if !confirm {
        return Err(AppError::InvalidInput("confirmation required".into()));
    }
    blocking(&state, move |s| {
        sensitive_gate(s, master.as_ref())?;
        let name = s
            .vaults
            .list_items(&vault_id)?
            .into_iter()
            .find(|i| i.id == item_id)
            .map(|i| i.name);
        let r = s.vaults.remove_item(&vault_id, &item_id);
        s.record(Event::VaultItemRemove, name.as_deref(), &outcome_code(&r));
        r
    })
    .await
}

// ----- export / import ----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportJob {
    pub op_id: String,
    pub vault_id: String,
    pub dest_dir: String,
    pub on_conflict: ConflictPolicy,
}

/// Write the vault as a `.veilvault` bundle. Works while the vault is locked: the bundle is
/// exactly as protected as the vault itself.
#[tauri::command]
pub async fn vault_export(app: AppHandle, state: St<'_>, job: ExportJob) -> Result<String> {
    blocking(&state, move |s| {
        let view = s.vaults.get(&job.vault_id)?;
        let guard = s.begin_op(&job.op_id)?;
        let mut emit = |info: &ProgressInfo| {
            emit_progress(
                &app,
                &ProgressEvent {
                    op_id: &job.op_id,
                    item_index: 0,
                    item_count: 1,
                    info,
                },
            );
        };
        let r = s.vaults.export(
            &job.vault_id,
            Path::new(&job.dest_dir),
            job.on_conflict,
            &guard.ctl,
            &mut emit,
        );
        s.record(
            Event::VaultExport,
            Some(&view.record.name),
            &outcome_code(&r),
        );
        Ok(r?.to_string_lossy().into_owned())
    })
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportJob {
    pub op_id: String,
    pub bundle: String,
}

/// Import a `.veilvault` bundle as a new vault. The imported vault stays locked.
#[tauri::command]
pub async fn vault_import(app: AppHandle, state: St<'_>, job: ImportJob) -> Result<VaultView> {
    blocking(&state, move |s| {
        let guard = s.begin_op(&job.op_id)?;
        let mut emit = |info: &ProgressInfo| {
            emit_progress(
                &app,
                &ProgressEvent {
                    op_id: &job.op_id,
                    item_index: 0,
                    item_count: 1,
                    info,
                },
            );
        };
        let r = s
            .vaults
            .import(Path::new(&job.bundle), &guard.ctl, &mut emit);
        let name = r.as_ref().ok().map(|v| v.record.name.clone());
        s.record(Event::VaultImport, name.as_deref(), &outcome_code(&r));
        r
    })
    .await
}
