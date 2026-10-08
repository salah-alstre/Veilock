//! File-level encrypt / decrypt workflows: staging, verification, atomic publication and cleanup.
//!
//! The ordering here is the data-safety contract of the whole application:
//!
//! **Encrypt**
//! 1. Write the container to a hidden temp file *next to the destination* (same volume, so the
//!    final rename is atomic).
//! 2. `fsync`, then re-read the temp file from byte 0 with the in-memory key and compare the
//!    SHA-256 and length of what it decrypts to against what was read from the source.
//! 3. Re-check that the source did not change while we were reading it.
//! 4. Publish: rename into place without ever overwriting something the user did not agree to
//!    overwrite.
//! 5. Only now, and only if the caller asked, remove the original — and for folders only the exact
//!    entries that were archived, never a blanket recursive delete.
//!
//! **Decrypt**
//! 1. Unlock and authenticate the metadata *before* touching the file system, so a wrong password
//!    never creates, changes or deletes anything.
//! 2. Stream into a hidden temp file/folder. AEAD plaintext is released chunk by chunk before the
//!    whole stream is authenticated, so nothing is published until the final chunk checks out.
//! 3. Publish with the caller's conflict policy.
//!
//! Any error or cancellation drops the temp guard, which removes the partial output. The source
//! (or, on decrypt, the container) is never modified on a failure path.

use super::archive::{scan_folder, ArchiveExtractor, ArchiveReader, CurrentItem, EntryKind, Scan};
use super::names::{safe_output_name, sanitize_for_output, validate_component, MAX_COMPONENT_LEN};
use crate::crypto::container::{self, Inspection, SealOptions, Unlock};
use crate::crypto::kdf::KdfParams;
use crate::crypto::metadata::Metadata;
use crate::crypto::params::{ContainerKind, TAG_LEN};
use crate::crypto::recovery::RecoveryKey;
use crate::errors::{AppError, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Extension of encrypted containers.
pub const CONTAINER_EXT: &str = "veil";
/// How many " (n)" suffixes `KeepBoth` will try before giving up.
const MAX_KEEP_BOTH: u32 = 10_000;
/// Progress events are throttled so a fast disk cannot flood the UI.
const EMIT_INTERVAL: Duration = Duration::from_millis(100);

/// What to do when the destination name is already taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConflictPolicy {
    /// Refuse with `OutputExists`; the UI then asks the user.
    Fail,
    /// Pick "name (2)", "name (3)", ...
    KeepBoth,
    /// Replace the existing item (only ever chosen explicitly by the user).
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Scanning,
    Encrypting,
    Verifying,
    Decrypting,
    Exporting,
    Importing,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressInfo {
    pub phase: Phase,
    pub done_bytes: u64,
    pub total_bytes: u64,
    pub current_item: String,
    pub bytes_per_sec: u64,
    pub eta_secs: Option<u64>,
}

/// Cancellation flag plus the shared "current item" label of one running operation.
#[derive(Clone)]
pub struct OpControl {
    pub cancel: Arc<AtomicBool>,
    pub current: CurrentItem,
}

impl OpControl {
    pub fn new() -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            current: Arc::new(Mutex::new(String::new())),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub(crate) fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(AppError::Cancelled)
        } else {
            Ok(())
        }
    }
}

impl Default for OpControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Turns the cumulative byte counts coming out of the stream layer into throttled progress events
/// with speed and ETA.
pub(crate) struct Meter<'a> {
    sink: &'a mut dyn FnMut(&ProgressInfo),
    current: CurrentItem,
    phase: Phase,
    total: u64,
    started: Instant,
    last_emit: Option<Instant>,
}

impl<'a> Meter<'a> {
    pub(crate) fn new(sink: &'a mut dyn FnMut(&ProgressInfo), current: CurrentItem) -> Self {
        Self {
            sink,
            current,
            phase: Phase::Scanning,
            total: 0,
            started: Instant::now(),
            last_emit: None,
        }
    }

    pub(crate) fn begin(&mut self, phase: Phase, total: u64) {
        self.phase = phase;
        self.total = total;
        self.started = Instant::now();
        self.last_emit = None;
        self.emit(0);
    }

    pub(crate) fn update(&mut self, done: u64) {
        let due = self
            .last_emit
            .map_or(true, |t| t.elapsed() >= EMIT_INTERVAL);
        if due || done >= self.total {
            self.emit(done);
        }
    }

    fn emit(&mut self, done: u64) {
        let done = done.min(self.total.max(done));
        let secs = self.started.elapsed().as_secs_f64();
        let rate = if secs > 0.25 { done as f64 / secs } else { 0.0 };
        let eta = if rate > 0.0 && self.total >= done {
            Some(((self.total - done) as f64 / rate).ceil() as u64)
        } else {
            None
        };
        let current_item = self.current.lock().map(|g| g.clone()).unwrap_or_default();
        self.last_emit = Some(Instant::now());
        (self.sink)(&ProgressInfo {
            phase: self.phase,
            done_bytes: done,
            total_bytes: self.total,
            current_item,
            bytes_per_sec: rate as u64,
            eta_secs: eta,
        });
    }
}

/// Removes a staged temp file or folder unless disarmed. This is what makes cancel and every
/// error path leave no partial output behind.
pub(crate) struct TempGuard {
    path: PathBuf,
    armed: bool,
}

impl TempGuard {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            remove_any(&self.path);
        }
    }
}

/// Best-effort removal that never follows symlinks.
pub(crate) fn remove_any(p: &Path) {
    if let Ok(md) = fs::symlink_metadata(p) {
        if md.file_type().is_symlink() {
            if fs::remove_file(p).is_err() {
                let _ = fs::remove_dir(p);
            }
        } else if md.is_dir() {
            let _ = fs::remove_dir_all(p);
        } else {
            let _ = fs::remove_file(p);
        }
    }
}

pub(crate) fn temp_name(tag: &str) -> String {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(".veilock-{tag}-{hex}.tmp")
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// "report.pdf" -> "report (2).pdf"; "Photos" -> "Photos (2)".
fn numbered(name: &str, n: u32) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => {
            format!("{} ({n}){}", &name[..i], &name[i..])
        }
        _ => format!("{name} ({n})"),
    }
}

fn container_name(source_name: &str) -> String {
    let budget = MAX_COMPONENT_LEN - CONTAINER_EXT.len() - 1;
    let stem: String = sanitize_for_output(source_name)
        .chars()
        .take(budget)
        .collect();
    format!("{stem}.{CONTAINER_EXT}")
}

fn source_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| AppError::InvalidInput("the item has no usable name".into()))
}

fn parent_dir(path: &Path) -> Result<PathBuf> {
    let p = path
        .parent()
        .ok_or_else(|| AppError::InvalidInput("the item has no parent folder".into()))?;
    Ok(if p.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        p.to_path_buf()
    })
}

fn resolve_out_dir(requested: Option<&Path>, fallback_from: &Path) -> Result<PathBuf> {
    let dir = match requested {
        Some(d) => d.to_path_buf(),
        None => parent_dir(fallback_from)?,
    };
    if !fs::metadata(&dir)?.is_dir() {
        return Err(AppError::InvalidInput(
            "the output location is not a folder".into(),
        ));
    }
    Ok(dir)
}

fn exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

fn already_exists() -> io::Error {
    io::Error::from(io::ErrorKind::AlreadyExists)
}

/// Move `tmp` to `dst` only if `dst` does not exist. Never overwrites.
fn publish_no_clobber(tmp: &Path, dst: &Path, is_dir: bool) -> io::Result<()> {
    if is_dir {
        // Windows refuses to rename a folder onto an existing one, but the error kind varies, so
        // check explicitly and re-check after a failure.
        if exists(dst) {
            return Err(already_exists());
        }
        return match fs::rename(tmp, dst) {
            Ok(()) => Ok(()),
            Err(e) if exists(dst) => {
                let _ = e;
                Err(already_exists())
            }
            Err(e) => Err(e),
        };
    }
    // A hard link fails atomically if the name is taken, which is exactly "create if absent".
    match fs::hard_link(tmp, dst) {
        Ok(()) => {
            let _ = fs::remove_file(tmp);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(e),
        Err(_) => {
            // Volume without hard links (FAT, some network shares): reserve the name atomically
            // with create_new, then rename over the reservation.
            OpenOptions::new().write(true).create_new(true).open(dst)?;
            fs::rename(tmp, dst).inspect_err(|_| {
                let _ = fs::remove_file(dst);
            })
        }
    }
}

pub(crate) fn publish(
    tmp: &Path,
    dir: &Path,
    name: &str,
    is_dir: bool,
    policy: ConflictPolicy,
) -> Result<PathBuf> {
    match policy {
        ConflictPolicy::Fail => {
            let dst = dir.join(name);
            match publish_no_clobber(tmp, &dst, is_dir) {
                Ok(()) => Ok(dst),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    Err(AppError::OutputExists(name.to_owned()))
                }
                Err(e) => Err(e.into()),
            }
        }
        ConflictPolicy::KeepBoth => {
            for n in 1..=MAX_KEEP_BOTH {
                let candidate = if n == 1 {
                    name.to_owned()
                } else {
                    numbered(name, n)
                };
                let dst = dir.join(&candidate);
                match publish_no_clobber(tmp, &dst, is_dir) {
                    Ok(()) => return Ok(dst),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(AppError::OutputExists(name.to_owned()))
        }
        ConflictPolicy::Replace => {
            let dst = dir.join(name);
            match fs::symlink_metadata(&dst) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    publish_no_clobber(tmp, &dst, is_dir)?;
                }
                Err(e) => return Err(e.into()),
                Ok(existing) => {
                    if !is_dir && !existing.is_dir() {
                        // Atomic replace of a file by a file.
                        fs::rename(tmp, &dst)?;
                    } else {
                        // Move the old item aside first so a failure can be rolled back instead
                        // of leaving the user with neither.
                        let old = dir.join(temp_name("old"));
                        fs::rename(&dst, &old)?;
                        match fs::rename(tmp, &dst) {
                            Ok(()) => remove_any(&old),
                            Err(e) => {
                                let _ = fs::rename(&old, &dst);
                                return Err(e.into());
                            }
                        }
                    }
                }
            }
            Ok(dst)
        }
    }
}

/// Size and modification time of a single-file source, used to detect it changing under us.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    mtime: Option<SystemTime>,
}

fn stamp(path: &Path) -> Result<FileStamp> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() || !md.is_file() {
        return Err(AppError::SourceChanged);
    }
    Ok(FileStamp {
        len: md.len(),
        mtime: md.modified().ok(),
    })
}

enum SourceSnapshot {
    File(FileStamp),
    Folder(Scan),
}

impl SourceSnapshot {
    /// Has the source stayed exactly as it was when we started reading it?
    fn unchanged(&self, path: &Path, cancel: &AtomicBool) -> Result<bool> {
        match self {
            SourceSnapshot::File(before) => Ok(stamp(path).is_ok_and(|now| &now == before)),
            SourceSnapshot::Folder(before) => {
                let now = scan_folder(path, cancel)?;
                Ok(before.same_as(&now))
            }
        }
    }
}

/// Delete exactly what was archived. A folder is emptied entry by entry and the (by then empty)
/// directories are removed non-recursively, so a file that appeared after the scan is never
/// deleted — the directory simply stays.
fn remove_scanned(scan: &Scan, root: &Path) -> io::Result<()> {
    for e in &scan.entries {
        if matches!(e.kind, EntryKind::File { .. }) {
            fs::remove_file(&e.abs)?;
        }
    }
    for e in scan.entries.iter().rev() {
        if matches!(e.kind, EntryKind::Dir) {
            fs::remove_dir(&e.abs)?;
        }
    }
    fs::remove_dir(root)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "status", content = "code")]
pub enum Removal {
    NotRequested,
    Removed,
    /// The encrypted copy is intact and verified; only deleting the original failed.
    Failed(String),
}

pub struct EncryptRequest<'a> {
    pub source: &'a Path,
    /// Defaults to the folder containing the source.
    pub out_dir: Option<&'a Path>,
    pub password: &'a str,
    pub kdf: KdfParams,
    pub chunk_size: u32,
    pub with_recovery: bool,
    pub on_conflict: ConflictPolicy,
    pub remove_original: bool,
    /// Explicit output file name (used by vaults so stored items get opaque names). When `None`
    /// the name is derived from the source name. Must be a single safe path component.
    pub out_name: Option<&'a str>,
}

pub struct EncryptOutcome {
    pub output: PathBuf,
    pub name: String,
    pub kind: ContainerKind,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
    pub created_at: i64,
    /// Shown to the user exactly once by the caller; never persisted.
    pub recovery_key: Option<RecoveryKey>,
    pub removal: Removal,
}

pub fn encrypt_path(
    req: &EncryptRequest<'_>,
    ctl: &OpControl,
    on_progress: &mut dyn FnMut(&ProgressInfo),
) -> Result<EncryptOutcome> {
    let mut meter = Meter::new(on_progress, ctl.current.clone());
    ctl.check()?;

    let src_md = fs::symlink_metadata(req.source)?;
    if src_md.file_type().is_symlink() {
        return Err(AppError::UnsafePath(
            "the item is a symbolic link or junction".into(),
        ));
    }
    let is_dir = src_md.is_dir();
    if !is_dir && !src_md.is_file() {
        return Err(AppError::InvalidInput(
            "only files and folders can be encrypted".into(),
        ));
    }
    let name = source_name(req.source)?;
    let out_dir = resolve_out_dir(req.out_dir, req.source)?;
    if is_dir {
        // Writing the container inside the folder being archived would make it part of its own
        // input.
        let out_c = fs::canonicalize(&out_dir)?;
        let src_c = fs::canonicalize(req.source)?;
        if out_c.starts_with(&src_c) {
            return Err(AppError::InvalidInput(
                "the output location is inside the folder being encrypted".into(),
            ));
        }
    }
    let out_name = match req.out_name {
        Some(n) => {
            validate_component(n)?;
            n.to_string()
        }
        None => container_name(&name),
    };
    if req.on_conflict == ConflictPolicy::Fail && exists(&out_dir.join(&out_name)) {
        return Err(AppError::OutputExists(out_name));
    }

    let (snapshot, total, original_size, file_count, dir_count, kind) = if is_dir {
        meter.begin(Phase::Scanning, 0);
        let scan = scan_folder(req.source, &ctl.cancel)?;
        let t = scan.stream_len();
        let (c, f, d) = (scan.content_bytes, scan.file_count, scan.dir_count);
        (
            SourceSnapshot::Folder(scan),
            t,
            c,
            f,
            d,
            ContainerKind::Archive,
        )
    } else {
        let st = stamp(req.source)?;
        let len = st.len;
        (
            SourceSnapshot::File(st),
            len,
            len,
            1,
            0,
            ContainerKind::File,
        )
    };

    let created_at = unix_now();
    let opts = SealOptions {
        password: req.password,
        kdf: req.kdf,
        chunk_size: req.chunk_size,
        with_recovery: req.with_recovery,
        kind,
        metadata: Metadata {
            name: name.clone(),
            kind: if is_dir { "folder" } else { "file" }.into(),
            original_size,
            created_at,
            file_count,
            dir_count,
            app_version: env!("CARGO_PKG_VERSION").into(),
        },
        expected_plaintext_len: Some(total),
    };

    let tmp_path = out_dir.join(temp_name("enc"));
    let mut guard = TempGuard::new(tmp_path.clone());
    let tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;
    let mut w = BufWriter::with_capacity(256 * 1024, tmp_file);

    meter.begin(Phase::Encrypting, total);
    let sealed = {
        let mut cb = |n: u64| -> Result<()> {
            ctl.check()?;
            meter.update(n);
            Ok(())
        };
        match &snapshot {
            SourceSnapshot::File(_) => {
                let mut f = File::open(req.source)?;
                *ctl.current.lock().map_err(|_| poisoned())? = name.clone();
                container::seal(&mut f, &mut w, &opts, &mut cb)?
            }
            SourceSnapshot::Folder(scan) => {
                let mut r = ArchiveReader::new(scan, ctl.current.clone());
                container::seal(&mut r, &mut w, &opts, &mut cb)?
            }
        }
    };
    w.flush()?;
    let tmp_file = w.into_inner().map_err(|e| e.into_error())?;
    // Data must be on disk before we verify it, or we would be verifying the OS cache.
    tmp_file.sync_all()?;
    let encrypted_size = tmp_file.metadata()?.len();
    drop(tmp_file);

    // Verify from the start of the file using the in-memory key (no Argon2 re-run).
    meter.begin(Phase::Verifying, sealed.plaintext_len);
    {
        let mut cb = |n: u64| -> Result<()> {
            ctl.check()?;
            meter.update(n);
            Ok(())
        };
        let mut vf = File::open(&tmp_path)?;
        container::verify(
            &mut vf,
            &sealed.dek,
            &sealed.plaintext_sha256,
            sealed.plaintext_len,
            &mut cb,
        )?;
    }

    ctl.check()?;
    if !snapshot.unchanged(req.source, &ctl.cancel)? {
        return Err(AppError::SourceChanged);
    }

    let output = publish(&tmp_path, &out_dir, &out_name, false, req.on_conflict)?;
    guard.disarm();

    let removal = if !req.remove_original {
        Removal::NotRequested
    } else {
        // Re-check immediately before deleting: the verified copy matches the snapshot, so if the
        // source moved on since, the original holds data the container does not.
        match snapshot.unchanged(req.source, &ctl.cancel) {
            Ok(true) => {
                let r = match &snapshot {
                    SourceSnapshot::File(_) => fs::remove_file(req.source),
                    SourceSnapshot::Folder(scan) => remove_scanned(scan, req.source),
                };
                match r {
                    Ok(()) => Removal::Removed,
                    Err(e) => Removal::Failed(AppError::from(e).code().to_owned()),
                }
            }
            Ok(false) => Removal::Failed(AppError::SourceChanged.code().to_owned()),
            Err(e) => Removal::Failed(e.code().to_owned()),
        }
    };

    Ok(EncryptOutcome {
        output,
        name,
        kind,
        original_size,
        encrypted_size,
        file_count,
        dir_count,
        created_at,
        recovery_key: sealed.recovery_key,
        removal,
    })
}

pub(crate) fn poisoned() -> AppError {
    AppError::Internal("progress state unavailable".into())
}

pub struct DecryptRequest<'a> {
    pub source: &'a Path,
    /// Defaults to the folder containing the container.
    pub out_dir: Option<&'a Path>,
    pub unlock: Unlock<'a>,
    pub on_conflict: ConflictPolicy,
}

pub struct DecryptOutcome {
    pub output: PathBuf,
    pub name: String,
    pub kind: ContainerKind,
    pub bytes: u64,
    pub file_count: u64,
    pub dir_count: u64,
}

pub fn decrypt_path(
    req: &DecryptRequest<'_>,
    ctl: &OpControl,
    on_progress: &mut dyn FnMut(&ProgressInfo),
) -> Result<DecryptOutcome> {
    let mut meter = Meter::new(on_progress, ctl.current.clone());
    ctl.check()?;

    let mut src = File::open(req.source)?;
    let src_len = src.metadata()?.len();

    // Everything up to and including the metadata is authenticated before any output exists.
    let opened = container::open(&mut src, &req.unlock)?;
    let is_dir = match (opened.header.kind, opened.metadata.kind.as_str()) {
        (ContainerKind::File, "file") => false,
        (ContainerKind::Archive, "folder") => true,
        _ => return Err(AppError::Corrupted("inconsistent container type".into())),
    };
    let out_name = safe_output_name(&opened.metadata.name)?;
    let out_dir = resolve_out_dir(req.out_dir, req.source)?;
    if req.on_conflict == ConflictPolicy::Fail && exists(&out_dir.join(&out_name)) {
        return Err(AppError::OutputExists(out_name));
    }

    // The plaintext length is the ciphertext length minus one tag per chunk.
    let data_len = src_len.saturating_sub(opened.data_offset);
    let per_chunk = u64::from(opened.header.chunk_size) + TAG_LEN as u64;
    let total = data_len.saturating_sub(data_len.div_ceil(per_chunk) * TAG_LEN as u64);

    let tmp_path = out_dir.join(temp_name("dec"));
    let mut guard = TempGuard::new(tmp_path.clone());
    meter.begin(Phase::Decrypting, total);

    let mut cb = |n: u64| -> Result<()> {
        ctl.check()?;
        meter.update(n);
        Ok(())
    };

    let (bytes, file_count, dir_count) = if is_dir {
        fs::create_dir(&tmp_path)?;
        let mut ex = ArchiveExtractor::new(&tmp_path, ctl.current.clone());
        let n = container::decrypt_body(&mut src, &opened, &mut ex, &mut cb)?;
        let (files, dirs) = ex.finish()?;
        if files != opened.metadata.file_count || dirs != opened.metadata.dir_count {
            return Err(AppError::Corrupted("item counts do not match".into()));
        }
        (n, files, dirs)
    } else {
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        let mut w = BufWriter::with_capacity(256 * 1024, f);
        *ctl.current.lock().map_err(|_| poisoned())? = out_name.clone();
        let n = container::decrypt_body(&mut src, &opened, &mut w, &mut cb)?;
        if n != opened.metadata.original_size {
            return Err(AppError::Corrupted("size does not match".into()));
        }
        w.flush()?;
        let f = w.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        (n, 1, 0)
    };
    drop(src);

    ctl.check()?;
    let output = publish(&tmp_path, &out_dir, &out_name, is_dir, req.on_conflict)?;
    guard.disarm();

    Ok(DecryptOutcome {
        output,
        name: opened.metadata.name.clone(),
        kind: opened.header.kind,
        bytes,
        file_count,
        dir_count,
    })
}

/// Clear-text facts about a file on disk, or `NotAContainer`. Nothing returned is authenticated.
pub struct Probe {
    pub inspection: Inspection,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

pub fn probe_container(path: &Path) -> Result<Probe> {
    let mut f = File::open(path)?;
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(AppError::NotAContainer);
    }
    let inspection = container::inspect(&mut f)?;
    Ok(Probe {
        inspection,
        size: md.len(),
        modified: md.modified().ok(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    const PW: &str = "correct horse battery staple";

    fn enc_req<'a>(src: &'a Path, out: &'a Path) -> EncryptRequest<'a> {
        EncryptRequest {
            source: src,
            out_dir: Some(out),
            password: PW,
            kdf: KdfParams::FLOOR,
            chunk_size: 4096,
            with_recovery: false,
            on_conflict: ConflictPolicy::Fail,
            remove_original: false,
            out_name: None,
        }
    }

    fn dec_req<'a>(
        src: &'a Path,
        out: &'a Path,
        pw: &'a str,
        policy: ConflictPolicy,
    ) -> DecryptRequest<'a> {
        DecryptRequest {
            source: src,
            out_dir: Some(out),
            unlock: Unlock::Password(pw),
            on_conflict: policy,
        }
    }

    fn encrypt(req: &EncryptRequest<'_>) -> Result<EncryptOutcome> {
        encrypt_path(req, &OpControl::new(), &mut |_| {})
    }

    fn decrypt(req: &DecryptRequest<'_>) -> Result<DecryptOutcome> {
        decrypt_path(req, &OpControl::new(), &mut |_| {})
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    fn pseudo_random(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        rand::rngs::OsRng.fill_bytes(&mut v);
        v
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// Encrypt `data` stored under `name`, delete the original, decrypt, compare bytes.
    fn roundtrip_file(name: &str, data: &[u8]) {
        let t = TempDir::new().unwrap();
        let src_dir = t.path().join("in");
        let enc_dir = t.path().join("enc");
        let out_dir = t.path().join("out");
        for d in [&src_dir, &enc_dir, &out_dir] {
            fs::create_dir(d).unwrap();
        }
        let src = src_dir.join(name);
        fs::write(&src, data).unwrap();

        let o = encrypt(&enc_req(&src, &enc_dir)).unwrap();
        assert_eq!(o.removal, Removal::NotRequested);
        assert!(src.exists(), "source must be untouched when not requested");
        assert_eq!(o.original_size, data.len() as u64);

        let ct = fs::read(&o.output).unwrap();
        if data.len() >= 16 {
            assert!(!contains(&ct, data), "ciphertext contains the plaintext");
        }

        // The "original" is only deleted after the container exists, mirroring the app flow.
        fs::remove_file(&src).unwrap();
        let d = decrypt(&dec_req(&o.output, &out_dir, PW, ConflictPolicy::Fail)).unwrap();
        assert_eq!(d.name, name);
        assert_eq!(fs::read(&d.output).unwrap(), data);
        assert_eq!(listing(&enc_dir).len(), 1, "no temp files left (encrypt)");
        assert_eq!(listing(&out_dir).len(), 1, "no temp files left (decrypt)");
    }

    #[test]
    fn text_file_roundtrip_and_ciphertext_hides_plaintext() {
        roundtrip_file(
            "test-file.txt",
            b"known contents: the quick brown fox 0123456789",
        );
    }

    #[test]
    fn empty_file_roundtrip() {
        roundtrip_file("empty.bin", b"");
    }

    #[test]
    fn multi_chunk_binary_roundtrip() {
        roundtrip_file("random.bin", &pseudo_random(100_000));
    }

    #[test]
    fn exact_chunk_boundary_roundtrip() {
        roundtrip_file("boundary.bin", &pseudo_random(4096 * 3));
    }

    #[test]
    fn unicode_arabic_and_spaced_names_roundtrip() {
        roundtrip_file("ملف سري.txt", "محتوى عربي".as_bytes());
        roundtrip_file("naïve café 日本語.dat", &pseudo_random(5000));
        roundtrip_file("name with   spaces .txt", b"x");
    }

    #[test]
    fn large_file_streams_and_roundtrips() {
        // ~12 MiB across many chunks, without ever holding the file in memory in the code path.
        let t = TempDir::new().unwrap();
        let src = t.path().join("big.bin");
        {
            let mut f = File::create(&src).unwrap();
            let block = pseudo_random(1024 * 1024);
            for _ in 0..12 {
                f.write_all(&block).unwrap();
            }
        }
        let enc_dir = t.path().join("e");
        let out_dir = t.path().join("o");
        fs::create_dir(&enc_dir).unwrap();
        fs::create_dir(&out_dir).unwrap();
        let mut req = enc_req(&src, &enc_dir);
        req.chunk_size = 1024 * 1024;
        let o = encrypt(&req).unwrap();
        let d = decrypt(&dec_req(&o.output, &out_dir, PW, ConflictPolicy::Fail)).unwrap();
        let (mut a, mut b) = (File::open(&src).unwrap(), File::open(&d.output).unwrap());
        let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
        loop {
            let na = crate::crypto::stream::read_full(&mut a, &mut ba).unwrap();
            let nb = crate::crypto::stream::read_full(&mut b, &mut bb).unwrap();
            assert_eq!(na, nb);
            assert_eq!(ba[..na], bb[..nb]);
            if na == 0 {
                break;
            }
        }
    }

    fn make_tree(root: &Path) {
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        fs::create_dir_all(root.join("empty dir")).unwrap();
        fs::create_dir_all(root.join("مجلد")).unwrap();
        fs::write(root.join("top.txt"), b"top level").unwrap();
        fs::write(root.join("a/one.bin"), pseudo_random(9000)).unwrap();
        fs::write(root.join("a/b/c/deep.txt"), b"deep file").unwrap();
        fs::write(root.join("مجلد/ملف.txt"), "نص".as_bytes()).unwrap();
        fs::write(root.join("zero.dat"), b"").unwrap();
    }

    fn tree_contents(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, Option<Vec<u8>>)>) {
            for e in fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let name = e.file_name().into_string().unwrap();
                let rel = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                if e.path().is_dir() {
                    out.push((rel.clone(), None));
                    walk(&e.path(), &rel, out);
                } else {
                    out.push((rel, Some(fs::read(e.path()).unwrap())));
                }
            }
        }
        let mut v = Vec::new();
        walk(root, "", &mut v);
        v.sort();
        v
    }

    #[test]
    fn nested_folder_roundtrip_with_removal() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("Private Photos");
        fs::create_dir(&src).unwrap();
        make_tree(&src);
        let expected = tree_contents(&src);
        let enc_dir = t.path().join("enc");
        let out_dir = t.path().join("out");
        fs::create_dir(&enc_dir).unwrap();
        fs::create_dir(&out_dir).unwrap();

        let mut req = enc_req(&src, &enc_dir);
        req.remove_original = true;
        let o = encrypt(&req).unwrap();
        assert_eq!(o.removal, Removal::Removed);
        assert!(
            !src.exists(),
            "original removed only after verified success"
        );
        assert_eq!(o.output.file_name().unwrap(), "Private Photos.veil");
        assert_eq!((o.file_count, o.dir_count), (5, 5));

        // Filenames must not leak into the container.
        let ct = fs::read(&o.output).unwrap();
        assert!(!contains(&ct, b"deep.txt") && !contains(&ct, b"top level"));

        let d = decrypt(&dec_req(&o.output, &out_dir, PW, ConflictPolicy::Fail)).unwrap();
        assert_eq!(d.kind, ContainerKind::Archive);
        assert_eq!(d.output.file_name().unwrap(), "Private Photos");
        assert_eq!(tree_contents(&d.output), expected);
        assert_eq!(listing(&out_dir), vec!["Private Photos"]);
    }

    #[test]
    fn empty_folder_roundtrip() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("nothing");
        fs::create_dir(&src).unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir(&o).unwrap();
        let enc = encrypt(&enc_req(&src, &e)).unwrap();
        let d = decrypt(&dec_req(&enc.output, &o, PW, ConflictPolicy::Fail)).unwrap();
        assert!(d.output.is_dir());
        assert_eq!(listing(&d.output).len(), 0);
    }

    #[test]
    fn folder_output_inside_source_is_rejected() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("proj");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("f.txt"), b"x").unwrap();
        let err = encrypt(&enc_req(&src, &src.join("sub"))).err().unwrap();
        assert!(matches!(err, AppError::InvalidInput(_)));
        assert_eq!(listing(&src.join("sub")).len(), 0);
    }

    #[test]
    fn wrong_password_creates_nothing_and_changes_nothing() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.txt");
        fs::write(&src, b"secret data").unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir(&o).unwrap();
        let enc = encrypt(&enc_req(&src, &e)).unwrap();
        let before = fs::read(&enc.output).unwrap();

        let err = decrypt(&dec_req(
            &enc.output,
            &o,
            "wrong password",
            ConflictPolicy::Fail,
        ))
        .err()
        .unwrap();
        assert!(matches!(err, AppError::WrongPassword));
        assert_eq!(listing(&o).len(), 0, "nothing may be created");
        assert_eq!(
            fs::read(&enc.output).unwrap(),
            before,
            "container unchanged"
        );
    }

    #[test]
    fn flipped_data_byte_fails_authentication_and_leaves_no_output() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.bin");
        fs::write(&src, pseudo_random(30_000)).unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir(&o).unwrap();
        let enc = encrypt(&enc_req(&src, &e)).unwrap();
        let mut ct = fs::read(&enc.output).unwrap();
        let at = ct.len() - 100;
        ct[at] ^= 0x01;
        fs::write(&enc.output, &ct).unwrap();

        let err = decrypt(&dec_req(&enc.output, &o, PW, ConflictPolicy::Fail))
            .err()
            .unwrap();
        assert!(matches!(err, AppError::Corrupted(_)), "got {err:?}");
        assert_eq!(listing(&o).len(), 0, "no partial plaintext may remain");
    }

    #[test]
    fn flipped_metadata_and_header_bytes_fail() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.txt");
        fs::write(&src, b"hello metadata").unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir(&o).unwrap();
        let enc = encrypt(&enc_req(&src, &e)).unwrap();
        let good = fs::read(&enc.output).unwrap();
        // header (chunk size field), metadata ciphertext
        for at in [12usize, 500, 520] {
            let mut bad = good.clone();
            bad[at] ^= 0x80;
            fs::write(&enc.output, &bad).unwrap();
            let r = decrypt(&dec_req(&enc.output, &o, PW, ConflictPolicy::Fail));
            assert!(r.is_err(), "flip at {at} must be rejected");
            assert_eq!(listing(&o).len(), 0);
        }
    }

    #[test]
    fn truncated_and_foreign_files_are_rejected() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.bin");
        fs::write(&src, pseudo_random(20_000)).unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir(&o).unwrap();
        let enc = encrypt(&enc_req(&src, &e)).unwrap();
        let ct = fs::read(&enc.output).unwrap();

        let cut = t.path().join("cut.veil");
        fs::write(&cut, &ct[..ct.len() - 5000]).unwrap();
        let err = decrypt(&dec_req(&cut, &o, PW, ConflictPolicy::Fail))
            .err()
            .unwrap();
        assert!(matches!(err, AppError::Corrupted(_)), "got {err:?}");

        let foreign = t.path().join("note.veil");
        fs::write(&foreign, b"just a text file").unwrap();
        let err = decrypt(&dec_req(&foreign, &o, PW, ConflictPolicy::Fail))
            .err()
            .unwrap();
        assert!(matches!(err, AppError::NotAContainer));
        assert!(probe_container(&foreign).is_err());
        assert!(
            probe_container(&enc.output)
                .unwrap()
                .inspection
                .has_password_slot
        );
        assert_eq!(listing(&o).len(), 0);
    }

    #[test]
    fn cancel_during_encrypt_keeps_source_and_cleans_temp() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.bin");
        let data = pseudo_random(200_000);
        fs::write(&src, &data).unwrap();
        let e = t.path().join("e");
        fs::create_dir(&e).unwrap();
        let ctl = OpControl::new();
        let flag = ctl.cancel.clone();
        let mut req = enc_req(&src, &e);
        req.remove_original = true;
        let err = encrypt_path(&req, &ctl, &mut |p| {
            if p.phase == Phase::Encrypting && p.done_bytes > 0 {
                flag.store(true, Ordering::Relaxed);
            }
        })
        .err()
        .unwrap();
        assert!(matches!(err, AppError::Cancelled), "got {err:?}");
        assert_eq!(fs::read(&src).unwrap(), data, "source untouched");
        assert_eq!(listing(&e).len(), 0, "temp file removed");
    }

    #[test]
    fn cancel_during_decrypt_cleans_temp() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.bin");
        fs::write(&src, pseudo_random(200_000)).unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir(&o).unwrap();
        let enc = encrypt(&enc_req(&src, &e)).unwrap();
        let ctl = OpControl::new();
        let flag = ctl.cancel.clone();
        let err = decrypt_path(
            &dec_req(&enc.output, &o, PW, ConflictPolicy::Fail),
            &ctl,
            &mut |p| {
                if p.done_bytes > 0 {
                    flag.store(true, Ordering::Relaxed);
                }
            },
        )
        .err()
        .unwrap();
        assert!(matches!(err, AppError::Cancelled));
        assert_eq!(listing(&o).len(), 0);
        assert!(enc.output.exists());
    }

    #[test]
    fn cancel_before_start_is_a_no_op() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.txt");
        fs::write(&src, b"x").unwrap();
        let ctl = OpControl::new();
        ctl.cancel.store(true, Ordering::Relaxed);
        let err = encrypt_path(&enc_req(&src, t.path()), &ctl, &mut |_| {})
            .err()
            .unwrap();
        assert!(matches!(err, AppError::Cancelled));
        assert_eq!(listing(t.path()), vec!["s.txt"]);
    }

    #[test]
    fn source_growing_during_encrypt_is_detected_and_nothing_is_deleted() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.bin");
        fs::write(&src, pseudo_random(100_000)).unwrap();
        let e = t.path().join("e");
        fs::create_dir(&e).unwrap();
        let mut req = enc_req(&src, &e);
        req.remove_original = true;
        let mut appended = false;
        let err = encrypt_path(&req, &OpControl::new(), &mut |p| {
            if p.phase == Phase::Encrypting && p.done_bytes > 0 && !appended {
                appended = true;
                let mut f = OpenOptions::new().append(true).open(&src).unwrap();
                f.write_all(b"more data").unwrap();
            }
        })
        .err()
        .unwrap();
        assert!(matches!(err, AppError::SourceChanged), "got {err:?}");
        assert!(src.exists());
        assert_eq!(listing(&e).len(), 0);
    }

    #[test]
    fn same_length_in_place_edit_during_encrypt_is_detected() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.bin");
        fs::write(&src, pseudo_random(100_000)).unwrap();
        let e = t.path().join("e");
        fs::create_dir(&e).unwrap();
        let mut req = enc_req(&src, &e);
        req.remove_original = true;
        let mut edited = false;
        let err = encrypt_path(&req, &OpControl::new(), &mut |p| {
            if p.phase == Phase::Verifying && !edited {
                edited = true;
                let f = OpenOptions::new().write(true).open(&src).unwrap();
                f.set_modified(SystemTime::now() + Duration::from_secs(5))
                    .unwrap();
            }
        })
        .err()
        .unwrap();
        assert!(matches!(err, AppError::SourceChanged), "got {err:?}");
        assert!(src.exists());
        assert_eq!(listing(&e).len(), 0);
    }

    #[test]
    fn conflict_policies_never_silently_overwrite() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("doc.txt");
        fs::write(&src, b"version one").unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir(&o).unwrap();

        // encrypt: Fail leaves the existing container alone
        let first = encrypt(&enc_req(&src, &e)).unwrap();
        let first_bytes = fs::read(&first.output).unwrap();
        let err = encrypt(&enc_req(&src, &e)).err().unwrap();
        assert!(matches!(err, AppError::OutputExists(_)));
        assert_eq!(fs::read(&first.output).unwrap(), first_bytes);
        assert_eq!(listing(&e), vec!["doc.txt.veil"]);

        // encrypt: KeepBoth
        let mut r = enc_req(&src, &e);
        r.on_conflict = ConflictPolicy::KeepBoth;
        let second = encrypt(&r).unwrap();
        assert_eq!(second.output.file_name().unwrap(), "doc.txt (2).veil");
        assert_eq!(fs::read(&first.output).unwrap(), first_bytes);

        // decrypt into a folder that already has the name
        fs::write(o.join("doc.txt"), b"precious existing file").unwrap();
        let err = decrypt(&dec_req(&first.output, &o, PW, ConflictPolicy::Fail))
            .err()
            .unwrap();
        assert!(matches!(err, AppError::OutputExists(_)));
        assert_eq!(
            fs::read(o.join("doc.txt")).unwrap(),
            b"precious existing file"
        );
        assert_eq!(listing(&o), vec!["doc.txt"]);

        let kb = decrypt(&dec_req(&first.output, &o, PW, ConflictPolicy::KeepBoth)).unwrap();
        assert_eq!(kb.output.file_name().unwrap(), "doc (2).txt");
        assert_eq!(fs::read(&kb.output).unwrap(), b"version one");
        assert_eq!(
            fs::read(o.join("doc.txt")).unwrap(),
            b"precious existing file"
        );

        let rep = decrypt(&dec_req(&first.output, &o, PW, ConflictPolicy::Replace)).unwrap();
        assert_eq!(fs::read(&rep.output).unwrap(), b"version one");
        assert_eq!(listing(&o), vec!["doc (2).txt", "doc.txt"]);
    }

    #[test]
    fn folder_conflict_policies() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("Album");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"from container").unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir_all(o.join("Album")).unwrap();
        fs::write(o.join("Album/mine.txt"), b"keep me").unwrap();
        let enc = encrypt(&enc_req(&src, &e)).unwrap();

        let err = decrypt(&dec_req(&enc.output, &o, PW, ConflictPolicy::Fail))
            .err()
            .unwrap();
        assert!(matches!(err, AppError::OutputExists(_)));
        assert_eq!(fs::read(o.join("Album/mine.txt")).unwrap(), b"keep me");

        let kb = decrypt(&dec_req(&enc.output, &o, PW, ConflictPolicy::KeepBoth)).unwrap();
        assert_eq!(kb.output.file_name().unwrap(), "Album (2)");
        assert_eq!(fs::read(o.join("Album/mine.txt")).unwrap(), b"keep me");

        decrypt(&dec_req(&enc.output, &o, PW, ConflictPolicy::Replace)).unwrap();
        assert_eq!(fs::read(o.join("Album/a.txt")).unwrap(), b"from container");
        assert!(!o.join("Album/mine.txt").exists());
        assert_eq!(listing(&o), vec!["Album", "Album (2)"]);
    }

    #[test]
    fn recovery_key_decrypts_and_a_wrong_one_does_not() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.txt");
        fs::write(&src, b"recoverable").unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir(&o).unwrap();
        let mut r = enc_req(&src, &e);
        r.with_recovery = true;
        let enc = encrypt(&r).unwrap();
        let rk = enc.recovery_key.expect("recovery key requested");
        let shown = rk.to_display_string();
        let parsed = RecoveryKey::parse(&shown).unwrap();

        let req = DecryptRequest {
            source: &enc.output,
            out_dir: Some(&o),
            unlock: Unlock::Recovery(&parsed),
            on_conflict: ConflictPolicy::Fail,
        };
        let d = decrypt(&req).unwrap();
        assert_eq!(fs::read(&d.output).unwrap(), b"recoverable");

        let other = RecoveryKey::generate();
        let req = DecryptRequest {
            source: &enc.output,
            out_dir: Some(&o),
            unlock: Unlock::Recovery(&other),
            on_conflict: ConflictPolicy::KeepBoth,
        };
        let err = decrypt(&req).err().unwrap();
        assert!(matches!(
            err,
            AppError::InvalidRecoveryKey | AppError::WrongPassword
        ));
        assert_eq!(listing(&o).len(), 1);
    }

    #[test]
    fn progress_reports_phases_and_totals() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.bin");
        fs::write(&src, pseudo_random(50_000)).unwrap();
        let (e, o) = (t.path().join("e"), t.path().join("o"));
        fs::create_dir(&e).unwrap();
        fs::create_dir(&o).unwrap();
        let mut seen: Vec<(Phase, u64, u64)> = Vec::new();
        let enc = encrypt_path(&enc_req(&src, &e), &OpControl::new(), &mut |p| {
            seen.push((p.phase, p.done_bytes, p.total_bytes))
        })
        .unwrap();
        assert!(seen
            .iter()
            .any(|s| s.0 == Phase::Encrypting && s.1 == 50_000));
        assert!(seen
            .iter()
            .any(|s| s.0 == Phase::Verifying && s.1 == 50_000));
        assert!(seen.iter().all(|s| s.1 <= s.2.max(s.1) && s.2 == 50_000));

        let mut last = (0, 0);
        decrypt_path(
            &dec_req(&enc.output, &o, PW, ConflictPolicy::Fail),
            &OpControl::new(),
            &mut |p| last = (p.done_bytes, p.total_bytes),
        )
        .unwrap();
        assert_eq!(last, (50_000, 50_000), "decrypt total is exact");
    }

    #[test]
    fn missing_source_and_missing_output_dir_map_to_clean_errors() {
        let t = TempDir::new().unwrap();
        let err = encrypt(&enc_req(&t.path().join("nope.txt"), t.path()))
            .err()
            .unwrap();
        assert!(matches!(err, AppError::NotFound(_)));

        let src = t.path().join("s.txt");
        fs::write(&src, b"x").unwrap();
        let err = encrypt(&enc_req(&src, &t.path().join("missing")))
            .err()
            .unwrap();
        assert!(matches!(err, AppError::NotFound(_)));
        assert_eq!(listing(t.path()), vec!["s.txt"]);
    }

    #[test]
    fn empty_password_is_refused_before_any_output() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.txt");
        fs::write(&src, b"x").unwrap();
        let e = t.path().join("e");
        fs::create_dir(&e).unwrap();
        let mut r = enc_req(&src, &e);
        r.password = "";
        assert!(matches!(
            encrypt(&r).err().unwrap(),
            AppError::InvalidInput(_)
        ));
        assert_eq!(listing(&e).len(), 0);
    }

    #[test]
    fn numbered_names() {
        assert_eq!(numbered("report.pdf", 2), "report (2).pdf");
        assert_eq!(numbered("Photos", 3), "Photos (3)");
        assert_eq!(numbered(".hidden", 2), ".hidden (2)");
        assert_eq!(numbered("a.txt.veil", 2), "a.txt (2).veil");
    }

    #[test]
    fn container_name_is_length_bounded() {
        let long = "x".repeat(400);
        assert!(container_name(&long).chars().count() <= MAX_COMPONENT_LEN);
        assert!(container_name("a.txt").ends_with(".txt.veil"));
    }

    #[test]
    fn plaintext_never_appears_in_temp_during_encrypt_listing() {
        // The only file ever created in the output dir is the container (or its hidden temp).
        let t = TempDir::new().unwrap();
        let src = t.path().join("s.txt");
        fs::write(&src, b"needle-needle-needle-needle").unwrap();
        let e = t.path().join("e");
        fs::create_dir(&e).unwrap();
        let enc = encrypt(&enc_req(&src, &e)).unwrap();
        let mut buf = Vec::new();
        File::open(&enc.output)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        assert!(!contains(&buf, b"needle"));
    }
}
