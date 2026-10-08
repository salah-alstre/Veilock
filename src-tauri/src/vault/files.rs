//! Encrypted file vaults: named collections of encrypted files and folders that are locked and
//! unlocked as a unit.
//!
//! On-disk layout, one directory per vault under `vault/vaults/<uuid>/`:
//!
//! ```text
//! vault.key        a `.veil` File container whose plaintext is the 32-byte vault secret S
//!                  (password slot, optional recovery slot)
//! index.enc        VLKVIDX1: the encrypted item list (names, sizes, dates)
//! items/<uuid>.veil  one ordinary `.veil` container per stored file or folder
//! ```
//!
//! Key hierarchy. The vault password (or recovery key) unwraps S through the normal container
//! machinery, so changing the password or adding/removing a recovery key rewrites only the key
//! slots of `vault.key`; S, the index and every item stay valid. Everything else is derived from S
//! with HKDF-SHA256:
//!
//! * index key  = HKDF(S, salt = constant, info = "veilock/vault-index")
//! * item key   = hex(HKDF(S, salt = item uuid, info = "veilock/vault-item")), used as the
//!   "password" of the item's own container. It is 256 bits of key material, so the container's
//!   Argon2id runs at the floor cost: stretching adds nothing against a uniformly random input.
//!
//! Index file `VLKVIDX1` (little-endian): `magic(8) | version u16 | nonce(12) | ct_len u32 | ct`.
//! AES-256-GCM, a fresh nonce per save, AAD = magic ‖ version. The AAD deliberately excludes the
//! vault id so that an imported vault (which gets a fresh id) still opens.
//!
//! Bundle `VLKVBND1` (`.veilvault`, export/import): `magic(8) | meta_len u32 | meta JSON |
//! VLKARCH1 archive of the vault directory`. The metadata JSON (vault name, icon, description,
//! creation date) is stored in the clear so that an import can name the vault before it is
//! unlocked; everything that holds user data remains encrypted. Import treats the bundle as
//! hostile: it is extracted into a staging directory, its structure is validated strictly, and only
//! then is it moved into place.
//!
//! Adding an item is "pending entry first": an index entry marked `pending` is written before the
//! container is created, and finalized afterwards. If the process dies in between, the next unlock
//! either finalizes the entry (the container exists and authenticates) or drops it. That makes it
//! safe to delete the original after verification even though the index is updated afterwards.

use crate::crypto::container::{self, SealOptions, Sealed, Unlock};
use crate::crypto::kdf::{hkdf32, KdfParams, Key32};
use crate::crypto::metadata::Metadata;
use crate::crypto::params::{ContainerKind, DEFAULT_CHUNK_SIZE, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::crypto::recovery::RecoveryKey;
use crate::errors::{AppError, Result};
use crate::filesystem::archive::{scan_folder, ArchiveExtractor, ArchiveReader, EntryKind, Scan};
use crate::filesystem::names::{sanitize_for_output, validate_component};
use crate::filesystem::ops::{
    decrypt_path, encrypt_path, poisoned, publish, remove_any, temp_name, ConflictPolicy,
    DecryptOutcome, DecryptRequest, EncryptRequest, Meter, OpControl, Phase, ProgressInfo, Removal,
    TempGuard,
};
use crate::storage::atomic::write_atomic;
use crate::storage::db::{now, Db, VaultRecord};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const BUNDLE_EXT: &str = "veilvault";
pub const DEFAULT_ICON: &str = "vault";

const KEY_FILE: &str = "vault.key";
const INDEX_FILE: &str = "index.enc";
const ITEMS_DIR: &str = "items";
const ITEM_EXT: &str = "veil";

const INDEX_MAGIC: &[u8; 8] = b"VLKVIDX1";
const INDEX_VERSION: u16 = 1;
const INDEX_HEADER_LEN: usize = 8 + 2 + NONCE_LEN + 4;
const INDEX_SALT: &[u8] = b"veilock/vault-index-salt/v1";
const INDEX_INFO: &[u8] = b"veilock/vault-index";
const ITEM_INFO: &[u8] = b"veilock/vault-item";

const BUNDLE_MAGIC: &[u8; 8] = b"VLKVBND1";
const BUNDLE_FORMAT: u16 = 1;
const MAX_BUNDLE_META: u32 = 64 * 1024;

/// A vault key file holds 32 bytes of secret; anything much larger is not ours.
const MAX_KEY_FILE: u64 = 64 * 1024;
/// Upper bound on the encrypted index, checked before it is read into memory.
const MAX_INDEX_FILE: u64 = 32 * 1024 * 1024;
const MAX_ITEMS: usize = 100_000;
const MAX_NAME_CHARS: usize = 100;
const MAX_DESCRIPTION_CHARS: usize = 500;
const MAX_ICON_CHARS: usize = 32;
const MAX_PASSWORD_CHARS: usize = 1024;
const PUMP_BUF: usize = 256 * 1024;

// ---------------------------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexItem {
    id: String,
    name: String,
    kind: String,
    original_size: u64,
    encrypted_size: u64,
    created_at: i64,
    file_count: u64,
    dir_count: u64,
    pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexData {
    version: u16,
    items: Vec<IndexItem>,
}

impl Default for IndexData {
    fn default() -> Self {
        Self {
            version: INDEX_VERSION,
            items: Vec::new(),
        }
    }
}

fn index_aad() -> [u8; 10] {
    let mut a = [0u8; 10];
    a[..8].copy_from_slice(INDEX_MAGIC);
    a[8..].copy_from_slice(&INDEX_VERSION.to_le_bytes());
    a
}

fn derive_index_key(secret: &Key32) -> Key32 {
    hkdf32(&secret[..], INDEX_SALT, INDEX_INFO)
}

fn seal_index(key: &Key32, data: &IndexData) -> Result<Vec<u8>> {
    let json = Zeroizing::new(serde_json::to_vec(data)?);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| AppError::Internal("index key length".into()))?;
    let aad = index_aad();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &json,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::Internal("index encryption failed".into()))?;
    if (INDEX_HEADER_LEN + ct.len()) as u64 > MAX_INDEX_FILE {
        return Err(AppError::InvalidInput("the vault index is full".into()));
    }
    let mut out = Vec::with_capacity(INDEX_HEADER_LEN + ct.len());
    out.extend_from_slice(INDEX_MAGIC);
    out.extend_from_slice(&INDEX_VERSION.to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Check the unauthenticated header fields of an index file.
fn check_index_header(b: &[u8]) -> Result<()> {
    if b.len() < INDEX_HEADER_LEN || &b[..8] != INDEX_MAGIC {
        return Err(AppError::Corrupted("vault index header".into()));
    }
    let version = u16::from_le_bytes([b[8], b[9]]);
    if version != INDEX_VERSION {
        return Err(AppError::Unsupported(format!(
            "vault index version {version}"
        )));
    }
    Ok(())
}

fn open_index(key: &Key32, b: &[u8]) -> Result<IndexData> {
    check_index_header(b)?;
    let nonce = &b[10..10 + NONCE_LEN];
    let len_at = 10 + NONCE_LEN;
    let ct_len = u32::from_le_bytes([b[len_at], b[len_at + 1], b[len_at + 2], b[len_at + 3]]);
    let ct = &b[INDEX_HEADER_LEN..];
    if ct_len as usize != ct.len() || ct.len() < TAG_LEN {
        return Err(AppError::Corrupted("vault index length".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(&key[..])
        .map_err(|_| AppError::Internal("index key length".into()))?;
    let aad = index_aad();
    // The vault key already authenticated, so a failure here means the index was damaged or
    // replaced, not that the password was wrong.
    let plain = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| AppError::Corrupted("vault index failed authentication".into()))?,
    );
    let data: IndexData = serde_json::from_slice(&plain)?;
    if data.version != INDEX_VERSION {
        return Err(AppError::Unsupported(format!(
            "vault index version {}",
            data.version
        )));
    }
    if data.items.len() > MAX_ITEMS {
        return Err(AppError::Corrupted("vault index too large".into()));
    }
    // Item ids become file names, so they must be canonical UUIDs even though the index is
    // authenticated.
    let mut seen = HashSet::new();
    for it in &data.items {
        if canonical_uuid(&it.id).as_deref() != Some(it.id.as_str()) || !seen.insert(&it.id) {
            return Err(AppError::Corrupted("vault index item id".into()));
        }
    }
    Ok(data)
}

fn canonical_uuid(s: &str) -> Option<String> {
    Uuid::parse_str(s).ok().map(|u| u.hyphenated().to_string())
}

fn parse_id(id: &str) -> Result<String> {
    canonical_uuid(id).ok_or_else(|| AppError::InvalidInput("invalid identifier".into()))
}

/// The password of one item's container, derived from the vault secret.
fn item_password(secret: &Key32, item_id: &str) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let k = hkdf32(&secret[..], item_id.as_bytes(), ITEM_INFO);
    // Built from a lookup table rather than `format!` so no un-zeroized temporary strings hold
    // pieces of the key.
    let mut s = Zeroizing::new(String::with_capacity(KEY_LEN * 2));
    for b in k.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------------------------
// Public view types
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultView {
    #[serde(flatten)]
    pub record: VaultRecord,
    pub unlocked: bool,
    /// Only known while the vault is unlocked.
    pub item_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub created_at: i64,
    pub file_count: u64,
    pub dir_count: u64,
}

impl From<&IndexItem> for ItemView {
    fn from(i: &IndexItem) -> Self {
        Self {
            id: i.id.clone(),
            name: i.name.clone(),
            kind: i.kind.clone(),
            original_size: i.original_size,
            encrypted_size: i.encrypted_size,
            created_at: i.created_at,
            file_count: i.file_count,
            dir_count: i.dir_count,
        }
    }
}

pub struct CreatedVault {
    pub vault: VaultView,
    /// Shown to the user once by the caller; never persisted.
    pub recovery_key: Option<RecoveryKey>,
}

pub struct AddOutcome {
    pub item: ItemView,
    pub removal: Removal,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleMeta {
    format: u16,
    name: String,
    icon: String,
    description: String,
    created_at: i64,
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

struct Session {
    secret: Key32,
    index_key: Key32,
    index: IndexData,
}

#[derive(Default)]
struct State {
    sessions: HashMap<String, Session>,
    /// Vaults with a mutating or long-running operation in flight.
    busy: HashSet<String>,
    /// Bumped by every lock. An unlock that began before a lock must not install its session
    /// afterwards, or Panic Lock could be undone by a slow Argon2 run.
    generation: u64,
}

struct Claim<'a> {
    owner: &'a FileVaults,
    id: String,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        let mut st = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        st.busy.remove(&self.id);
    }
}

pub struct FileVaults {
    root: PathBuf,
    db: Arc<Db>,
    kdf: KdfParams,
    state: Mutex<State>,
}

impl FileVaults {
    pub fn new(root: PathBuf, db: Arc<Db>) -> Self {
        Self::with_kdf(root, db, KdfParams::DEFAULT)
    }

    pub fn with_kdf(root: PathBuf, db: Arc<Db>, kdf: KdfParams) -> Self {
        Self {
            root,
            db,
            kdf,
            state: Mutex::new(State::default()),
        }
    }

    fn st(&self) -> Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| poisoned())
    }

    fn claim(&self, id: &str) -> Result<Claim<'_>> {
        let mut st = self.st()?;
        if !st.busy.insert(id.to_string()) {
            return Err(AppError::Busy);
        }
        Ok(Claim {
            owner: self,
            id: id.to_string(),
        })
    }

    fn vault_dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }
    fn key_path(&self, id: &str) -> PathBuf {
        self.vault_dir(id).join(KEY_FILE)
    }
    fn index_path(&self, id: &str) -> PathBuf {
        self.vault_dir(id).join(INDEX_FILE)
    }
    fn items_dir(&self, id: &str) -> PathBuf {
        self.vault_dir(id).join(ITEMS_DIR)
    }
    fn item_path(&self, id: &str, item: &str) -> PathBuf {
        self.items_dir(id).join(format!("{item}.{ITEM_EXT}"))
    }

    fn record(&self, id: &str) -> Result<VaultRecord> {
        self.db
            .vault(id)?
            .ok_or_else(|| AppError::NotFound("vault".into()))
    }

    fn with_session<T>(&self, id: &str, f: impl FnOnce(&Session) -> Result<T>) -> Result<T> {
        let st = self.st()?;
        let s = st.sessions.get(id).ok_or(AppError::VaultLocked)?;
        f(s)
    }

    /// Apply `f` to a copy of the index, persist it, and only then commit it in memory, so the
    /// in-memory and on-disk indexes never disagree after a failed write.
    fn modify_index<T>(&self, id: &str, f: impl FnOnce(&mut IndexData) -> Result<T>) -> Result<T> {
        let mut st = self.st()?;
        let s = st.sessions.get_mut(id).ok_or(AppError::VaultLocked)?;
        let mut next = s.index.clone();
        let out = f(&mut next)?;
        let bytes = seal_index(&s.index_key, &next)?;
        write_atomic(&self.index_path(id), &bytes)?;
        s.index = next;
        Ok(out)
    }

    fn view(&self, rec: VaultRecord) -> VaultView {
        let (unlocked, item_count) = match self.st() {
            Ok(st) => match st.sessions.get(&rec.id) {
                Some(s) => (
                    true,
                    Some(s.index.items.iter().filter(|i| !i.pending).count()),
                ),
                None => (false, None),
            },
            Err(_) => (false, None),
        };
        VaultView {
            record: rec,
            unlocked,
            item_count,
        }
    }

    // ----- queries -----------------------------------------------------------------------

    pub fn list(&self) -> Result<Vec<VaultView>> {
        Ok(self
            .db
            .vaults()?
            .into_iter()
            .map(|r| self.view(r))
            .collect())
    }

    pub fn get(&self, id: &str) -> Result<VaultView> {
        let id = parse_id(id)?;
        Ok(self.view(self.record(&id)?))
    }

    pub fn is_unlocked(&self, id: &str) -> bool {
        parse_id(id)
            .ok()
            .and_then(|id| self.st().ok().map(|st| st.sessions.contains_key(&id)))
            .unwrap_or(false)
    }

    pub fn unlocked_ids(&self) -> Vec<String> {
        self.st()
            .map(|st| st.sessions.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn list_items(&self, id: &str) -> Result<Vec<ItemView>> {
        let id = parse_id(id)?;
        self.with_session(&id, |s| {
            let mut v: Vec<ItemView> = s
                .index
                .items
                .iter()
                .filter(|i| !i.pending)
                .map(ItemView::from)
                .collect();
            v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.name.cmp(&b.name)));
            Ok(v)
        })
    }

    // ----- create / unlock / lock --------------------------------------------------------

    pub fn create(
        &self,
        name: &str,
        icon: &str,
        description: &str,
        password: &str,
        with_recovery: bool,
    ) -> Result<CreatedVault> {
        let name = clean_name(name)?;
        check_icon(icon)?;
        let description = clean_description(description)?;
        check_password(password)?;

        fs::create_dir_all(&self.root)?;
        let id = Uuid::new_v4().hyphenated().to_string();
        // Build the whole vault in a staging directory and rename it into place, so a crash can
        // never leave a half-initialised vault directory behind.
        let stage = self.root.join(temp_name("vault"));
        let mut guard = TempGuard::new(stage.clone());
        fs::create_dir(&stage)?;
        fs::create_dir(stage.join(ITEMS_DIR))?;

        let mut secret: Key32 = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut secret[..]);
        let sealed = seal_vault_key(
            &stage.join(KEY_FILE),
            &secret,
            password,
            self.kdf,
            with_recovery,
        )?;
        let index_key = derive_index_key(&secret);
        let index = IndexData::default();
        write_atomic(&stage.join(INDEX_FILE), &seal_index(&index_key, &index)?)?;

        let dest = self.vault_dir(&id);
        fs::rename(&stage, &dest)?;
        guard.disarm();

        let rec = VaultRecord {
            id: id.clone(),
            name,
            icon: icon.to_string(),
            description,
            created_at: now(),
            last_opened_at: Some(now()),
            has_recovery: with_recovery,
            has_saved_password: false,
            favorite: false,
        };
        if let Err(e) = self.db.insert_vault(&rec) {
            remove_any(&dest);
            return Err(e);
        }
        self.st()?.sessions.insert(
            id,
            Session {
                secret,
                index_key,
                index,
            },
        );
        Ok(CreatedVault {
            vault: self.view(rec),
            recovery_key: sealed.recovery_key,
        })
    }

    pub fn unlock(&self, id: &str, unlock: &Unlock<'_>) -> Result<()> {
        let id = parse_id(id)?;
        self.record(&id)?;
        let _claim = self.claim(&id)?;
        let started_at = {
            let st = self.st()?;
            if st.sessions.contains_key(&id) {
                return Ok(());
            }
            st.generation
        };

        let key_bytes = read_limited(&self.key_path(&id), MAX_KEY_FILE, "vault key")?;
        // Pre-sized so the 32-byte secret is written once and never copied by a reallocation.
        let mut plain = Zeroizing::new(Vec::with_capacity(64));
        let (opened, _) = container::decrypt(
            &mut Cursor::new(&key_bytes[..]),
            &mut *plain,
            unlock,
            &mut |_| Ok(()),
        )?;
        if opened.header.kind != ContainerKind::File || plain.len() != KEY_LEN {
            return Err(AppError::Corrupted("vault key content".into()));
        }
        let mut secret: Key32 = Zeroizing::new([0u8; KEY_LEN]);
        secret.copy_from_slice(&plain);
        let index_key = derive_index_key(&secret);
        let index_bytes = read_limited(&self.index_path(&id), MAX_INDEX_FILE, "vault index")?;
        let index = open_index(&index_key, &index_bytes)?;

        {
            let mut st = self.st()?;
            if st.generation != started_at {
                return Err(AppError::Cancelled);
            }
            st.sessions.insert(
                id.clone(),
                Session {
                    secret,
                    index_key,
                    index,
                },
            );
        }
        // Housekeeping must not block access to the user's data.
        if let Err(e) = self.recover_pending(&id) {
            log::warn!("vault pending-entry recovery failed: {}", e.code());
        }
        self.sweep_orphans(&id);
        let _ = self.db.touch_vault(&id);
        Ok(())
    }

    /// Forget one vault's keys. Always succeeds, even while an operation is running on it (that
    /// operation then fails with `VaultLocked` or `Cancelled`).
    pub fn lock(&self, id: &str) {
        if let Ok(id) = parse_id(id) {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.generation += 1;
            st.sessions.remove(&id);
        }
    }

    pub fn lock_all(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.generation += 1;
        st.sessions.clear();
    }

    /// Finalize or drop index entries left `pending` by an interrupted add.
    fn recover_pending(&self, id: &str) -> Result<()> {
        enum Fix {
            Drop,
            Finish(Box<Metadata>, u64),
        }
        let work: Vec<(String, Zeroizing<String>)> = self.with_session(id, |s| {
            Ok(s.index
                .items
                .iter()
                .filter(|i| i.pending)
                .map(|i| (i.id.clone(), item_password(&s.secret, &i.id)))
                .collect())
        })?;
        if work.is_empty() {
            return Ok(());
        }
        let mut fixes: Vec<(String, Fix)> = Vec::new();
        for (item, pw) in &work {
            let path = self.item_path(id, item);
            let md = match fs::symlink_metadata(&path) {
                Ok(md) if md.is_file() => md,
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    fixes.push((item.clone(), Fix::Drop));
                    continue;
                }
                Err(_) => continue,
            };
            let opened = File::open(&path)
                .map_err(AppError::from)
                .and_then(|mut f| container::open(&mut f, &Unlock::Password(pw)));
            match opened {
                Ok(o) => fixes.push((item.clone(), Fix::Finish(Box::new(o.metadata), md.len()))),
                // An unreadable container can never be opened again; the orphan sweep removes it.
                Err(
                    AppError::WrongPassword
                    | AppError::Corrupted(_)
                    | AppError::NotAContainer
                    | AppError::Unsupported(_),
                ) => fixes.push((item.clone(), Fix::Drop)),
                // Anything else (I/O trouble) may be transient: leave the entry for next time.
                Err(_) => {}
            }
        }
        self.modify_index(id, |ix| {
            for (item, fix) in fixes {
                match fix {
                    Fix::Drop => ix.items.retain(|i| i.id != item),
                    Fix::Finish(meta, enc_len) => {
                        if let Some(e) = ix.items.iter_mut().find(|i| i.id == item) {
                            e.name = meta.name;
                            e.kind = meta.kind;
                            e.original_size = meta.original_size;
                            e.created_at = meta.created_at;
                            e.file_count = meta.file_count;
                            e.dir_count = meta.dir_count;
                            e.encrypted_size = enc_len;
                            e.pending = false;
                        }
                    }
                }
            }
            Ok(())
        })
    }

    /// Remove item containers that no index entry refers to, and stale temp files. Only called
    /// while the vault's claim is held, so it cannot race an add.
    fn sweep_orphans(&self, id: &str) {
        let known: HashSet<String> = match self.with_session(id, |s| {
            Ok(s.index.items.iter().map(|i| i.id.clone()).collect())
        }) {
            Ok(k) => k,
            Err(_) => return,
        };
        let Ok(rd) = fs::read_dir(self.items_dir(id)) else {
            return;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let orphan = match name.strip_suffix(&format!(".{ITEM_EXT}")) {
                Some(stem) => {
                    canonical_uuid(stem).as_deref() == Some(stem) && !known.contains(stem)
                }
                None => name.starts_with(".veilock-") && name.ends_with(".tmp"),
            };
            if orphan {
                remove_any(&e.path());
            }
        }
    }

    // ----- items -------------------------------------------------------------------------

    pub fn add_item(
        &self,
        vault_id: &str,
        source: &Path,
        remove_original: bool,
        ctl: &OpControl,
        on_progress: &mut dyn FnMut(&ProgressInfo),
    ) -> Result<AddOutcome> {
        let vid = parse_id(vault_id)?;
        let _claim = self.claim(&vid)?;
        let item_id = Uuid::new_v4().hyphenated().to_string();
        let pw = self.with_session(&vid, |s| Ok(item_password(&s.secret, &item_id)))?;

        let md = fs::symlink_metadata(source)?;
        let display_name = source
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let kind = if md.is_dir() { "folder" } else { "file" };

        self.modify_index(&vid, |ix| {
            if ix.items.len() >= MAX_ITEMS {
                return Err(AppError::InvalidInput("the vault is full".into()));
            }
            ix.items.push(IndexItem {
                id: item_id.clone(),
                name: display_name.clone(),
                kind: kind.into(),
                original_size: 0,
                encrypted_size: 0,
                created_at: now(),
                file_count: 0,
                dir_count: 0,
                pending: true,
            });
            Ok(())
        })?;

        let items_dir = self.items_dir(&vid);
        let out_name = format!("{item_id}.{ITEM_EXT}");
        let outcome = encrypt_path(
            &EncryptRequest {
                source,
                out_dir: Some(&items_dir),
                password: &pw,
                kdf: KdfParams::FLOOR,
                chunk_size: DEFAULT_CHUNK_SIZE,
                with_recovery: false,
                on_conflict: ConflictPolicy::Fail,
                remove_original,
                out_name: Some(&out_name),
            },
            ctl,
            on_progress,
        );
        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => {
                // Nothing was published, so the placeholder entry is simply withdrawn. If that
                // fails (vault locked meanwhile) the next unlock drops it.
                let _ = self.modify_index(&vid, |ix| {
                    ix.items.retain(|i| i.id != item_id);
                    Ok(())
                });
                return Err(e);
            }
        };

        // From here the encrypted copy exists (and the original may already be gone), so a
        // failure must not roll anything back; the pending entry is recovered at next unlock.
        let item = self.modify_index(&vid, |ix| {
            let e = ix
                .items
                .iter_mut()
                .find(|i| i.id == item_id)
                .ok_or_else(|| AppError::Internal("pending entry vanished".into()))?;
            e.name = outcome.name.clone();
            e.kind = if outcome.kind == ContainerKind::Archive {
                "folder"
            } else {
                "file"
            }
            .into();
            e.original_size = outcome.original_size;
            e.encrypted_size = outcome.encrypted_size;
            e.created_at = outcome.created_at;
            e.file_count = outcome.file_count;
            e.dir_count = outcome.dir_count;
            e.pending = false;
            Ok(ItemView::from(&*e))
        })?;
        Ok(AddOutcome {
            item,
            removal: outcome.removal,
        })
    }

    pub fn extract_item(
        &self,
        vault_id: &str,
        item_id: &str,
        out_dir: &Path,
        on_conflict: ConflictPolicy,
        ctl: &OpControl,
        on_progress: &mut dyn FnMut(&ProgressInfo),
    ) -> Result<DecryptOutcome> {
        let vid = parse_id(vault_id)?;
        let item = parse_id(item_id)?;
        let _claim = self.claim(&vid)?;
        let pw = self.with_session(&vid, |s| {
            s.index
                .items
                .iter()
                .find(|i| i.id == item && !i.pending)
                .ok_or_else(|| AppError::NotFound("item".into()))?;
            Ok(item_password(&s.secret, &item))
        })?;
        decrypt_path(
            &DecryptRequest {
                source: &self.item_path(&vid, &item),
                out_dir: Some(out_dir),
                unlock: Unlock::Password(&pw),
                on_conflict,
            },
            ctl,
            on_progress,
        )
        // The derived key is correct by construction, so a rejection means the container is not
        // the one this vault wrote (replaced or swapped from another vault).
        .map_err(|e| match e {
            AppError::WrongPassword => {
                AppError::Corrupted("vault item failed authentication".into())
            }
            other => other,
        })
    }

    /// Delete an item from the vault. Callers must have asked the user to confirm.
    pub fn remove_item(&self, vault_id: &str, item_id: &str) -> Result<()> {
        let vid = parse_id(vault_id)?;
        let item = parse_id(item_id)?;
        let _claim = self.claim(&vid)?;
        // Index first: an entry without a file would be a dangling reference, whereas a file
        // without an entry is just an orphan that the next unlock sweeps away.
        self.modify_index(&vid, |ix| {
            let before = ix.items.len();
            ix.items.retain(|i| i.id != item);
            if ix.items.len() == before {
                return Err(AppError::NotFound("item".into()));
            }
            Ok(())
        })?;
        match fs::remove_file(self.item_path(&vid, &item)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    // ----- credentials -------------------------------------------------------------------

    /// Re-wrap the vault secret under a new password. `current` may also be the recovery key,
    /// which makes this the "forgot my password" path for vaults that have one.
    pub fn change_password(
        &self,
        id: &str,
        current: &Unlock<'_>,
        new_password: &str,
    ) -> Result<()> {
        let id = parse_id(id)?;
        self.record(&id)?;
        check_password(new_password)?;
        let _claim = self.claim(&id)?;
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.key_path(&id))?;
        container::change_password(&mut f, current, new_password, self.kdf)
    }

    pub fn set_recovery(&self, id: &str, current: &Unlock<'_>) -> Result<RecoveryKey> {
        let id = parse_id(id)?;
        self.record(&id)?;
        let _claim = self.claim(&id)?;
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.key_path(&id))?;
        let rk = container::set_recovery(&mut f, current)?;
        self.db.set_vault_flags(&id, Some(true), None, None)?;
        Ok(rk)
    }

    pub fn remove_recovery(&self, id: &str, current: &Unlock<'_>) -> Result<()> {
        let id = parse_id(id)?;
        self.record(&id)?;
        let _claim = self.claim(&id)?;
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.key_path(&id))?;
        container::remove_recovery(&mut f, current)?;
        self.db.set_vault_flags(&id, Some(false), None, None)
    }

    // ----- vault management ----------------------------------------------------------------

    pub fn rename(&self, id: &str, name: &str, icon: &str, description: &str) -> Result<VaultView> {
        let id = parse_id(id)?;
        let name = clean_name(name)?;
        check_icon(icon)?;
        let description = clean_description(description)?;
        self.record(&id)?;
        self.db.update_vault_info(&id, &name, icon, &description)?;
        Ok(self.view(self.record(&id)?))
    }

    /// Delete a vault and everything in it. Callers must have asked the user to confirm.
    pub fn delete(&self, id: &str) -> Result<()> {
        let id = parse_id(id)?;
        self.record(&id)?;
        let _claim = self.claim(&id)?;
        self.lock(&id);
        match fs::remove_dir_all(self.vault_dir(&id)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            // Keep the row so the user can see the vault still exists and try again.
            Err(e) => return Err(e.into()),
        }
        self.db.delete_vault(&id)
    }

    // ----- export / import -------------------------------------------------------------------

    /// Write the vault as a `.veilvault` bundle into `dest_dir`. The vault does not need to be
    /// unlocked: the bundle is the vault's own encrypted files.
    pub fn export(
        &self,
        id: &str,
        dest_dir: &Path,
        on_conflict: ConflictPolicy,
        ctl: &OpControl,
        on_progress: &mut dyn FnMut(&ProgressInfo),
    ) -> Result<PathBuf> {
        let id = parse_id(id)?;
        let rec = self.record(&id)?;
        let _claim = self.claim(&id)?;
        if !fs::metadata(dest_dir)?.is_dir() {
            return Err(AppError::InvalidInput(
                "the destination is not a folder".into(),
            ));
        }
        let vault_dir = self.vault_dir(&id);
        if fs::canonicalize(dest_dir)?.starts_with(fs::canonicalize(&vault_dir)?) {
            return Err(AppError::InvalidInput(
                "the destination is inside the vault".into(),
            ));
        }
        let scan = vault_scan(&vault_dir, &ctl.cancel)?;
        let meta = serde_json::to_vec(&BundleMeta {
            format: BUNDLE_FORMAT,
            name: rec.name.clone(),
            icon: rec.icon.clone(),
            description: rec.description.clone(),
            created_at: rec.created_at,
        })?;

        let tmp = dest_dir.join(temp_name("exp"));
        let mut guard = TempGuard::new(tmp.clone());
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(BUNDLE_MAGIC)?;
        file.write_all(&(meta.len() as u32).to_le_bytes())?;
        file.write_all(&meta)?;

        let total = scan.stream_len();
        let mut meter = Meter::new(on_progress, ctl.current.clone());
        meter.begin(Phase::Exporting, total);
        let mut reader = ArchiveReader::new(&scan, ctl.current.clone());
        pump(&mut reader, &mut file, ctl, &mut meter)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);

        let base = sanitize_for_output(&rec.name);
        let name = format!("{base}.{BUNDLE_EXT}");
        let name = if validate_component(&name).is_ok() {
            name
        } else {
            format!("vault.{BUNDLE_EXT}")
        };
        let out = publish(&tmp, dest_dir, &name, false, on_conflict)?;
        guard.disarm();
        Ok(out)
    }

    /// Import a `.veilvault` bundle as a new vault with a fresh id. The vault stays locked.
    pub fn import(
        &self,
        bundle: &Path,
        ctl: &OpControl,
        on_progress: &mut dyn FnMut(&ProgressInfo),
    ) -> Result<VaultView> {
        let md = fs::symlink_metadata(bundle)?;
        if !md.is_file() {
            return Err(AppError::NotAContainer);
        }
        let mut f = File::open(bundle)?;
        let mut magic = [0u8; 8];
        read_exact_or(&mut f, &mut magic, AppError::NotAContainer)?;
        if &magic != BUNDLE_MAGIC {
            return Err(AppError::NotAContainer);
        }
        let mut len = [0u8; 4];
        read_exact_or(
            &mut f,
            &mut len,
            AppError::Corrupted("bundle header".into()),
        )?;
        let meta_len = u32::from_le_bytes(len);
        if meta_len > MAX_BUNDLE_META {
            return Err(AppError::Corrupted("bundle metadata length".into()));
        }
        let mut meta_bytes = vec![0u8; meta_len as usize];
        read_exact_or(
            &mut f,
            &mut meta_bytes,
            AppError::Corrupted("bundle header".into()),
        )?;
        let meta: BundleMeta = serde_json::from_slice(&meta_bytes)?;
        if meta.format != BUNDLE_FORMAT {
            return Err(AppError::Unsupported(format!(
                "vault bundle version {}",
                meta.format
            )));
        }

        fs::create_dir_all(&self.root)?;
        let stage = self.root.join(temp_name("import"));
        let mut guard = TempGuard::new(stage.clone());
        fs::create_dir(&stage)?;

        let mut meter = Meter::new(on_progress, ctl.current.clone());
        meter.begin(Phase::Importing, md.len());
        let mut ex = ArchiveExtractor::new(&stage, ctl.current.clone());
        pump(&mut f, &mut ex, ctl, &mut meter)?;
        ex.finish()?;
        let has_recovery = validate_staged(&stage)?;

        let id = Uuid::new_v4().hyphenated().to_string();
        let dest = self.vault_dir(&id);
        fs::rename(&stage, &dest)?;
        guard.disarm();

        let rec = VaultRecord {
            id,
            name: lossy_name(&meta.name),
            icon: if check_icon(&meta.icon).is_ok() {
                meta.icon
            } else {
                DEFAULT_ICON.to_string()
            },
            description: lossy_description(&meta.description),
            created_at: meta.created_at.clamp(0, now()),
            last_opened_at: None,
            has_recovery,
            has_saved_password: false,
            favorite: false,
        };
        if let Err(e) = self.db.insert_vault(&rec) {
            remove_any(&dest);
            return Err(e);
        }
        Ok(self.view(rec))
    }

    #[cfg(test)]
    fn raw_items(&self, id: &str) -> Vec<IndexItem> {
        self.with_session(id, |s| Ok(s.index.items.clone()))
            .unwrap()
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn seal_vault_key(
    path: &Path,
    secret: &Key32,
    password: &str,
    kdf: KdfParams,
    with_recovery: bool,
) -> Result<Sealed> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let sealed = container::seal(
        &mut Cursor::new(&secret[..]),
        &mut file,
        &SealOptions {
            password,
            kdf,
            chunk_size: DEFAULT_CHUNK_SIZE,
            with_recovery,
            kind: ContainerKind::File,
            metadata: Metadata {
                name: KEY_FILE.into(),
                kind: "file".into(),
                original_size: KEY_LEN as u64,
                created_at: now(),
                file_count: 1,
                dir_count: 0,
                app_version: env!("CARGO_PKG_VERSION").into(),
            },
            expected_plaintext_len: Some(KEY_LEN as u64),
        },
        &mut |_| Ok(()),
    )?;
    file.sync_all()?;
    drop(file);
    // Re-read the file we just wrote with the in-memory key: a vault whose key file cannot be
    // read back is worse than no vault.
    container::verify(
        &mut File::open(path)?,
        &sealed.dek,
        &sealed.plaintext_sha256,
        sealed.plaintext_len,
        &mut |_| Ok(()),
    )?;
    Ok(sealed)
}

fn read_limited(path: &Path, max: u64, what: &str) -> Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(AppError::Corrupted(format!("{what} length")));
    }
    Ok(buf)
}

fn read_exact_or<R: Read>(r: &mut R, buf: &mut [u8], on_eof: AppError) -> Result<()> {
    match r.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(on_eof),
        Err(e) => Err(e.into()),
    }
}

/// Copy `r` to `w` with cancellation and progress. The data is always ciphertext or archive
/// framing of ciphertext, never plaintext.
fn pump<R: Read + ?Sized, W: Write + ?Sized>(
    r: &mut R,
    w: &mut W,
    ctl: &OpControl,
    meter: &mut Meter<'_>,
) -> Result<u64> {
    let mut buf = vec![0u8; PUMP_BUF];
    let mut done = 0u64;
    loop {
        ctl.check()?;
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        w.write_all(&buf[..n])?;
        done += n as u64;
        meter.update(done);
    }
    Ok(done)
}

fn is_vault_path(rel: &str, kind: &EntryKind) -> bool {
    match kind {
        EntryKind::Dir => rel == ITEMS_DIR,
        EntryKind::File { .. } => {
            if rel == KEY_FILE || rel == INDEX_FILE {
                return true;
            }
            rel.strip_prefix("items/")
                .and_then(|n| n.strip_suffix(&format!(".{ITEM_EXT}")))
                .is_some_and(|stem| canonical_uuid(stem).as_deref() == Some(stem))
        }
    }
}

/// Scan a vault directory, keeping only the files that belong in a bundle. Leftover temp files
/// from interrupted operations are skipped rather than exported.
fn vault_scan(dir: &Path, cancel: &AtomicBool) -> Result<Scan> {
    let scan = scan_folder(dir, cancel)?;
    let mut entries = Vec::new();
    let (mut files, mut dirs, mut bytes) = (0u64, 0u64, 0u64);
    for e in scan.entries {
        if !is_vault_path(&e.rel, &e.kind) {
            continue;
        }
        match e.kind {
            EntryKind::Dir => dirs += 1,
            EntryKind::File { size } => {
                files += 1;
                bytes += size;
            }
        }
        entries.push(e);
    }
    let has = |n: &str| entries.iter().any(|e| e.rel == n);
    if !has(KEY_FILE) || !has(INDEX_FILE) || !has(ITEMS_DIR) {
        return Err(AppError::Corrupted("the vault is incomplete".into()));
    }
    Ok(Scan {
        entries,
        file_count: files,
        dir_count: dirs,
        content_bytes: bytes,
    })
}

/// Strictly validate an extracted bundle. Returns whether the key file has a recovery slot.
fn validate_staged(stage: &Path) -> Result<bool> {
    let bad = || AppError::Corrupted("unexpected content in vault bundle".into());
    let (mut key, mut index, mut items) = (false, false, false);
    for entry in fs::read_dir(stage)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let md = fs::symlink_metadata(entry.path())?;
        match name.as_str() {
            KEY_FILE if md.is_file() => key = true,
            INDEX_FILE if md.is_file() => {
                if md.len() > MAX_INDEX_FILE {
                    return Err(bad());
                }
                let mut head = [0u8; INDEX_HEADER_LEN];
                read_exact_or(&mut File::open(entry.path())?, &mut head, bad())?;
                check_index_header(&head)?;
                index = true;
            }
            ITEMS_DIR if md.is_dir() => items = true,
            _ => return Err(bad()),
        }
    }
    if !(key && index && items) {
        return Err(bad());
    }

    let mut count = 0usize;
    for entry in fs::read_dir(stage.join(ITEMS_DIR))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        name.strip_suffix(&format!(".{ITEM_EXT}"))
            .filter(|s| canonical_uuid(s).as_deref() == Some(*s))
            .ok_or_else(bad)?;
        if !fs::symlink_metadata(entry.path())?.is_file() {
            return Err(bad());
        }
        count += 1;
        if count > MAX_ITEMS {
            return Err(bad());
        }
        container::inspect(&mut File::open(entry.path())?)?;
    }

    let key_path = stage.join(KEY_FILE);
    if fs::metadata(&key_path)?.len() > MAX_KEY_FILE {
        return Err(bad());
    }
    let insp = container::inspect(&mut File::open(&key_path)?)?;
    if insp.kind != ContainerKind::File || !insp.has_password_slot {
        return Err(bad());
    }
    Ok(insp.has_recovery_slot)
}

fn has_control(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

fn clean_name(name: &str) -> Result<String> {
    let n = name.trim();
    let chars = n.chars().count();
    if chars == 0 || chars > MAX_NAME_CHARS || has_control(n) {
        return Err(AppError::InvalidInput("invalid vault name".into()));
    }
    Ok(n.to_string())
}

fn clean_description(d: &str) -> Result<String> {
    let d = d.trim();
    if d.chars().count() > MAX_DESCRIPTION_CHARS || d.chars().any(|c| c.is_control() && c != '\n') {
        return Err(AppError::InvalidInput("invalid vault description".into()));
    }
    Ok(d.to_string())
}

fn check_icon(icon: &str) -> Result<()> {
    let ok = !icon.is_empty()
        && icon.len() <= MAX_ICON_CHARS
        && icon
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(AppError::InvalidInput("invalid vault icon".into()))
    }
}

fn check_password(p: &str) -> Result<()> {
    let n = p.chars().count();
    if n == 0 || n > MAX_PASSWORD_CHARS {
        return Err(AppError::InvalidInput("invalid password length".into()));
    }
    Ok(())
}

/// Imported metadata is untrusted: clamp instead of rejecting so a valid vault is never refused
/// over a cosmetic field.
fn lossy_name(s: &str) -> String {
    let n: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_CHARS)
        .collect();
    let n = n.trim().to_string();
    if n.is_empty() {
        "Imported vault".into()
    } else {
        n
    }
}

fn lossy_description(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(MAX_DESCRIPTION_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::archive::ARCHIVE_MAGIC;
    use tempfile::TempDir;

    const PW: &str = "vault password 1";

    struct Fx {
        _dir: TempDir,
        work: PathBuf,
        v: FileVaults,
        db: Arc<Db>,
    }

    fn fx() -> Fx {
        let dir = TempDir::new().unwrap();
        let work = dir.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let db = Arc::new(Db::open_in_memory().unwrap());
        let v = FileVaults::with_kdf(dir.path().join("vaults"), db.clone(), KdfParams::FLOOR);
        Fx {
            _dir: dir,
            work,
            v,
            db,
        }
    }

    fn mk(f: &Fx) -> String {
        f.v.create("Test vault", "vault", "", PW, false)
            .unwrap()
            .vault
            .record
            .id
    }

    fn add(f: &Fx, id: &str, src: &Path, remove: bool) -> Result<AddOutcome> {
        f.v.add_item(id, src, remove, &OpControl::new(), &mut |_| {})
    }

    fn extract(f: &Fx, id: &str, item: &str, out: &Path) -> Result<DecryptOutcome> {
        fs::create_dir_all(out).unwrap();
        f.v.extract_item(
            id,
            item,
            out,
            ConflictPolicy::Fail,
            &OpControl::new(),
            &mut |_| {},
        )
    }

    fn sample(f: &Fx, name: &str, bytes: &[u8]) -> PathBuf {
        let p = f.work.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn create_lock_unlock_cycle() {
        let f = fx();
        let id = mk(&f);
        assert!(f.v.is_unlocked(&id));
        assert!(f.v.list_items(&id).unwrap().is_empty());

        f.v.lock(&id);
        assert!(!f.v.is_unlocked(&id));
        assert!(matches!(f.v.list_items(&id), Err(AppError::VaultLocked)));

        assert!(matches!(
            f.v.unlock(&id, &Unlock::Password("wrong password")),
            Err(AppError::WrongPassword)
        ));
        assert!(!f.v.is_unlocked(&id));

        f.v.unlock(&id, &Unlock::Password(PW)).unwrap();
        assert!(f.v.is_unlocked(&id));
        // Unlocking an unlocked vault is a no-op.
        f.v.unlock(&id, &Unlock::Password("ignored")).unwrap();
        assert!(f.db.vault(&id).unwrap().unwrap().last_opened_at.is_some());
    }

    #[test]
    fn invalid_ids_are_rejected_before_touching_the_filesystem() {
        let f = fx();
        for bad in ["../x", "", "not-a-uuid", "..\\..\\x"] {
            assert!(matches!(f.v.get(bad), Err(AppError::InvalidInput(_))));
            assert!(matches!(
                f.v.unlock(bad, &Unlock::Password(PW)),
                Err(AppError::InvalidInput(_))
            ));
        }
        let id = mk(&f);
        assert!(matches!(
            f.v.remove_item(&id, "../../etc"),
            Err(AppError::InvalidInput(_))
        ));
    }

    #[test]
    fn create_validates_inputs() {
        let f = fx();
        assert!(f.v.create("", "vault", "", PW, false).is_err());
        assert!(f.v.create("ok", "Bad Icon!", "", PW, false).is_err());
        assert!(f.v.create("ok", "vault", "", "", false).is_err());
        assert!(f.db.vaults().unwrap().is_empty());
        // No staging leftovers.
        assert_eq!(
            fs::read_dir(f._dir.path().join("vaults")).map_or(0, |d| d.count()),
            0
        );
    }

    #[test]
    fn recovery_key_unlocks_and_can_be_added_and_removed() {
        let f = fx();
        let created = f.v.create("R", "vault", "", PW, true).unwrap();
        let id = created.vault.record.id.clone();
        let rk = created.recovery_key.unwrap();
        assert!(created.vault.record.has_recovery);
        f.v.lock(&id);

        assert!(f
            .v
            .unlock(&id, &Unlock::Recovery(&RecoveryKey::generate()))
            .is_err());
        assert!(!f.v.is_unlocked(&id));
        f.v.unlock(&id, &Unlock::Recovery(&rk)).unwrap();
        f.v.lock(&id);

        f.v.remove_recovery(&id, &Unlock::Password(PW)).unwrap();
        assert!(!f.db.vault(&id).unwrap().unwrap().has_recovery);
        assert!(f.v.unlock(&id, &Unlock::Recovery(&rk)).is_err());

        let rk2 = f.v.set_recovery(&id, &Unlock::Password(PW)).unwrap();
        assert!(f.db.vault(&id).unwrap().unwrap().has_recovery);
        f.v.unlock(&id, &Unlock::Recovery(&rk2)).unwrap();
        assert!(f.v.unlock(&id, &Unlock::Recovery(&rk)).is_ok()); // already unlocked: no-op
    }

    #[test]
    fn add_and_extract_roundtrip() {
        let f = fx();
        let id = mk(&f);
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let src = sample(&f, "secret-name.txt", &data);
        let out = add(&f, &id, &src, false).unwrap();
        assert_eq!(out.item.name, "secret-name.txt");
        assert_eq!(out.item.original_size, data.len() as u64);
        assert!(matches!(out.removal, Removal::NotRequested));
        assert!(src.exists());

        let items = f.v.list_items(&id).unwrap();
        assert_eq!(items.len(), 1);

        // The stored container reveals neither contents nor name.
        let stored = fs::read(f.v.item_path(&id, &items[0].id)).unwrap();
        assert!(!stored.windows(11).any(|w| w == b"secret-name"));
        assert!(!stored.windows(64).any(|w| w == &data[1000..1064]));
        let index = fs::read(f.v.index_path(&id)).unwrap();
        assert!(!index.windows(11).any(|w| w == b"secret-name"));

        let dest = f.work.join("out");
        let r = extract(&f, &id, &items[0].id, &dest).unwrap();
        assert_eq!(fs::read(&r.output).unwrap(), data);
        assert_eq!(r.name, "secret-name.txt");
    }

    #[test]
    fn folder_item_roundtrip_with_original_removal() {
        let f = fx();
        let id = mk(&f);
        let root = f.work.join("Папка مجلد");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("top.txt"), b"top").unwrap();
        fs::write(root.join("a/b/deep.bin"), [0u8, 1, 2, 255]).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();

        let out = add(&f, &id, &root, true).unwrap();
        assert_eq!(out.item.kind, "folder");
        assert_eq!(out.item.file_count, 2);
        assert!(matches!(out.removal, Removal::Removed));
        assert!(!root.exists());

        let dest = f.work.join("restored");
        let r = extract(&f, &id, &out.item.id, &dest).unwrap();
        assert_eq!(fs::read(r.output.join("top.txt")).unwrap(), b"top");
        assert_eq!(
            fs::read(r.output.join("a/b/deep.bin")).unwrap(),
            [0u8, 1, 2, 255]
        );
        assert!(r.output.join("empty").is_dir());
    }

    #[test]
    fn cancelled_add_leaves_source_and_no_entries() {
        let f = fx();
        let id = mk(&f);
        let src = sample(&f, "keep.txt", b"important");
        let ctl = OpControl::new();
        ctl.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let r = f.v.add_item(&id, &src, true, &ctl, &mut |_| {});
        assert!(matches!(r, Err(AppError::Cancelled)));
        assert_eq!(fs::read(&src).unwrap(), b"important");
        assert!(f.v.raw_items(&id).is_empty());
        assert_eq!(fs::read_dir(f.v.items_dir(&id)).unwrap().count(), 0);
    }

    #[test]
    fn add_to_locked_vault_fails_and_keeps_source() {
        let f = fx();
        let id = mk(&f);
        f.v.lock(&id);
        let src = sample(&f, "x.txt", b"data");
        assert!(matches!(
            add(&f, &id, &src, true),
            Err(AppError::VaultLocked)
        ));
        assert_eq!(fs::read(&src).unwrap(), b"data");
    }

    #[test]
    fn change_password_preserves_items() {
        let f = fx();
        let id = mk(&f);
        let src = sample(&f, "doc.txt", b"contents");
        let item = add(&f, &id, &src, false).unwrap().item;
        f.v.lock(&id);

        assert!(f
            .v
            .change_password(&id, &Unlock::Password("nope nope"), "new password 2")
            .is_err());
        f.v.change_password(&id, &Unlock::Password(PW), "new password 2")
            .unwrap();
        assert!(matches!(
            f.v.unlock(&id, &Unlock::Password(PW)),
            Err(AppError::WrongPassword)
        ));
        f.v.unlock(&id, &Unlock::Password("new password 2"))
            .unwrap();
        let r = extract(&f, &id, &item.id, &f.work.join("o")).unwrap();
        assert_eq!(fs::read(r.output).unwrap(), b"contents");
    }

    #[test]
    fn remove_item_deletes_file_and_entry() {
        let f = fx();
        let id = mk(&f);
        let src = sample(&f, "a.txt", b"a");
        let item = add(&f, &id, &src, false).unwrap().item;
        let path = f.v.item_path(&id, &item.id);
        assert!(path.exists());
        f.v.remove_item(&id, &item.id).unwrap();
        assert!(!path.exists());
        assert!(f.v.list_items(&id).unwrap().is_empty());
        assert!(matches!(
            f.v.remove_item(&id, &item.id),
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            extract(&f, &id, &item.id, &f.work.join("o")),
            Err(AppError::NotFound(_))
        ));
    }

    #[test]
    fn concurrent_operation_on_same_vault_is_busy() {
        let f = fx();
        let id = mk(&f);
        let src = sample(&f, "a.txt", b"a");
        let claim = f.v.claim(&id).unwrap();
        assert!(matches!(add(&f, &id, &src, false), Err(AppError::Busy)));
        assert!(matches!(f.v.delete(&id), Err(AppError::Busy)));
        drop(claim);
        add(&f, &id, &src, false).unwrap();
    }

    #[test]
    fn pending_entries_are_recovered_at_unlock() {
        let f = fx();
        let id = mk(&f);
        let src = sample(&f, "crash.txt", b"survives");
        let item = add(&f, &id, &src, false).unwrap().item;

        // Simulate dying after the container was published but before the index was finalized,
        // plus a placeholder whose container never appeared and a stray orphan container.
        let ghost = Uuid::new_v4().hyphenated().to_string();
        f.v.modify_index(&id, |ix| {
            let e = ix.items.iter_mut().find(|i| i.id == item.id).unwrap();
            e.pending = true;
            e.original_size = 0;
            e.name = "?".into();
            let mut g = e.clone();
            g.id = ghost.clone();
            ix.items.push(g);
            Ok(())
        })
        .unwrap();
        let orphan = f.v.item_path(&id, &Uuid::new_v4().hyphenated().to_string());
        fs::write(&orphan, b"junk").unwrap();
        let stale = f.v.items_dir(&id).join(".veilock-enc-deadbeef.tmp");
        fs::write(&stale, b"junk").unwrap();
        assert!(f.v.list_items(&id).unwrap().is_empty());

        f.v.lock(&id);
        f.v.unlock(&id, &Unlock::Password(PW)).unwrap();

        let items = f.v.list_items(&id).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "crash.txt");
        assert_eq!(items[0].original_size, 8);
        assert_eq!(f.v.raw_items(&id).len(), 1);
        assert!(!orphan.exists());
        assert!(!stale.exists());
        let r = extract(&f, &id, &item.id, &f.work.join("o")).unwrap();
        assert_eq!(fs::read(r.output).unwrap(), b"survives");
    }

    #[test]
    fn rename_changes_only_metadata() {
        let f = fx();
        let id = mk(&f);
        let src = sample(&f, "a.txt", b"a");
        add(&f, &id, &src, false).unwrap();
        let v = f.v.rename(&id, " New name ", "shield", "notes").unwrap();
        assert_eq!(v.record.name, "New name");
        assert_eq!(v.record.icon, "shield");
        assert_eq!(f.v.list_items(&id).unwrap().len(), 1);
        assert!(f.v.rename(&id, "x", "BAD", "").is_err());
    }

    #[test]
    fn delete_removes_directory_and_row() {
        let f = fx();
        let id = mk(&f);
        let dir = f.v.vault_dir(&id);
        assert!(dir.exists());
        f.v.delete(&id).unwrap();
        assert!(!dir.exists());
        assert!(f.db.vault(&id).unwrap().is_none());
        assert!(!f.v.is_unlocked(&id));
        assert!(matches!(f.v.delete(&id), Err(AppError::NotFound(_))));
    }

    #[test]
    fn export_import_roundtrip() {
        let f = fx();
        let created =
            f.v.create("Travel docs", "vault", "passports", PW, false)
                .unwrap();
        let id = created.vault.record.id;
        let src = sample(&f, "passport.txt", b"P<GBR");
        let item = add(&f, &id, &src, false).unwrap().item;

        let dest = f.work.join("exports");
        fs::create_dir_all(&dest).unwrap();
        let bundle =
            f.v.export(
                &id,
                &dest,
                ConflictPolicy::Fail,
                &OpControl::new(),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(bundle.file_name().unwrap(), "Travel docs.veilvault");
        let raw = fs::read(&bundle).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"P<GBR"));
        assert!(!raw.windows(12).any(|w| w == b"passport.txt"));

        // Exporting again without a conflict policy refuses to overwrite.
        assert!(matches!(
            f.v.export(
                &id,
                &dest,
                ConflictPolicy::Fail,
                &OpControl::new(),
                &mut |_| {}
            ),
            Err(AppError::OutputExists(_))
        ));

        let imported = f.v.import(&bundle, &OpControl::new(), &mut |_| {}).unwrap();
        assert_ne!(imported.record.id, id);
        assert_eq!(imported.record.name, "Travel docs");
        assert!(!imported.unlocked);

        let nid = imported.record.id;
        assert!(matches!(
            f.v.unlock(&nid, &Unlock::Password("wrong")),
            Err(AppError::WrongPassword)
        ));
        f.v.unlock(&nid, &Unlock::Password(PW)).unwrap();
        let items = f.v.list_items(&nid).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, item.id);
        let r = extract(&f, &nid, &items[0].id, &f.work.join("o2")).unwrap();
        assert_eq!(fs::read(r.output).unwrap(), b"P<GBR");
        // The original vault is untouched.
        assert!(f.v.is_unlocked(&id));
    }

    // ----- hostile bundles -----------------------------------------------------------------

    fn archive(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
        let mut v = ARCHIVE_MAGIC.to_vec();
        let (mut files, mut dirs) = (0u64, 0u64);
        for (path, content) in entries {
            match content {
                None => {
                    v.push(1);
                    v.extend((path.len() as u32).to_le_bytes());
                    v.extend(path.as_bytes());
                    dirs += 1;
                }
                Some(b) => {
                    v.push(2);
                    v.extend((path.len() as u32).to_le_bytes());
                    v.extend(path.as_bytes());
                    v.extend((b.len() as u64).to_le_bytes());
                    v.extend(*b);
                    files += 1;
                }
            }
        }
        v.push(0);
        v.extend(files.to_le_bytes());
        v.extend(dirs.to_le_bytes());
        v
    }

    fn bundle(meta: &str, arch: &[u8]) -> Vec<u8> {
        let mut v = BUNDLE_MAGIC.to_vec();
        v.extend((meta.len() as u32).to_le_bytes());
        v.extend(meta.as_bytes());
        v.extend(arch);
        v
    }

    const META: &str =
        r#"{"format":1,"name":"Evil","icon":"vault","description":"","createdAt":1}"#;

    fn try_import(f: &Fx, bytes: &[u8]) -> Result<VaultView> {
        let p = f.work.join("hostile.veilvault");
        fs::write(&p, bytes).unwrap();
        f.v.import(&p, &OpControl::new(), &mut |_| {})
    }

    fn assert_nothing_left(f: &Fx) {
        assert!(f.db.vaults().unwrap().is_empty());
        let root = f._dir.path().join("vaults");
        assert_eq!(fs::read_dir(root).map_or(0, |d| d.count()), 0);
    }

    #[test]
    fn import_rejects_hostile_bundles_and_cleans_up() {
        let f = fx();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("not a bundle", b"hello world, definitely not".to_vec()),
            ("empty", Vec::new()),
            (
                "huge metadata length",
                [BUNDLE_MAGIC.as_slice(), &u32::MAX.to_le_bytes()].concat(),
            ),
            ("bad metadata json", bundle("{not json", &archive(&[]))),
            (
                "future bundle version",
                bundle(
                    r#"{"format":9,"name":"x","icon":"vault","description":"","createdAt":1}"#,
                    &archive(&[]),
                ),
            ),
            (
                "traversal path",
                bundle(META, &archive(&[("../evil.txt", Some(b"x"))])),
            ),
            (
                "absolute path",
                bundle(META, &archive(&[("C:/evil.txt", Some(b"x"))])),
            ),
            (
                "extra file",
                bundle(
                    META,
                    &archive(&[("vault.key", Some(b"x")), ("extra.txt", Some(b"y"))]),
                ),
            ),
            ("missing parts", bundle(META, &archive(&[("items", None)]))),
            (
                "garbage key file",
                bundle(
                    META,
                    &archive(&[
                        ("vault.key", Some(b"not a container")),
                        ("index.enc", Some(&[0u8; 64])),
                        ("items", None),
                    ]),
                ),
            ),
            (
                "bad item name",
                bundle(
                    META,
                    &archive(&[
                        ("vault.key", Some(b"k")),
                        ("index.enc", Some(b"i")),
                        ("items", None),
                        ("items/evil.exe", Some(b"x")),
                    ]),
                ),
            ),
            (
                "truncated archive",
                bundle(META, &archive(&[("vault.key", Some(b"x"))])[..20]),
            ),
        ];
        for (label, bytes) in cases {
            let r = try_import(&f, &bytes);
            assert!(r.is_err(), "{label} must be rejected");
            assert_nothing_left(&f);
        }
        assert!(!f.work.parent().unwrap().join("evil.txt").exists());
    }

    #[test]
    fn import_rejects_bundle_with_trailing_data() {
        let f = fx();
        let id = mk(&f);
        let dest = f.work.join("exports");
        fs::create_dir_all(&dest).unwrap();
        let b =
            f.v.export(
                &id,
                &dest,
                ConflictPolicy::Fail,
                &OpControl::new(),
                &mut |_| {},
            )
            .unwrap();
        let mut bytes = fs::read(&b).unwrap();
        bytes.extend_from_slice(b"trailing");
        let before = f.db.vaults().unwrap().len();
        assert!(try_import(&f, &bytes).is_err());
        assert_eq!(f.db.vaults().unwrap().len(), before);
    }

    #[test]
    fn export_skips_leftover_temp_files() {
        let f = fx();
        let id = mk(&f);
        fs::write(f.v.items_dir(&id).join(".veilock-enc-aaaa.tmp"), b"junk").unwrap();
        let dest = f.work.join("exports");
        fs::create_dir_all(&dest).unwrap();
        let b =
            f.v.export(
                &id,
                &dest,
                ConflictPolicy::Fail,
                &OpControl::new(),
                &mut |_| {},
            )
            .unwrap();
        let raw = fs::read(&b).unwrap();
        assert!(!raw.windows(4).any(|w| w == b"junk"));
        f.v.import(&b, &OpControl::new(), &mut |_| {}).unwrap();
    }

    #[test]
    fn export_refuses_destination_inside_vault() {
        let f = fx();
        let id = mk(&f);
        let r = f.v.export(
            &id,
            &f.v.items_dir(&id),
            ConflictPolicy::Fail,
            &OpControl::new(),
            &mut |_| {},
        );
        assert!(matches!(r, Err(AppError::InvalidInput(_))));
    }

    #[test]
    fn tampered_index_is_detected_not_trusted() {
        let f = fx();
        let id = mk(&f);
        let src = sample(&f, "a.txt", b"a");
        add(&f, &id, &src, false).unwrap();
        f.v.lock(&id);
        let p = f.v.index_path(&id);
        let mut b = fs::read(&p).unwrap();
        let last = b.len() - 1;
        b[last] ^= 1;
        fs::write(&p, &b).unwrap();
        assert!(matches!(
            f.v.unlock(&id, &Unlock::Password(PW)),
            Err(AppError::Corrupted(_))
        ));
        assert!(!f.v.is_unlocked(&id));
    }

    #[test]
    fn tampered_key_file_reads_as_wrong_password() {
        let f = fx();
        let id = mk(&f);
        f.v.lock(&id);
        let p = f.v.key_path(&id);
        let mut b = fs::read(&p).unwrap();
        let last = b.len() - 1;
        b[last] ^= 1;
        fs::write(&p, &b).unwrap();
        assert!(f.v.unlock(&id, &Unlock::Password(PW)).is_err());
        assert!(!f.v.is_unlocked(&id));
    }

    #[test]
    fn item_file_swapped_from_another_vault_is_rejected() {
        let f = fx();
        let a = mk(&f);
        let b =
            f.v.create("B", "vault", "", PW, false)
                .unwrap()
                .vault
                .record
                .id;
        let src = sample(&f, "a.txt", b"a-data");
        let ia = add(&f, &a, &src, false).unwrap().item;
        let src2 = sample(&f, "b.txt", b"b-data");
        let ib = add(&f, &b, &src2, false).unwrap().item;
        // Put B's container where A expects its own.
        fs::copy(f.v.item_path(&b, &ib.id), f.v.item_path(&a, &ia.id)).unwrap();
        assert!(matches!(
            extract(&f, &a, &ia.id, &f.work.join("o")),
            Err(AppError::Corrupted(_))
        ));
    }

    #[test]
    fn index_roundtrip_and_header_checks() {
        let key: Key32 = Zeroizing::new([7u8; KEY_LEN]);
        let data = IndexData::default();
        let bytes = seal_index(&key, &data).unwrap();
        assert_eq!(open_index(&key, &bytes).unwrap().items.len(), 0);
        let other: Key32 = Zeroizing::new([8u8; KEY_LEN]);
        assert!(open_index(&other, &bytes).is_err());
        assert!(open_index(&key, &bytes[..10]).is_err());
        let mut v = bytes.clone();
        v[8] = 9;
        assert!(matches!(
            open_index(&key, &v),
            Err(AppError::Unsupported(_))
        ));
        let mut len_lie = bytes.clone();
        len_lie[10 + NONCE_LEN] ^= 0xff;
        assert!(open_index(&key, &len_lie).is_err());
    }

    #[test]
    fn index_rejects_non_uuid_item_ids() {
        let key: Key32 = Zeroizing::new([7u8; KEY_LEN]);
        let mut data = IndexData::default();
        data.items.push(IndexItem {
            id: "../../evil".into(),
            name: "x".into(),
            kind: "file".into(),
            original_size: 0,
            encrypted_size: 0,
            created_at: 0,
            file_count: 0,
            dir_count: 0,
            pending: false,
        });
        let bytes = seal_index(&key, &data).unwrap();
        assert!(matches!(
            open_index(&key, &bytes),
            Err(AppError::Corrupted(_))
        ));
    }

    #[test]
    fn item_passwords_are_distinct_and_deterministic() {
        let s1: Key32 = Zeroizing::new([1u8; KEY_LEN]);
        let s2: Key32 = Zeroizing::new([2u8; KEY_LEN]);
        let a = Uuid::new_v4().hyphenated().to_string();
        let b = Uuid::new_v4().hyphenated().to_string();
        assert_eq!(*item_password(&s1, &a), *item_password(&s1, &a));
        assert_ne!(*item_password(&s1, &a), *item_password(&s1, &b));
        assert_ne!(*item_password(&s1, &a), *item_password(&s2, &a));
        assert_eq!(item_password(&s1, &a).len(), 64);
    }
}
