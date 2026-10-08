//! The credential vault: saved encryption passwords and the optional Default Encryption Password,
//! encrypted at rest under a key derived from the Master Password.
//!
//! File format `VLKCRED1` (all integers little-endian):
//!
//! ```text
//! magic "VLKCRED1" (8) | version u16 | m_cost u32 | t_cost u32 | p_cost u32 |
//! salt (16) | nonce (12) | ct_len u32 | ciphertext (ct_len, includes 16-byte GCM tag)
//! ```
//!
//! The key is `Argon2id(NFKC(master), salt, params)` used directly as an AES-256-GCM key. The
//! whole header is the AEAD associated data, so the KDF parameters, salt and length cannot be
//! altered without failing authentication. A fresh random nonce is used for every save.
//!
//! The Master Password itself is never stored. "Is this the right master?" is answered by
//! re-deriving the key and comparing it in constant time with the key held in memory (or, at
//! unlock time, by whether the AEAD tag verifies).
//!
//! A wrong Master Password and a tampered file both fail AEAD verification and are reported as
//! `WrongPassword`; they are indistinguishable by design.

use crate::crypto::kdf::{derive_password_kek, KdfParams, Key32};
use crate::crypto::params::{KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::crypto::password::normalize;
use crate::errors::{AppError, Result};
use crate::storage::atomic::write_atomic;
use crate::storage::db::now;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 8] = b"VLKCRED1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 12 + SALT_LEN + NONCE_LEN + 4;
/// Upper bound on the encrypted payload, checked before any allocation.
const MAX_CT_LEN: u32 = 32 * 1024 * 1024;

pub const MIN_MASTER_CHARS: usize = 8;
const MAX_SECRET_CHARS: usize = 1024;
const MAX_NAME_CHARS: usize = 255;
const MAX_PATH_CHARS: usize = 4096;
const MAX_NOTES_CHARS: usize = 10_000;
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockPhase {
    Locked,
    Unlocking,
    Unlocked,
    Locking,
}

/// One saved password. Zeroised when dropped.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct PasswordEntry {
    pub id: String,
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub original_path: Option<String>,
    #[serde(default)]
    pub encrypted_path: Option<String>,
    pub password: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub favorite: bool,
    pub created_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default)]
    pub item_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct CredentialData {
    version: u32,
    entries: Vec<PasswordEntry>,
    #[serde(default)]
    default_password: Option<String>,
}

impl CredentialData {
    fn empty() -> Self {
        CredentialData {
            version: 1,
            entries: Vec::new(),
            default_password: None,
        }
    }
}

/// What the UI may list: everything except the password and notes text.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub original_path: Option<String>,
    pub encrypted_path: Option<String>,
    pub favorite: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub item_id: Option<String>,
    pub has_notes: bool,
}

/// An entry as shown in the edit form: the view plus the notes. The password is still not
/// included; it is fetched separately through `reveal`.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EditableEntry {
    #[serde(flatten)]
    pub view: EntryView,
    pub notes: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct NewEntry {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub original_path: Option<String>,
    #[serde(default)]
    pub encrypted_path: Option<String>,
    pub password: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub item_id: Option<String>,
}

#[derive(Default, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct EntryUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub favorite: Option<bool>,
}

fn view_of(e: &PasswordEntry) -> EntryView {
    EntryView {
        id: e.id.clone(),
        name: e.name.clone(),
        kind: e.kind.clone(),
        original_path: e.original_path.clone(),
        encrypted_path: e.encrypted_path.clone(),
        favorite: e.favorite,
        created_at: e.created_at,
        last_used_at: e.last_used_at,
        item_id: e.item_id.clone(),
        has_notes: !e.notes.is_empty(),
    }
}

struct Unlocked {
    key: Key32,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    data: CredentialData,
}

struct Inner {
    phase: LockPhase,
    unlocked: Option<Unlocked>,
}

pub struct CredentialStore {
    path: PathBuf,
    /// Cost parameters used when *creating* a vault or changing the master. Existing files carry
    /// their own parameters.
    kdf: KdfParams,
    inner: Mutex<Inner>,
    /// Bumped by every `lock()`. A long-running unlock or master change compares it afterwards and
    /// discards its result if the vault was locked in the meantime, so Panic Lock always wins.
    generation: AtomicU64,
}

struct Parsed<'a> {
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    header: &'a [u8],
    ct: &'a [u8],
}

fn check_text(s: &str, max: usize, what: &str) -> Result<()> {
    if s.chars().count() > max || s.contains('\0') {
        return Err(AppError::InvalidInput(what.into()));
    }
    Ok(())
}

fn check_master(master: &str) -> Result<()> {
    if master.chars().count() < MIN_MASTER_CHARS {
        return Err(AppError::InvalidInput("master password too short".into()));
    }
    check_text(master, MAX_SECRET_CHARS, "master password")
}

fn check_kind(kind: &str) -> Result<()> {
    match kind {
        "file" | "folder" | "vault" | "other" => Ok(()),
        _ => Err(AppError::InvalidInput("entry type".into())),
    }
}

fn parse(bytes: &[u8]) -> Result<Parsed<'_>> {
    if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
        return Err(AppError::Corrupted("credential store header".into()));
    }
    let u16_at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
    let u32_at =
        |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
    let version = u16_at(8);
    if version != VERSION {
        return Err(AppError::Unsupported(format!(
            "credential store version {version}"
        )));
    }
    let kdf = KdfParams {
        m_cost_kib: u32_at(10),
        t_cost: u32_at(14),
        p_cost: u32_at(18),
    };
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[22..22 + SALT_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[22 + SALT_LEN..22 + SALT_LEN + NONCE_LEN]);
    let ct_len = u32_at(HEADER_LEN - 4);
    if ct_len < TAG_LEN as u32 || ct_len > MAX_CT_LEN {
        return Err(AppError::Corrupted("credential store length".into()));
    }
    if bytes.len() != HEADER_LEN + ct_len as usize {
        return Err(AppError::Corrupted("credential store length".into()));
    }
    Ok(Parsed {
        kdf,
        salt,
        nonce,
        header: &bytes[..HEADER_LEN],
        ct: &bytes[HEADER_LEN..],
    })
}

fn encrypt_file(
    key: &Key32,
    kdf: &KdfParams,
    salt: &[u8; SALT_LEN],
    data: &CredentialData,
) -> Result<Vec<u8>> {
    // Best effort: serde_json may leave intermediate copies in freed memory that we can't reach.
    let plain = Zeroizing::new(
        serde_json::to_vec(data).map_err(|_| AppError::Internal("serialize".into()))?,
    );
    let ct_len = plain.len() + TAG_LEN;
    if ct_len as u64 > MAX_CT_LEN as u64 {
        return Err(AppError::InvalidInput("credential store too large".into()));
    }
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let mut out = Vec::with_capacity(HEADER_LEN + ct_len);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&kdf.m_cost_kib.to_le_bytes());
    out.extend_from_slice(&kdf.t_cost.to_le_bytes());
    out.extend_from_slice(&kdf.p_cost.to_le_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ct_len as u32).to_le_bytes());
    debug_assert_eq!(out.len(), HEADER_LEN);

    let cipher =
        Aes256Gcm::new_from_slice(&key[..]).map_err(|_| AppError::Internal("key".into()))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &out,
            },
        )
        .map_err(|_| AppError::Internal("encrypt".into()))?;
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_file(key: &Key32, p: &Parsed<'_>) -> Result<CredentialData> {
    let cipher =
        Aes256Gcm::new_from_slice(&key[..]).map_err(|_| AppError::Internal("key".into()))?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&p.nonce),
            Payload {
                msg: p.ct,
                aad: p.header,
            },
        )
        .map_err(|_| AppError::WrongPassword)?;
    let plain = Zeroizing::new(plain);
    // The tag verified, so this really is what we wrote; a parse failure means a bug or a file
    // written by a newer app, not an attack.
    serde_json::from_slice::<CredentialData>(&plain)
        .map_err(|_| AppError::Corrupted("credential store contents".into()))
}

fn derive(master: &str, salt: &[u8; SALT_LEN], kdf: &KdfParams) -> Result<Key32> {
    let pw = normalize(master);
    derive_password_kek(&pw, salt, kdf)
}

impl CredentialStore {
    pub fn new(path: PathBuf) -> Self {
        Self::with_kdf(path, KdfParams::DEFAULT)
    }

    pub fn with_kdf(path: PathBuf, kdf: KdfParams) -> Self {
        CredentialStore {
            path,
            kdf,
            inner: Mutex::new(Inner {
                phase: LockPhase::Locked,
                unlocked: None,
            }),
            generation: AtomicU64::new(0),
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether a Master Password has been set up (a credential file exists).
    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    pub fn phase(&self) -> LockPhase {
        self.inner().phase
    }

    pub fn is_unlocked(&self) -> bool {
        let g = self.inner();
        g.phase == LockPhase::Unlocked && g.unlocked.is_some()
    }

    /// Create the store with a new Master Password and leave it unlocked.
    pub fn create(&self, master: &str) -> Result<()> {
        check_master(master)?;
        if self.exists() {
            return Err(AppError::OutputExists("credential store".into()));
        }
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let gen = {
            let mut g = self.inner();
            if g.phase != LockPhase::Locked {
                return Err(AppError::Busy);
            }
            g.phase = LockPhase::Unlocking;
            self.generation.load(Ordering::SeqCst)
        };
        let result = (|| {
            let key = derive(master, &salt, &self.kdf)?;
            let data = CredentialData::empty();
            let bytes = encrypt_file(&key, &self.kdf, &salt, &data)?;
            Ok((key, data, bytes))
        })();
        let mut g = self.inner();
        if self.generation.load(Ordering::SeqCst) != gen {
            return Err(AppError::Cancelled);
        }
        match result {
            Ok((key, data, bytes)) => {
                if let Err(e) = write_atomic(&self.path, &bytes) {
                    g.phase = LockPhase::Locked;
                    return Err(e);
                }
                g.unlocked = Some(Unlocked {
                    key,
                    kdf: self.kdf,
                    salt,
                    data,
                });
                g.phase = LockPhase::Unlocked;
                Ok(())
            }
            Err(e) => {
                g.phase = LockPhase::Locked;
                Err(e)
            }
        }
    }

    pub fn unlock(&self, master: &str) -> Result<()> {
        check_text(master, MAX_SECRET_CHARS, "master password")?;
        let bytes = read_limited(&self.path, (HEADER_LEN + MAX_CT_LEN as usize) as u64).map_err(
            |e| match e {
                AppError::PermissionDenied(_) | AppError::Corrupted(_) => e,
                AppError::Io(_) | AppError::NotFound(_) => {
                    if self.path.exists() {
                        e
                    } else {
                        AppError::NotFound("credential store".into())
                    }
                }
                other => other,
            },
        )?;
        let parsed = parse(&bytes)?;

        let gen = {
            let mut g = self.inner();
            match g.phase {
                LockPhase::Unlocked => return Ok(()),
                LockPhase::Unlocking | LockPhase::Locking => return Err(AppError::Busy),
                LockPhase::Locked => {}
            }
            g.phase = LockPhase::Unlocking;
            self.generation.load(Ordering::SeqCst)
        };

        // The mutex is NOT held while Argon2 runs, so lock() and phase() stay responsive.
        let result = derive(master, &parsed.salt, &parsed.kdf)
            .and_then(|key| decrypt_file(&key, &parsed).map(|data| (key, data)));

        let mut g = self.inner();
        if self.generation.load(Ordering::SeqCst) != gen {
            // lock() ran while we were deriving; it already reset the phase.
            return Err(AppError::Cancelled);
        }
        match result {
            Ok((key, data)) => {
                g.unlocked = Some(Unlocked {
                    key,
                    kdf: parsed.kdf,
                    salt: parsed.salt,
                    data,
                });
                g.phase = LockPhase::Unlocked;
                Ok(())
            }
            Err(e) => {
                g.phase = LockPhase::Locked;
                Err(e)
            }
        }
    }

    /// Forget every key and decrypted value held in memory.
    pub fn lock(&self) {
        let mut g = self.inner();
        self.generation.fetch_add(1, Ordering::SeqCst);
        g.phase = LockPhase::Locking;
        // Dropping zeroises the key and all entries.
        g.unlocked = None;
        g.phase = LockPhase::Locked;
    }

    /// Re-check the Master Password against the unlocked session. Used before revealing secrets
    /// and for sensitive operations when the user has asked for that.
    pub fn verify_master(&self, master: &str) -> Result<()> {
        check_text(master, MAX_SECRET_CHARS, "master password")?;
        let (gen, salt, kdf, expected) = {
            let g = self.inner();
            let u = g.unlocked.as_ref().ok_or(AppError::VaultLocked)?;
            let mut copy = Zeroizing::new([0u8; KEY_LEN]);
            copy.copy_from_slice(&u.key[..]);
            (self.generation.load(Ordering::SeqCst), u.salt, u.kdf, copy)
        };
        let derived = derive(master, &salt, &kdf)?;
        if self.generation.load(Ordering::SeqCst) != gen {
            return Err(AppError::Cancelled);
        }
        if bool::from(derived.ct_eq(&*expected)) {
            Ok(())
        } else {
            Err(AppError::WrongPassword)
        }
    }

    pub fn change_master(&self, current: &str, new: &str) -> Result<()> {
        check_master(new)?;
        self.verify_master(current)?;
        let gen = self.generation.load(Ordering::SeqCst);
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let kdf = self.kdf;
        let key = derive(new, &salt, &kdf)?;

        let mut g = self.inner();
        if self.generation.load(Ordering::SeqCst) != gen {
            return Err(AppError::Cancelled);
        }
        let u = g.unlocked.as_mut().ok_or(AppError::VaultLocked)?;
        // Write the file first; only swap the in-memory key if that succeeded, so a failed write
        // leaves the old master fully working.
        let bytes = encrypt_file(&key, &kdf, &salt, &u.data)?;
        write_atomic(&self.path, &bytes)?;
        u.key = key;
        u.kdf = kdf;
        u.salt = salt;
        Ok(())
    }

    fn read<R>(&self, f: impl FnOnce(&CredentialData) -> Result<R>) -> Result<R> {
        let g = self.inner();
        let u = g.unlocked.as_ref().ok_or(AppError::VaultLocked)?;
        f(&u.data)
    }

    /// Apply `f` to a copy of the data, persist the copy, and only then commit it in memory.
    fn modify<R>(&self, f: impl FnOnce(&mut CredentialData) -> Result<R>) -> Result<R> {
        let mut g = self.inner();
        let u = g.unlocked.as_mut().ok_or(AppError::VaultLocked)?;
        let mut draft = u.data.clone();
        let r = f(&mut draft)?;
        let bytes = encrypt_file(&u.key, &u.kdf, &u.salt, &draft)?;
        write_atomic(&self.path, &bytes)?;
        u.data = draft;
        Ok(r)
    }

    // ---- entries -------------------------------------------------------------------------

    pub fn list(&self) -> Result<Vec<EntryView>> {
        self.read(|d| Ok(d.entries.iter().map(view_of).collect()))
    }

    pub fn entry_for_edit(&self, id: &str) -> Result<EditableEntry> {
        self.read(|d| {
            let e = d
                .entries
                .iter()
                .find(|e| e.id == id)
                .ok_or_else(|| AppError::NotFound("saved password".into()))?;
            Ok(EditableEntry {
                view: view_of(e),
                notes: e.notes.clone(),
            })
        })
    }

    pub fn add(&self, new: NewEntry) -> Result<EntryView> {
        check_kind(&new.kind)?;
        check_new_fields(&new)?;
        self.modify(|d| {
            if d.entries.len() >= MAX_ENTRIES {
                return Err(AppError::InvalidInput("too many saved passwords".into()));
            }
            let entry = entry_from(&new);
            let v = view_of(&entry);
            d.entries.push(entry);
            Ok(v)
        })
    }

    /// Save the password for an encrypted path, replacing any entry already saved for that path.
    /// This is what "Save password in vault" uses so repeated encryption doesn't pile up entries.
    pub fn upsert_for_path(&self, new: NewEntry) -> Result<EntryView> {
        check_kind(&new.kind)?;
        check_new_fields(&new)?;
        let Some(path) = new.encrypted_path.clone() else {
            return Err(AppError::InvalidInput("encrypted path".into()));
        };
        self.modify(|d| {
            if let Some(e) = d
                .entries
                .iter_mut()
                .find(|e| path_matches(e.encrypted_path.as_deref(), &path))
            {
                e.name = new.name.clone();
                e.kind = new.kind.clone();
                e.original_path = new.original_path.clone();
                e.password = new.password.clone();
                e.item_id = new.item_id.clone();
                return Ok(view_of(e));
            }
            if d.entries.len() >= MAX_ENTRIES {
                return Err(AppError::InvalidInput("too many saved passwords".into()));
            }
            let entry = entry_from(&new);
            let v = view_of(&entry);
            d.entries.push(entry);
            Ok(v)
        })
    }

    pub fn update(&self, id: &str, upd: EntryUpdate) -> Result<EntryView> {
        if let Some(n) = &upd.name {
            if n.trim().is_empty() {
                return Err(AppError::InvalidInput("name".into()));
            }
            check_text(n, MAX_NAME_CHARS, "name")?;
        }
        if let Some(n) = &upd.notes {
            check_text(n, MAX_NOTES_CHARS, "notes")?;
        }
        if let Some(p) = &upd.password {
            if p.is_empty() {
                return Err(AppError::InvalidInput("password".into()));
            }
            check_text(p, MAX_SECRET_CHARS, "password")?;
        }
        self.modify(|d| {
            let e = d
                .entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| AppError::NotFound("saved password".into()))?;
            if let Some(n) = &upd.name {
                e.name = n.trim().to_owned();
            }
            if let Some(n) = &upd.notes {
                e.notes = n.clone();
            }
            if let Some(p) = &upd.password {
                e.password = p.clone();
            }
            if let Some(f) = upd.favorite {
                e.favorite = f;
            }
            Ok(view_of(e))
        })
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        self.modify(|d| {
            let before = d.entries.len();
            d.entries.retain(|e| e.id != id);
            if d.entries.len() == before {
                return Err(AppError::NotFound("saved password".into()));
            }
            Ok(())
        })
    }

    /// The password, for display after the caller has done any master re-check it requires. Does
    /// not count as "use".
    pub fn reveal(&self, id: &str) -> Result<Zeroizing<String>> {
        self.read(|d| {
            d.entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| Zeroizing::new(e.password.clone()))
                .ok_or_else(|| AppError::NotFound("saved password".into()))
        })
    }

    /// The password for use (copy / unlock); records the last-used time.
    pub fn use_entry(&self, id: &str) -> Result<Zeroizing<String>> {
        self.modify(|d| {
            let e = d
                .entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| AppError::NotFound("saved password".into()))?;
            e.last_used_at = Some(now());
            Ok(Zeroizing::new(e.password.clone()))
        })
    }

    /// Look up the saved password for an encrypted file, if any, and record the use.
    pub fn use_for_path(&self, encrypted_path: &str) -> Result<Option<Zeroizing<String>>> {
        let id = self.read(|d| {
            Ok(d.entries
                .iter()
                .find(|e| path_matches(e.encrypted_path.as_deref(), encrypted_path))
                .map(|e| e.id.clone()))
        })?;
        match id {
            Some(id) => self.use_entry(&id).map(Some),
            None => Ok(None),
        }
    }

    pub fn has_for_path(&self, encrypted_path: &str) -> Result<bool> {
        self.read(|d| {
            Ok(d.entries
                .iter()
                .any(|e| path_matches(e.encrypted_path.as_deref(), encrypted_path)))
        })
    }

    /// Keep entries pointing at the right file after the user moves or renames it.
    pub fn repoint_path(&self, old: &str, new: &str) -> Result<()> {
        check_text(new, MAX_PATH_CHARS, "path")?;
        self.modify(|d| {
            for e in d
                .entries
                .iter_mut()
                .filter(|e| path_matches(e.encrypted_path.as_deref(), old))
            {
                e.encrypted_path = Some(new.to_owned());
            }
            Ok(())
        })
    }

    // ---- default encryption password --------------------------------------------------------

    pub fn has_default_password(&self) -> Result<bool> {
        self.read(|d| Ok(d.default_password.is_some()))
    }

    pub fn default_password(&self) -> Result<Option<Zeroizing<String>>> {
        self.read(|d| {
            Ok(d.default_password
                .as_ref()
                .map(|p| Zeroizing::new(p.clone())))
        })
    }

    pub fn set_default_password(&self, pw: Option<&str>) -> Result<()> {
        if let Some(p) = pw {
            if p.is_empty() {
                return Err(AppError::InvalidInput("password".into()));
            }
            check_text(p, MAX_SECRET_CHARS, "password")?;
        }
        self.modify(|d| {
            d.default_password = pw.map(str::to_owned);
            Ok(())
        })
    }
}

fn check_new_fields(n: &NewEntry) -> Result<()> {
    if n.name.trim().is_empty() {
        return Err(AppError::InvalidInput("name".into()));
    }
    check_text(&n.name, MAX_NAME_CHARS, "name")?;
    if n.password.is_empty() {
        return Err(AppError::InvalidInput("password".into()));
    }
    check_text(&n.password, MAX_SECRET_CHARS, "password")?;
    check_text(&n.notes, MAX_NOTES_CHARS, "notes")?;
    for p in [&n.original_path, &n.encrypted_path].into_iter().flatten() {
        check_text(p, MAX_PATH_CHARS, "path")?;
    }
    Ok(())
}

fn entry_from(n: &NewEntry) -> PasswordEntry {
    PasswordEntry {
        id: uuid::Uuid::new_v4().to_string(),
        name: n.name.trim().to_owned(),
        kind: n.kind.clone(),
        original_path: n.original_path.clone(),
        encrypted_path: n.encrypted_path.clone(),
        password: n.password.clone(),
        notes: n.notes.clone(),
        favorite: false,
        created_at: now(),
        last_used_at: None,
        item_id: n.item_id.clone(),
    }
}

/// Read a file, refusing to buffer more than `max` bytes.
fn read_limited(path: &std::path::Path, max: u64) -> Result<Vec<u8>> {
    let f = fs::File::open(path)?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(AppError::Corrupted("credential store length".into()));
    }
    Ok(buf)
}

/// Paths reach the app from the file picker, drag-and-drop, the shell association and stored item
/// records, so one Windows file can arrive with `/` or `\`, different case, or a `\\?\` prefix.
/// Saved-password lookups compare this canonical form instead of raw strings.
pub fn path_key(p: &str) -> String {
    let p = p.strip_prefix(r"\\?\").unwrap_or(p);
    if cfg!(windows) {
        p.replace('/', "\\").to_lowercase()
    } else {
        p.to_owned()
    }
}

pub fn path_matches(stored: Option<&str>, wanted: &str) -> bool {
    stored.is_some_and(|s| path_key(s) == path_key(wanted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    const MASTER: &str = "correct horse battery";

    fn store(dir: &tempfile::TempDir) -> CredentialStore {
        CredentialStore::with_kdf(dir.path().join("credentials.vlkc"), KdfParams::FLOOR)
    }

    fn new_entry(name: &str, pw: &str, path: Option<&str>) -> NewEntry {
        NewEntry {
            name: name.into(),
            kind: "file".into(),
            original_path: Some("C:\\Users\\x\\orig.txt".into()),
            encrypted_path: path.map(str::to_owned),
            password: pw.into(),
            notes: String::new(),
            item_id: None,
        }
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn create_lock_unlock_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        assert!(!s.exists());
        s.create(MASTER).unwrap();
        assert!(s.exists());
        assert_eq!(s.phase(), LockPhase::Unlocked);
        let v = s
            .add(new_entry("Taxes", "hunter2-pass", Some("C:\\a.veil")))
            .unwrap();
        s.lock();
        assert_eq!(s.phase(), LockPhase::Locked);
        assert!(matches!(s.list(), Err(AppError::VaultLocked)));
        assert!(matches!(s.reveal(&v.id), Err(AppError::VaultLocked)));

        s.unlock(MASTER).unwrap();
        assert_eq!(s.phase(), LockPhase::Unlocked);
        assert_eq!(s.list().unwrap().len(), 1);
        assert_eq!(&**s.reveal(&v.id).unwrap(), "hunter2-pass");
    }

    #[test]
    fn nothing_sensitive_is_in_the_file() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        s.add(new_entry(
            "Quarterly Report",
            "S3cr3t-Entry-Pass",
            Some("C:\\r.veil"),
        ))
        .unwrap();
        s.set_default_password(Some("Default-Pass-Value")).unwrap();
        let raw = fs::read(d.path().join("credentials.vlkc")).unwrap();
        for needle in [
            MASTER,
            "S3cr3t-Entry-Pass",
            "Default-Pass-Value",
            "Quarterly Report",
            "orig.txt",
            "password",
        ] {
            assert!(!contains(&raw, needle.as_bytes()), "leaked {needle}");
        }
        assert_eq!(&raw[..8], MAGIC);
    }

    #[test]
    fn wrong_master_fails_and_stays_locked() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        s.lock();
        assert!(matches!(
            s.unlock("not the master"),
            Err(AppError::WrongPassword)
        ));
        assert_eq!(s.phase(), LockPhase::Locked);
        assert!(s.unlock(MASTER).is_ok());
    }

    #[test]
    fn every_tampered_byte_region_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        s.add(new_entry("a", "pw-pw-pw-pw", None)).unwrap();
        s.lock();
        let path = d.path().join("credentials.vlkc");
        let original = fs::read(&path).unwrap();
        // magic, version, kdf params, salt, nonce, ct_len, ciphertext, tag
        for off in [
            0usize,
            8,
            10,
            14,
            18,
            22,
            40,
            52,
            HEADER_LEN,
            original.len() - 1,
        ] {
            let mut b = original.clone();
            b[off] ^= 0x01;
            fs::write(&path, &b).unwrap();
            assert!(s.unlock(MASTER).is_err(), "offset {off} accepted");
            assert_eq!(s.phase(), LockPhase::Locked);
        }
        fs::write(&path, &original).unwrap();
        s.unlock(MASTER).unwrap();
    }

    #[test]
    fn malformed_files_are_rejected_without_allocating() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        s.lock();
        let path = d.path().join("credentials.vlkc");
        let original = fs::read(&path).unwrap();

        // truncated
        fs::write(&path, &original[..original.len() - 5]).unwrap();
        assert!(matches!(s.unlock(MASTER), Err(AppError::Corrupted(_))));
        // trailing junk
        let mut b = original.clone();
        b.push(0);
        fs::write(&path, &b).unwrap();
        assert!(matches!(s.unlock(MASTER), Err(AppError::Corrupted(_))));
        // absurd claimed length
        let mut b = original.clone();
        b[HEADER_LEN - 4..HEADER_LEN].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, &b).unwrap();
        assert!(matches!(s.unlock(MASTER), Err(AppError::Corrupted(_))));
        // hostile KDF cost must be refused before Argon2 runs
        let mut b = original.clone();
        b[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, &b).unwrap();
        assert!(matches!(s.unlock(MASTER), Err(AppError::Corrupted(_))));
        // future version
        let mut b = original.clone();
        b[8..10].copy_from_slice(&2u16.to_le_bytes());
        fs::write(&path, &b).unwrap();
        assert!(matches!(s.unlock(MASTER), Err(AppError::Unsupported(_))));
        // not ours at all
        fs::write(&path, b"hello").unwrap();
        assert!(matches!(s.unlock(MASTER), Err(AppError::Corrupted(_))));
        // missing
        fs::remove_file(&path).unwrap();
        assert!(matches!(s.unlock(MASTER), Err(AppError::NotFound(_))));
        assert_eq!(s.phase(), LockPhase::Locked);
    }

    #[test]
    fn fresh_nonce_and_salt_rules() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        let path = d.path().join("credentials.vlkc");
        let first = fs::read(&path).unwrap();
        s.add(new_entry("a", "pw-pw-pw-pw", None)).unwrap();
        let second = fs::read(&path).unwrap();
        // same salt (same master), different nonce on every save
        assert_eq!(first[22..38], second[22..38]);
        assert_ne!(first[38..50], second[38..50]);
        s.change_master(MASTER, "another master pw").unwrap();
        let third = fs::read(&path).unwrap();
        assert_ne!(
            second[22..38],
            third[22..38],
            "master change must use a new salt"
        );
    }

    #[test]
    fn master_change_keeps_data_and_replaces_old_master() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        let v = s.add(new_entry("a", "pw-pw-pw-pw", None)).unwrap();
        s.set_default_password(Some("dflt-pass-1")).unwrap();

        assert!(matches!(
            s.change_master("wrong current", "new master pw"),
            Err(AppError::WrongPassword)
        ));
        assert!(matches!(
            s.change_master(MASTER, "short"),
            Err(AppError::InvalidInput(_))
        ));
        s.change_master(MASTER, "new master pw").unwrap();
        s.lock();
        assert!(matches!(s.unlock(MASTER), Err(AppError::WrongPassword)));
        s.unlock("new master pw").unwrap();
        assert_eq!(&**s.reveal(&v.id).unwrap(), "pw-pw-pw-pw");
        assert_eq!(&**s.default_password().unwrap().unwrap(), "dflt-pass-1");
    }

    #[test]
    fn verify_master_checks_without_storing_it() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        s.verify_master(MASTER).unwrap();
        assert!(matches!(
            s.verify_master("nope nope nope"),
            Err(AppError::WrongPassword)
        ));
        s.lock();
        assert!(matches!(
            s.verify_master(MASTER),
            Err(AppError::VaultLocked)
        ));
    }

    #[test]
    fn master_password_normalisation_is_applied() {
        // "é" as one code point vs. e + combining accent must be the same password.
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create("caf\u{e9} password").unwrap();
        s.lock();
        s.unlock("cafe\u{301} password").unwrap();
    }

    #[test]
    fn edit_favorite_delete_and_use() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        let v = s
            .add(new_entry("a", "pw-pw-pw-pw", Some("C:\\a.veil")))
            .unwrap();
        assert!(v.last_used_at.is_none());

        let upd = EntryUpdate {
            name: Some("  Renamed ".into()),
            notes: Some("remember".into()),
            password: Some("new-pw-new-pw".into()),
            favorite: Some(true),
        };
        let v2 = s.update(&v.id, upd).unwrap();
        assert_eq!(v2.name, "Renamed");
        assert!(v2.favorite && v2.has_notes);
        assert_eq!(s.entry_for_edit(&v.id).unwrap().notes, "remember");

        assert_eq!(
            &**s.use_for_path("C:\\a.veil").unwrap().unwrap(),
            "new-pw-new-pw"
        );
        assert!(s.list().unwrap()[0].last_used_at.is_some());
        assert!(s.use_for_path("C:\\none.veil").unwrap().is_none());

        // The same file arriving with forward slashes or other case still finds its entry.
        if cfg!(windows) {
            assert!(s.has_for_path("c:/A.veil").unwrap());
            assert_eq!(
                &**s.use_for_path("C:/a.VEIL").unwrap().unwrap(),
                "new-pw-new-pw"
            );
        }
        assert!(!s.has_for_path("C:\\b.veil").unwrap());

        s.repoint_path("C:\\a.veil", "D:\\moved.veil").unwrap();
        assert!(s.has_for_path("D:\\moved.veil").unwrap());
        assert!(!s.has_for_path("C:\\a.veil").unwrap());

        s.delete(&v.id).unwrap();
        assert!(s.list().unwrap().is_empty());
        assert!(matches!(s.delete(&v.id), Err(AppError::NotFound(_))));
        assert!(matches!(s.reveal(&v.id), Err(AppError::NotFound(_))));
    }

    #[test]
    fn upsert_replaces_by_path() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        let a = s
            .upsert_for_path(new_entry("a", "first-pass-1", Some("C:\\a.veil")))
            .unwrap();
        let b = s
            .upsert_for_path(new_entry("a", "second-pass-2", Some("C:\\a.veil")))
            .unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(s.list().unwrap().len(), 1);
        assert_eq!(&**s.reveal(&a.id).unwrap(), "second-pass-2");
        assert!(matches!(
            s.upsert_for_path(new_entry("x", "pw-pw-pw-pw", None)),
            Err(AppError::InvalidInput(_))
        ));
    }

    #[test]
    fn input_validation() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        let mut e = new_entry("", "pw-pw-pw-pw", None);
        assert!(s.add(e).is_err());
        e = new_entry("ok", "", None);
        assert!(s.add(e).is_err());
        e = new_entry("ok", "pw-pw-pw-pw", None);
        e.kind = "weird".into();
        assert!(s.add(e).is_err());
        e = new_entry("ok", &"x".repeat(MAX_SECRET_CHARS + 1), None);
        assert!(s.add(e).is_err());
        assert!(s.set_default_password(Some("")).is_err());
        assert!(s.create("short").is_err());
    }

    #[test]
    fn failed_write_leaves_memory_unchanged() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        // Make the target path a directory so the atomic rename must fail.
        let path = d.path().join("credentials.vlkc");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(s.add(new_entry("a", "pw-pw-pw-pw", None)).is_err());
        assert!(s.list().unwrap().is_empty());
        // no leftover temp files
        let leftovers: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn default_password_lifecycle() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        assert!(!s.has_default_password().unwrap());
        s.set_default_password(Some("dflt-pass-1")).unwrap();
        assert!(s.has_default_password().unwrap());
        s.lock();
        assert!(matches!(
            s.has_default_password(),
            Err(AppError::VaultLocked)
        ));
        s.unlock(MASTER).unwrap();
        assert!(s.has_default_password().unwrap());
        s.set_default_password(None).unwrap();
        assert!(s.default_password().unwrap().is_none());
    }

    #[test]
    fn create_refuses_to_overwrite_existing_store() {
        let d = tempfile::tempdir().unwrap();
        let s = store(&d);
        s.create(MASTER).unwrap();
        s.lock();
        assert!(matches!(
            s.create("another master"),
            Err(AppError::OutputExists(_))
        ));
        s.unlock(MASTER).unwrap();
    }

    #[test]
    fn lock_during_unlock_discards_the_result() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("credentials.vlkc");
        // Heavy enough that the unlock is still deriving when lock() runs.
        let heavy = KdfParams {
            m_cost_kib: 128 * 1024,
            t_cost: 6,
            p_cost: 1,
        };
        let s = Arc::new(CredentialStore::with_kdf(path, heavy));
        s.create(MASTER).unwrap();
        s.lock();

        let s2 = Arc::clone(&s);
        let h = std::thread::spawn(move || s2.unlock(MASTER));
        // Wait for the unlock to reach its derivation phase.
        let mut waited = 0;
        while s.phase() != LockPhase::Unlocking && waited < 200 {
            std::thread::sleep(Duration::from_millis(5));
            waited += 1;
        }
        assert_eq!(s.phase(), LockPhase::Unlocking);
        // A second unlock while one is in flight is refused rather than racing.
        assert!(matches!(s.unlock(MASTER), Err(AppError::Busy)));
        s.lock();
        assert!(matches!(h.join().unwrap(), Err(AppError::Cancelled)));
        assert_eq!(s.phase(), LockPhase::Locked);
        assert!(!s.is_unlocked());
    }

    #[test]
    fn read_limited_rejects_oversize() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        fs::write(&p, vec![0u8; 100]).unwrap();
        assert!(read_limited(&p, 50).is_err());
        assert_eq!(read_limited(&p, 100).unwrap().len(), 100);
    }
}
