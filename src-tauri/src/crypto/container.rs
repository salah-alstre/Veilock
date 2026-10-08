//! The container: ties header, key slots, encrypted metadata and the chunk stream together.
//!
//! ```text
//!   0..48     core header (clear, bound into every AAD)
//!  48..480    key-slot region (4 x 108 bytes: password primary/shadow, recovery primary/shadow)
//! 480..484    metadata ciphertext length (u32 LE, range-checked before allocation)
//! 484..496    metadata nonce
//! 496..       metadata ciphertext (AES-256-GCM, AAD = header hash || "meta")
//!   ...       data chunks (see `stream`)
//! ```
//! Full specification: `docs/FORMAT.md`.

use super::header::CoreHeader;
use super::kdf::{hkdf32, KdfParams, Key32};
use super::keyslot::{
    new_password_record, new_recovery_record, Record, SlotKind, SlotRegion, SLOT_RECORD_LEN,
    SLOT_REGION_LEN,
};
use super::metadata::Metadata;
use super::params::*;
use super::password;
use super::recovery::RecoveryKey;
use super::stream::{
    decrypt_stream, encrypt_stream, read_full, HashingReader, HashingSink, Progress,
};
use crate::errors::{AppError, Result};
use rand::RngCore;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::Zeroizing;

const META_KEY_INFO: &[u8] = b"veilock/meta";
const DATA_KEY_INFO: &[u8] = b"veilock/data";

/// Offset of the key-slot region within the file.
const SLOT_REGION_OFFSET: u64 = CORE_HEADER_LEN as u64;

/// How the caller proves it may open a container.
pub enum Unlock<'a> {
    Password(&'a str),
    Recovery(&'a RecoveryKey),
}

pub struct SealOptions<'a> {
    pub password: &'a str,
    pub kdf: KdfParams,
    pub chunk_size: u32,
    pub with_recovery: bool,
    pub kind: ContainerKind,
    pub metadata: Metadata,
    /// If set, the number of plaintext bytes the source is expected to yield. A mismatch means the
    /// source was modified while we were reading it, and the operation is aborted.
    pub expected_plaintext_len: Option<u64>,
}

/// Result of sealing. `dek` lets the caller verify the output without re-running Argon2.
pub struct Sealed {
    pub dek: Key32,
    pub plaintext_sha256: [u8; 32],
    pub plaintext_len: u64,
    pub recovery_key: Option<RecoveryKey>,
}

pub struct Opened {
    pub header: CoreHeader,
    pub dek: Key32,
    pub metadata: Metadata,
    /// Absolute offset of the first data chunk.
    pub data_offset: u64,
}

/// Unauthenticated facts readable without any secret. Treat as hints only: an attacker can forge
/// all of it, and the real checks happen when the container is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    pub version: u16,
    pub kind: ContainerKind,
    pub cipher: &'static str,
    pub chunk_size: u32,
    pub has_password_slot: bool,
    pub has_recovery_slot: bool,
    pub kdf: Option<KdfParams>,
}

fn derive_keys(dek: &Key32, header: &CoreHeader) -> (Key32, Key32) {
    (
        hkdf32(&**dek, &header.file_id, META_KEY_INFO),
        hkdf32(&**dek, &header.file_id, DATA_KEY_INFO),
    )
}

/// Encrypt `src` into `dst`. `dst` should be a temp file; the caller finalises it after
/// verification.
pub fn seal<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    opts: &SealOptions<'_>,
    progress: Progress<'_>,
) -> Result<Sealed> {
    if opts.password.is_empty() {
        return Err(AppError::InvalidInput("password must not be empty".into()));
    }
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&opts.chunk_size) {
        return Err(AppError::InvalidInput("chunk size out of range".into()));
    }
    opts.kdf.validate_untrusted()?;

    let mut rng = rand::rngs::OsRng;
    let mut file_id = [0u8; FILE_ID_LEN];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    rng.fill_bytes(&mut file_id);
    rng.fill_bytes(&mut nonce_prefix);
    // The DEK is the only thing that protects the data; it comes straight from the OS CSPRNG and
    // is never derived from the password (so a password change never touches the data).
    let mut dek: Key32 = Zeroizing::new([0u8; KEY_LEN]);
    rng.fill_bytes(&mut *dek);

    let header = CoreHeader {
        version: FORMAT_VERSION,
        kind: opts.kind,
        cipher: CipherId::Aes256Gcm,
        chunk_size: opts.chunk_size,
        file_id,
        nonce_prefix,
    };
    let header_bytes = header.to_bytes();
    let core_hash = CoreHeader::hash(&header_bytes);
    let (meta_key, data_key) = derive_keys(&dek, &header);

    let pw = password::normalize(opts.password);
    let mut slots = SlotRegion::empty();
    let rec = new_password_record(&pw, opts.kdf, &dek, &header)?;
    slots.set_both(SlotKind::Password, &rec);
    let recovery_key = if opts.with_recovery {
        let rk = RecoveryKey::generate();
        let rec = new_recovery_record(&rk, &dek, &header)?;
        slots.set_both(SlotKind::Recovery, &rec);
        Some(rk)
    } else {
        None
    };

    let meta_block = opts.metadata.seal(&meta_key, &core_hash)?;

    dst.write_all(&header_bytes)?;
    dst.write_all(slots.as_bytes())?;
    dst.write_all(&meta_block)?;

    let mut reader = HashingReader::new(src);
    encrypt_stream(&mut reader, dst, &header, &data_key, progress)?;
    let (sha, len) = reader.finish();
    if let Some(expected) = opts.expected_plaintext_len {
        if expected != len {
            return Err(AppError::SourceChanged);
        }
    }
    Ok(Sealed {
        dek,
        plaintext_sha256: sha,
        plaintext_len: len,
        recovery_key,
    })
}

fn read_header<R: Read>(r: &mut R) -> Result<CoreHeader> {
    let mut raw = [0u8; CORE_HEADER_LEN];
    let n = read_full(r, &mut raw)?;
    // Decide "not ours" from the magic alone so short foreign files get a clean error, while a
    // file that starts like ours but is cut short is reported as damaged.
    if n < MAGIC.len() || raw[..MAGIC.len()] != MAGIC {
        return Err(AppError::NotAContainer);
    }
    if n < CORE_HEADER_LEN {
        return Err(AppError::Corrupted("file is truncated".into()));
    }
    CoreHeader::parse(&raw)
}

fn read_slots<R: Read>(r: &mut R) -> Result<SlotRegion> {
    let mut raw = [0u8; SLOT_REGION_LEN];
    r.read_exact(&mut raw).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            AppError::Corrupted("file is truncated".into())
        } else {
            e.into()
        }
    })?;
    Ok(SlotRegion::from_bytes(raw))
}

fn unlock_dek(slots: &SlotRegion, header: &CoreHeader, unlock: &Unlock<'_>) -> Result<Key32> {
    match unlock {
        Unlock::Password(p) => {
            let pw = password::normalize(p);
            slots.unwrap_password(&pw, header)
        }
        Unlock::Recovery(k) => slots.unwrap_recovery(k, header),
    }
}

/// Parse, unlock and authenticate the metadata. Leaves `r` positioned at the first data chunk.
pub fn open<R: Read>(r: &mut R, unlock: &Unlock<'_>) -> Result<Opened> {
    let header = read_header(r)?;
    let slots = read_slots(r)?;
    let dek = unlock_dek(&slots, &header, unlock)?;
    let (meta_key, _) = derive_keys(&dek, &header);
    let block = Metadata::read_block(r)?;
    let metadata = Metadata::open(&block, &meta_key, &CoreHeader::hash(&header.to_bytes()))?;
    let data_offset = SLOT_REGION_OFFSET + SLOT_REGION_LEN as u64 + 4 + block.len() as u64;
    Ok(Opened {
        header,
        dek,
        metadata,
        data_offset,
    })
}

/// Unlock and decrypt everything into `dst` (a temp file; the caller publishes it only on `Ok`).
pub fn decrypt<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    unlock: &Unlock<'_>,
    progress: Progress<'_>,
) -> Result<(Opened, u64)> {
    let opened = open(src, unlock)?;
    let (_, data_key) = derive_keys(&opened.dek, &opened.header);
    let n = decrypt_stream(src, dst, &opened.header, &data_key, progress)?;
    Ok((opened, n))
}

/// Decrypt the data section of an already-opened container (`src` must be positioned at
/// `opened.data_offset`, which is where `open` leaves it). Splitting this from `open` lets callers
/// pick and create their output only after the password has been accepted, so a wrong password
/// never touches the file system.
pub fn decrypt_body<R: Read, W: Write>(
    src: &mut R,
    opened: &Opened,
    dst: &mut W,
    progress: Progress<'_>,
) -> Result<u64> {
    let (_, data_key) = derive_keys(&opened.dek, &opened.header);
    decrypt_stream(src, dst, &opened.header, &data_key, progress)
}

/// Re-read a freshly written container using the in-memory DEK (no Argon2) and confirm it
/// decrypts to exactly the data that was encrypted. Any authentication failure here means the
/// output on disk is bad, which is reported as `VerificationFailed` so the source is kept.
pub fn verify<R: Read>(
    r: &mut R,
    dek: &Key32,
    expected_sha256: &[u8; 32],
    expected_len: u64,
    progress: Progress<'_>,
) -> Result<()> {
    let as_verify_failure = |e: AppError| match e {
        AppError::Corrupted(_) | AppError::NotAContainer | AppError::Unsupported(_) => {
            AppError::VerificationFailed
        }
        other => other,
    };
    let header = read_header(r).map_err(as_verify_failure)?;
    let _slots = read_slots(r).map_err(as_verify_failure)?;
    let (meta_key, data_key) = derive_keys(dek, &header);
    let block = Metadata::read_block(r).map_err(as_verify_failure)?;
    Metadata::open(&block, &meta_key, &CoreHeader::hash(&header.to_bytes()))
        .map_err(as_verify_failure)?;

    let mut sink = HashingSink::new();
    decrypt_stream(r, &mut sink, &header, &data_key, progress).map_err(as_verify_failure)?;
    let (sha, len) = sink.finish();
    if len != expected_len || &sha != expected_sha256 {
        return Err(AppError::VerificationFailed);
    }
    Ok(())
}

/// Read only the clear-text structure. Nothing here is authenticated.
pub fn inspect<R: Read>(r: &mut R) -> Result<Inspection> {
    let header = read_header(r)?;
    let slots = read_slots(r)?;
    Ok(Inspection {
        version: header.version,
        kind: header.kind,
        cipher: header.cipher.name(),
        chunk_size: header.chunk_size,
        has_password_slot: slots.has(SlotKind::Password),
        has_recovery_slot: slots.has(SlotKind::Recovery),
        kdf: slots.password_params(),
    })
}

/// Overwrite one slot pair on disk: shadow first, flushed, then primary, flushed. At every
/// instant at least one complete copy exists, so a crash cannot lock the user out.
fn write_slot_pair(file: &mut File, kind: SlotKind, rec: &Record) -> Result<()> {
    let (primary, shadow) = kind.offsets();
    for off in [shadow, primary] {
        file.seek(SeekFrom::Start(SLOT_REGION_OFFSET + off as u64))?;
        file.write_all(rec)?;
        file.sync_all()?;
    }
    Ok(())
}

/// Authenticate with `unlock` and return the DEK and header. Reads from the start of `file`.
fn unlock_file(file: &mut File, unlock: &Unlock<'_>) -> Result<(CoreHeader, Key32)> {
    file.seek(SeekFrom::Start(0))?;
    let header = read_header(file)?;
    let slots = read_slots(file)?;
    let dek = unlock_dek(&slots, &header, unlock)?;
    Ok((header, dek))
}

/// Re-wrap the DEK under a new password. The data section is untouched. Works with either the
/// current password or the recovery key (the "forgot my password" path).
pub fn change_password(
    file: &mut File,
    unlock: &Unlock<'_>,
    new_password: &str,
    kdf: KdfParams,
) -> Result<()> {
    if new_password.is_empty() {
        return Err(AppError::InvalidInput("password must not be empty".into()));
    }
    let (header, dek) = unlock_file(file, unlock)?;
    let pw = password::normalize(new_password);
    let rec = new_password_record(&pw, kdf, &dek, &header)?;
    write_slot_pair(file, SlotKind::Password, &rec)
}

/// Create (or replace) the recovery slot. A previous recovery key stops working.
pub fn set_recovery(file: &mut File, unlock: &Unlock<'_>) -> Result<RecoveryKey> {
    let (header, dek) = unlock_file(file, unlock)?;
    let rk = RecoveryKey::generate();
    let rec = new_recovery_record(&rk, &dek, &header)?;
    write_slot_pair(file, SlotKind::Recovery, &rec)?;
    Ok(rk)
}

pub fn remove_recovery(file: &mut File, unlock: &Unlock<'_>) -> Result<()> {
    // Authenticate first: removing a safety net is a security-relevant change.
    let _ = unlock_file(file, unlock)?;
    let zero: Record = [0u8; SLOT_RECORD_LEN];
    write_slot_pair(file, SlotKind::Recovery, &zero)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CS: u32 = MIN_CHUNK_SIZE;
    const PW: &str = "correct horse battery staple";

    fn meta(len: u64) -> Metadata {
        Metadata {
            name: "ملف سري.txt".into(),
            kind: "file".into(),
            original_size: len,
            created_at: 1_700_000_000,
            file_count: 1,
            dir_count: 0,
            app_version: "test".into(),
        }
    }

    fn opts(len: u64, recovery: bool) -> SealOptions<'static> {
        SealOptions {
            password: PW,
            kdf: KdfParams::FLOOR,
            chunk_size: CS,
            with_recovery: recovery,
            kind: ContainerKind::File,
            metadata: meta(len),
            expected_plaintext_len: Some(len),
        }
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
    }

    fn seal_vec(plain: &[u8], recovery: bool) -> (Vec<u8>, Sealed) {
        let mut out = Vec::new();
        let sealed = seal(
            &mut &plain[..],
            &mut out,
            &opts(plain.len() as u64, recovery),
            &mut |_| Ok(()),
        )
        .unwrap();
        (out, sealed)
    }

    fn open_vec(ct: &[u8], unlock: &Unlock<'_>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        decrypt(&mut &ct[..], &mut out, unlock, &mut |_| Ok(()))?;
        Ok(out)
    }

    #[test]
    fn roundtrip_across_chunk_boundaries() {
        let cs = CS as usize;
        for len in [0, 1, cs - 1, cs, cs + 1, 2 * cs, 2 * cs + 17, 5 * cs + 1234] {
            let plain = data(len);
            let (ct, sealed) = seal_vec(&plain, false);
            assert_eq!(sealed.plaintext_len, len as u64);
            assert_eq!(
                open_vec(&ct, &Unlock::Password(PW)).unwrap(),
                plain,
                "len {len}"
            );
        }
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext_or_filename() {
        let plain = b"THIS-IS-A-VERY-RECOGNISABLE-PLAINTEXT-MARKER".repeat(200);
        let (ct, _) = seal_vec(&plain, false);
        let needle = &plain[..44];
        assert!(!ct.windows(needle.len()).any(|w| w == needle));
        let name = "ملف سري.txt".as_bytes();
        assert!(!ct.windows(name.len()).any(|w| w == name));
    }

    #[test]
    fn two_encryptions_of_same_input_differ() {
        let plain = data(3000);
        let (a, _) = seal_vec(&plain, false);
        let (b, _) = seal_vec(&plain, false);
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_password_fails() {
        let (ct, _) = seal_vec(&data(5000), false);
        assert!(matches!(
            open_vec(&ct, &Unlock::Password("wrong")),
            Err(AppError::WrongPassword)
        ));
    }

    #[test]
    fn unicode_normalisation_makes_equivalent_passwords_match() {
        let mut o = opts(3, false);
        o.password = "caf\u{00e9}";
        let mut ct = Vec::new();
        seal(&mut &b"abc"[..], &mut ct, &o, &mut |_| Ok(())).unwrap();
        assert_eq!(
            open_vec(&ct, &Unlock::Password("cafe\u{0301}")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn empty_password_is_rejected() {
        let mut o = opts(0, false);
        o.password = "";
        let r = seal(&mut &b""[..], &mut Vec::new(), &o, &mut |_| Ok(()));
        assert!(matches!(r, Err(AppError::InvalidInput(_))));
    }

    #[test]
    fn metadata_round_trips_after_unlock() {
        let (ct, _) = seal_vec(&data(10), false);
        let opened = open(&mut &ct[..], &Unlock::Password(PW)).unwrap();
        assert_eq!(opened.metadata, meta(10));
        assert_eq!(opened.header.kind, ContainerKind::File);
        assert_eq!(
            opened.data_offset,
            496 + opened.metadata_ct_len_for_test(&ct)
        );
    }

    impl Opened {
        fn metadata_ct_len_for_test(&self, ct: &[u8]) -> u64 {
            u32::from_le_bytes(ct[480..484].try_into().unwrap()) as u64
        }
    }

    #[test]
    fn recovery_key_unlocks_and_wrong_one_fails() {
        let plain = data(9000);
        let (ct, sealed) = seal_vec(&plain, true);
        let rk = sealed.recovery_key.unwrap();
        assert_eq!(open_vec(&ct, &Unlock::Recovery(&rk)).unwrap(), plain);
        let wrong = RecoveryKey::generate();
        assert!(matches!(
            open_vec(&ct, &Unlock::Recovery(&wrong)),
            Err(AppError::InvalidInput(_)) | Err(AppError::InvalidRecoveryKey)
        ));
        // Round trip through the human-readable form too.
        let text = rk.to_display_string();
        let parsed = RecoveryKey::parse(&text).unwrap();
        assert_eq!(open_vec(&ct, &Unlock::Recovery(&parsed)).unwrap(), plain);
    }

    #[test]
    fn container_without_recovery_slot_rejects_recovery_key() {
        let (ct, _) = seal_vec(&data(100), false);
        let rk = RecoveryKey::generate();
        assert!(matches!(
            open_vec(&ct, &Unlock::Recovery(&rk)),
            Err(AppError::Corrupted(_))
        ));
    }

    #[test]
    fn foreign_and_short_files_are_not_containers() {
        for bytes in [&b""[..], &b"hello"[..], &[0u8; 600][..]] {
            assert!(matches!(
                open(&mut &bytes[..], &Unlock::Password(PW)),
                Err(AppError::NotAContainer)
            ));
        }
        // Valid magic but cut short is damage, not "not ours".
        let (ct, _) = seal_vec(&data(10), false);
        assert!(matches!(
            open(&mut &ct[..20], &Unlock::Password(PW)),
            Err(AppError::Corrupted(_))
        ));
    }

    #[test]
    fn newer_format_version_is_unsupported() {
        let (mut ct, _) = seal_vec(&data(10), false);
        ct[8] = 99;
        assert!(matches!(
            open(&mut &ct[..], &Unlock::Password(PW)),
            Err(AppError::Unsupported(_))
        ));
    }

    #[test]
    fn any_bit_flip_in_header_metadata_or_data_is_detected() {
        let plain = data(3 * CS as usize + 100);
        let (ct, _) = seal_vec(&plain, true);
        let slots_end = 480;
        let mut offsets: Vec<usize> = (0..slots_end.min(48)).collect(); // whole header
        offsets.extend(480..520); // metadata length, nonce, start of ciphertext
        let mut o = 520;
        while o < ct.len() {
            offsets.push(o);
            o += 331;
        }
        offsets.push(ct.len() - 1);
        for off in offsets {
            let mut bad = ct.clone();
            bad[off] ^= 0x01;
            assert!(
                open_vec(&bad, &Unlock::Password(PW)).is_err(),
                "flip at {off} went undetected"
            );
        }
    }

    #[test]
    fn corrupting_both_copies_of_a_slot_is_detected_but_one_copy_is_survivable() {
        let plain = data(500);
        let (ct, _) = seal_vec(&plain, false);
        // One copy damaged: the other still opens (this is the torn-write protection).
        let mut one = ct.clone();
        one[48 + 50] ^= 1;
        assert_eq!(open_vec(&one, &Unlock::Password(PW)).unwrap(), plain);
        // Both damaged: refuse, and do not claim the password is wrong.
        let mut both = one.clone();
        both[48 + SLOT_RECORD_LEN + 50] ^= 1;
        assert!(matches!(
            open_vec(&both, &Unlock::Password(PW)),
            Err(AppError::Corrupted(_))
        ));
    }

    #[test]
    fn truncation_at_every_interesting_point_is_detected() {
        let plain = data(3 * CS as usize + 100);
        let (ct, _) = seal_vec(&plain, false);
        let opened = open(&mut &ct[..], &Unlock::Password(PW)).unwrap();
        let d = opened.data_offset as usize;
        let full_chunk = CS as usize + TAG_LEN;
        let cuts = [
            0,
            10,
            48,
            100,
            480,
            496,
            d,
            d + 5,
            d + full_chunk,     // exactly one chunk kept
            d + 2 * full_chunk, // chunk boundary: previous chunk was not "final"
            d + 3 * full_chunk,
            ct.len() - 1,
            ct.len() - TAG_LEN,
        ];
        for cut in cuts {
            assert!(
                open_vec(&ct[..cut], &Unlock::Password(PW)).is_err(),
                "truncation at {cut} went undetected"
            );
        }
    }

    #[test]
    fn appended_data_is_detected() {
        let (mut ct, _) = seal_vec(&data(2 * CS as usize), false);
        ct.extend_from_slice(&[0u8; 64]);
        assert!(open_vec(&ct, &Unlock::Password(PW)).is_err());
    }

    #[test]
    fn chunks_cannot_be_swapped() {
        let plain = data(3 * CS as usize);
        let (mut ct, _) = seal_vec(&plain, false);
        let d = open(&mut &ct[..], &Unlock::Password(PW))
            .unwrap()
            .data_offset as usize;
        let n = CS as usize + TAG_LEN;
        let (a, b) = (d, d + n);
        for i in 0..n {
            ct.swap(a + i, b + i);
        }
        assert!(open_vec(&ct, &Unlock::Password(PW)).is_err());
    }

    #[test]
    fn chunks_cannot_be_spliced_between_files() {
        let plain = data(2 * CS as usize);
        let (a, _) = seal_vec(&plain, false);
        let (mut b, _) = seal_vec(&plain, false);
        let da = open(&mut &a[..], &Unlock::Password(PW))
            .unwrap()
            .data_offset as usize;
        let db = open(&mut &b[..], &Unlock::Password(PW))
            .unwrap()
            .data_offset as usize;
        let n = CS as usize + TAG_LEN;
        b[db..db + n].copy_from_slice(&a[da..da + n]);
        assert!(open_vec(&b, &Unlock::Password(PW)).is_err());
    }

    #[test]
    fn key_slots_cannot_be_transplanted_between_files() {
        let (a, _) = seal_vec(&data(100), false);
        let (mut b, _) = seal_vec(&data(100), false);
        b[48..480].copy_from_slice(&a[48..480]);
        assert!(open_vec(&b, &Unlock::Password(PW)).is_err());
    }

    #[test]
    fn oversized_metadata_length_is_rejected() {
        let (mut ct, _) = seal_vec(&data(100), false);
        ct[480..484].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            open_vec(&ct, &Unlock::Password(PW)),
            Err(AppError::Corrupted(_))
        ));
    }

    #[test]
    fn hostile_kdf_parameters_in_a_slot_are_refused() {
        let (mut ct, _) = seal_vec(&data(100), false);
        // Memory cost 4 TiB in both password copies, with a recomputed checksum so it passes the
        // torn-write check and must be stopped by parameter validation.
        for off in [48usize, 48 + SLOT_RECORD_LEN] {
            ct[off + 4..off + 8].copy_from_slice(&u32::MAX.to_le_bytes());
            let sum = sha2::Sha256::digest(&ct[off..off + 92]);
            ct[off + 92..off + 108].copy_from_slice(&sum[..16]);
        }
        use sha2::Digest;
        assert!(matches!(
            open_vec(&ct, &Unlock::Password(PW)),
            Err(AppError::Corrupted(_))
        ));
    }

    #[test]
    fn verify_accepts_good_output_and_rejects_bad_output() {
        let plain = data(2 * CS as usize + 9);
        let (ct, sealed) = seal_vec(&plain, false);
        let sha = sealed.plaintext_sha256;
        verify(
            &mut &ct[..],
            &sealed.dek,
            &sha,
            sealed.plaintext_len,
            &mut |_| Ok(()),
        )
        .unwrap();

        let mut bad = ct.clone();
        let last = bad.len() - 3;
        bad[last] ^= 1;
        assert!(matches!(
            verify(
                &mut &bad[..],
                &sealed.dek,
                &sha,
                sealed.plaintext_len,
                &mut |_| Ok(())
            ),
            Err(AppError::VerificationFailed)
        ));
        // Wrong expectations (e.g. source changed) must not verify either.
        let mut other_sha = sha;
        other_sha[0] ^= 1;
        assert!(matches!(
            verify(
                &mut &ct[..],
                &sealed.dek,
                &other_sha,
                sealed.plaintext_len,
                &mut |_| Ok(())
            ),
            Err(AppError::VerificationFailed)
        ));
        assert!(matches!(
            verify(
                &mut &ct[..],
                &sealed.dek,
                &sha,
                sealed.plaintext_len + 1,
                &mut |_| Ok(())
            ),
            Err(AppError::VerificationFailed)
        ));
    }

    #[test]
    fn source_changing_during_encryption_aborts() {
        let plain = data(1000);
        let mut o = opts(999, false); // claims a different length than what is read
        o.expected_plaintext_len = Some(999);
        let r = seal(&mut &plain[..], &mut Vec::new(), &o, &mut |_| Ok(()));
        assert!(r.is_err());
    }

    #[test]
    fn cancellation_stops_encryption_and_decryption() {
        let plain = data(10 * CS as usize);
        let mut calls = 0;
        let r = seal(
            &mut &plain[..],
            &mut Vec::new(),
            &opts(plain.len() as u64, false),
            &mut |_| {
                calls += 1;
                if calls == 3 {
                    Err(AppError::Cancelled)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(r, Err(AppError::Cancelled)));

        let (ct, _) = seal_vec(&plain, false);
        let mut calls = 0;
        let r = decrypt(
            &mut &ct[..],
            &mut Vec::new(),
            &Unlock::Password(PW),
            &mut |_| {
                calls += 1;
                if calls == 2 {
                    Err(AppError::Cancelled)
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(r, Err(AppError::Cancelled)));
    }

    #[test]
    fn progress_is_monotonic_and_reaches_total() {
        let plain = data(4 * CS as usize + 7);
        let mut seen = Vec::new();
        seal(
            &mut &plain[..],
            &mut Vec::new(),
            &opts(plain.len() as u64, false),
            &mut |n| {
                seen.push(n);
                Ok(())
            },
        )
        .unwrap();
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(*seen.last().unwrap(), plain.len() as u64);
    }

    #[test]
    fn inspect_reports_structure_without_a_password() {
        let (ct, _) = seal_vec(&data(10), true);
        let i = inspect(&mut &ct[..]).unwrap();
        assert_eq!(i.version, FORMAT_VERSION);
        assert_eq!(i.cipher, "AES-256-GCM");
        assert!(i.has_password_slot && i.has_recovery_slot);
        assert_eq!(i.kdf, Some(KdfParams::FLOOR));
        assert!(matches!(
            inspect(&mut &b"nope"[..]),
            Err(AppError::NotAContainer)
        ));
    }

    // ---- operations that rewrite the key slots on disk ----

    fn write_temp(ct: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.veil");
        std::fs::write(&p, ct).unwrap();
        (dir, p)
    }

    fn rw(p: &std::path::Path) -> File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(p)
            .unwrap()
    }

    #[test]
    fn password_change_preserves_data_and_invalidates_old_password() {
        let plain = data(3 * CS as usize + 5);
        let (ct, _) = seal_vec(&plain, false);
        let (_d, p) = write_temp(&ct);
        let before = std::fs::read(&p).unwrap();

        change_password(
            &mut rw(&p),
            &Unlock::Password(PW),
            "new-password-1",
            KdfParams::FLOOR,
        )
        .unwrap();

        let after = std::fs::read(&p).unwrap();
        assert_eq!(before.len(), after.len());
        // Only the password slot pair may differ; header, metadata and all data are byte-identical.
        let changed: Vec<usize> = (0..before.len())
            .filter(|&i| before[i] != after[i])
            .collect();
        assert!(changed
            .iter()
            .all(|&i| (48..48 + 2 * SLOT_RECORD_LEN).contains(&i)));

        assert_eq!(
            open_vec(&after, &Unlock::Password("new-password-1")).unwrap(),
            plain
        );
        assert!(matches!(
            open_vec(&after, &Unlock::Password(PW)),
            Err(AppError::WrongPassword)
        ));
    }

    #[test]
    fn password_change_with_wrong_current_password_changes_nothing() {
        let (ct, _) = seal_vec(&data(100), false);
        let (_d, p) = write_temp(&ct);
        let r = change_password(
            &mut rw(&p),
            &Unlock::Password("nope"),
            "x",
            KdfParams::FLOOR,
        );
        assert!(matches!(r, Err(AppError::WrongPassword)));
        assert_eq!(std::fs::read(&p).unwrap(), ct);
    }

    #[test]
    fn forgotten_password_can_be_reset_with_recovery_key() {
        let plain = data(2000);
        let (ct, sealed) = seal_vec(&plain, true);
        let rk = sealed.recovery_key.unwrap();
        let (_d, p) = write_temp(&ct);
        change_password(
            &mut rw(&p),
            &Unlock::Recovery(&rk),
            "fresh-pw",
            KdfParams::FLOOR,
        )
        .unwrap();
        let after = std::fs::read(&p).unwrap();
        assert_eq!(
            open_vec(&after, &Unlock::Password("fresh-pw")).unwrap(),
            plain
        );
        // The recovery key still works afterwards.
        assert_eq!(open_vec(&after, &Unlock::Recovery(&rk)).unwrap(), plain);
    }

    #[test]
    fn interrupted_password_change_never_locks_the_user_out() {
        let plain = data(700);
        let (ct, _) = seal_vec(&plain, false);
        let (_d, p) = write_temp(&ct);
        change_password(
            &mut rw(&p),
            &Unlock::Password(PW),
            "second",
            KdfParams::FLOOR,
        )
        .unwrap();
        let done = std::fs::read(&p).unwrap();

        // Crash point A: shadow written, primary still old.
        let mut a = ct.clone();
        a[48 + SLOT_RECORD_LEN..48 + 2 * SLOT_RECORD_LEN]
            .copy_from_slice(&done[48 + SLOT_RECORD_LEN..48 + 2 * SLOT_RECORD_LEN]);
        assert!(open_vec(&a, &Unlock::Password(PW)).is_ok());
        assert!(open_vec(&a, &Unlock::Password("second")).is_ok());

        // Crash point B: primary torn half-way through its write (shadow already new).
        let mut b = a.clone();
        b[48..88].copy_from_slice(&done[48..88]);
        assert!(open_vec(&b, &Unlock::Password("second")).is_ok());
    }

    #[test]
    fn recovery_slot_can_be_added_replaced_and_removed() {
        let plain = data(1500);
        let (ct, _) = seal_vec(&plain, false);
        let (_d, p) = write_temp(&ct);

        let rk1 = set_recovery(&mut rw(&p), &Unlock::Password(PW)).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(open_vec(&bytes, &Unlock::Recovery(&rk1)).unwrap(), plain);

        let rk2 = set_recovery(&mut rw(&p), &Unlock::Password(PW)).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert!(open_vec(&bytes, &Unlock::Recovery(&rk1)).is_err());
        assert_eq!(open_vec(&bytes, &Unlock::Recovery(&rk2)).unwrap(), plain);

        remove_recovery(&mut rw(&p), &Unlock::Password(PW)).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert!(!inspect(&mut &bytes[..]).unwrap().has_recovery_slot);
        assert!(open_vec(&bytes, &Unlock::Recovery(&rk2)).is_err());
        assert_eq!(open_vec(&bytes, &Unlock::Password(PW)).unwrap(), plain);
    }

    #[test]
    fn removing_recovery_requires_authentication() {
        let (ct, sealed) = seal_vec(&data(100), true);
        let (_d, p) = write_temp(&ct);
        let r = remove_recovery(&mut rw(&p), &Unlock::Password("nope"));
        assert!(matches!(r, Err(AppError::WrongPassword)));
        assert_eq!(std::fs::read(&p).unwrap(), ct);
        drop(sealed);
    }
}
