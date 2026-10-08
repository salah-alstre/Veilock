//! Chunked streaming AEAD (STREAM construction over AES-256-GCM).
//!
//! The plaintext is cut into `chunk_size` pieces; each is sealed independently so memory use is
//! one chunk regardless of file size (a 20 GB file needs ~2 MiB of buffers).
//!
//! * Nonce  = `nonce_prefix (8 random bytes per file) || chunk_index (u32 LE)`. Unique per chunk
//!   within a file; the per-file key (DEK) is itself unique per file, so a nonce never repeats
//!   under one key.
//! * AAD    = `SHA-256(core header) || chunk_index (u64 LE) || final_flag (1 byte)`.
//!   Binds each chunk to this file, to its position, and to "am I the last chunk". That defeats
//!   reordering, duplication, cross-file splicing, truncation at a chunk boundary, and appending.
//!
//! Chunks have no framing on disk: every chunk except the last is exactly `chunk_size + 16`
//! bytes. The last is detected by one-byte look-ahead, so no attacker-controlled length field is
//! ever consulted. An empty input is one final chunk with an empty plaintext, so "no chunks at
//! all" can only mean truncation.

use super::header::CoreHeader;
use super::kdf::Key32;
use super::params::*;
use crate::errors::{AppError, Result};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

/// Receives cumulative plaintext bytes processed; returning `Err` (e.g. `Cancelled`) aborts.
pub type Progress<'a> = &'a mut dyn FnMut(u64) -> Result<()>;

fn nonce_for(prefix: &[u8; NONCE_PREFIX_LEN], index: u64) -> Result<[u8; NONCE_LEN]> {
    // A u32 counter allows 2^32 chunks (4 PiB at 1 MiB). Refuse rather than wrap: wrapping would
    // reuse a nonce, which is catastrophic for GCM.
    let counter = u32::try_from(index)
        .map_err(|_| AppError::InvalidInput("input too large for this container format".into()))?;
    let mut n = [0u8; NONCE_LEN];
    n[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_le_bytes());
    Ok(n)
}

fn chunk_aad(core_hash: &[u8; 32], index: u64, is_final: bool) -> [u8; 41] {
    let mut a = [0u8; 41];
    a[..32].copy_from_slice(core_hash);
    a[32..40].copy_from_slice(&index.to_le_bytes());
    a[40] = u8::from(is_final);
    a
}

/// Fill `buf` as far as the reader allows; returns bytes read (< len only at EOF).
pub fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Encrypt everything from `src` into `dst`. Returns plaintext bytes consumed.
pub fn encrypt_stream<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    header: &CoreHeader,
    data_key: &Key32,
    progress: Progress<'_>,
) -> Result<u64> {
    let cs = header.chunk_size as usize;
    let cipher = Aes256Gcm::new_from_slice(&**data_key)
        .map_err(|_| AppError::Internal("data key length".into()))?;
    let core_hash = CoreHeader::hash(&header.to_bytes());

    // Capacity includes room for the tag so `encrypt_in_place` never reallocates (a realloc
    // would leave an un-zeroed copy of plaintext behind).
    let mut work: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(cs + TAG_LEN));
    work.resize(cs, 0);
    let mut n = read_full(src, &mut work[..cs])?;
    let mut index: u64 = 0;
    let mut total: u64 = 0;

    loop {
        let mut carry: Option<u8> = None;
        if n == cs {
            let mut peek = [0u8; 1];
            if read_full(src, &mut peek)? == 1 {
                carry = Some(peek[0]);
            }
        }
        let is_final = carry.is_none();

        work.truncate(n);
        let nonce = nonce_for(&header.nonce_prefix, index)?;
        cipher
            .encrypt_in_place(
                Nonce::from_slice(&nonce),
                &chunk_aad(&core_hash, index, is_final),
                &mut *work,
            )
            .map_err(|_| AppError::Internal("chunk encryption failed".into()))?;
        dst.write_all(&work)?;

        total += n as u64;
        progress(total)?;
        if is_final {
            return Ok(total);
        }

        work.clear();
        work.resize(cs, 0);
        work[0] = carry.unwrap_or(0);
        n = 1 + read_full(src, &mut work[1..cs])?;
        index += 1;
    }
}

/// Decrypt and authenticate every chunk. Plaintext is handed to `dst` chunk by chunk *after*
/// that chunk authenticated, but the stream as a whole is only trustworthy once this returns
/// `Ok` (the final-flag check catches truncation). Callers therefore write to a temp file and
/// publish it only on success.
pub fn decrypt_stream<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    header: &CoreHeader,
    data_key: &Key32,
    progress: Progress<'_>,
) -> Result<u64> {
    let cs = header.chunk_size as usize;
    let full_ct = cs + TAG_LEN;
    let cipher = Aes256Gcm::new_from_slice(&**data_key)
        .map_err(|_| AppError::Internal("data key length".into()))?;
    let core_hash = CoreHeader::hash(&header.to_bytes());

    let mut work: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(full_ct));
    work.resize(full_ct, 0);
    let mut n = read_full(src, &mut work[..full_ct])?;
    let mut index: u64 = 0;
    let mut total: u64 = 0;

    loop {
        if n < TAG_LEN {
            // Either no data section at all or a chunk cut off inside its tag.
            return Err(AppError::Corrupted("file is truncated".into()));
        }
        let mut carry: Option<u8> = None;
        if n == full_ct {
            let mut peek = [0u8; 1];
            if read_full(src, &mut peek)? == 1 {
                carry = Some(peek[0]);
            }
        }
        let is_final = carry.is_none();

        work.truncate(n);
        let nonce = nonce_for(&header.nonce_prefix, index)?;
        cipher
            .decrypt_in_place(
                Nonce::from_slice(&nonce),
                &chunk_aad(&core_hash, index, is_final),
                &mut *work,
            )
            .map_err(|_| AppError::Corrupted("data failed authentication".into()))?;
        dst.write_all(&work)?;

        total += work.len() as u64;
        progress(total)?;
        if is_final {
            return Ok(total);
        }

        work.clear();
        work.resize(full_ct, 0);
        work[0] = carry.unwrap_or(0);
        n = 1 + read_full(src, &mut work[1..full_ct])?;
        index += 1;
    }
}

/// Reader adapter that hashes and counts everything read through it. Used to record the SHA-256
/// of the plaintext *as it was encrypted*, so verification can compare against it without
/// re-reading (or trusting) a source file that might have changed.
pub struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    count: u64,
}

impl<R: Read> HashingReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            count: 0,
        }
    }
    pub fn finish(self) -> ([u8; 32], u64) {
        (self.hasher.finalize().into(), self.count)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
}

/// Writer that discards data but hashes and counts it (verification sink).
pub struct HashingSink {
    hasher: Sha256,
    count: u64,
}

impl HashingSink {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            count: 0,
        }
    }
    pub fn finish(self) -> ([u8; 32], u64) {
        (self.hasher.finalize().into(), self.count)
    }
}

impl Default for HashingSink {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for HashingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        self.count += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    const CS: u32 = MIN_CHUNK_SIZE;

    fn header() -> CoreHeader {
        CoreHeader {
            version: FORMAT_VERSION,
            kind: ContainerKind::File,
            cipher: CipherId::Aes256Gcm,
            chunk_size: CS,
            file_id: [4; 16],
            nonce_prefix: [6; 8],
        }
    }

    fn key() -> Key32 {
        Zeroizing::new([0x42u8; 32])
    }

    fn data(len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        rand::rngs::OsRng.fill_bytes(&mut v);
        v
    }

    fn enc(pt: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let n = encrypt_stream(&mut &pt[..], &mut out, &header(), &key(), &mut |_| Ok(())).unwrap();
        assert_eq!(n as usize, pt.len());
        out
    }

    fn dec(ct: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        decrypt_stream(&mut &ct[..], &mut out, &header(), &key(), &mut |_| Ok(()))?;
        Ok(out)
    }

    #[test]
    fn roundtrip_at_every_boundary() {
        let cs = CS as usize;
        for len in [
            0,
            1,
            15,
            16,
            cs - 1,
            cs,
            cs + 1,
            2 * cs - 1,
            2 * cs,
            2 * cs + 1,
            5 * cs + 123,
        ] {
            let pt = data(len);
            let ct = enc(&pt);
            assert_eq!(dec(&ct).unwrap(), pt, "len {len}");
        }
    }

    #[test]
    fn ciphertext_size_is_predictable() {
        let cs = CS as usize;
        assert_eq!(enc(&[]).len(), TAG_LEN);
        assert_eq!(enc(&data(cs)).len(), cs + TAG_LEN);
        assert_eq!(enc(&data(cs + 1)).len(), cs + 1 + 2 * TAG_LEN);
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let pt = b"known plaintext marker 0123456789".repeat(300);
        let ct = enc(&pt);
        assert!(!ct.windows(24).any(|w| w == &pt[..24]));
    }

    #[test]
    fn any_single_bit_flip_is_detected() {
        let cs = CS as usize;
        let ct = enc(&data(cs * 2 + 10));
        for pos in [0, 1, cs / 2, cs + TAG_LEN, ct.len() - 1] {
            let mut bad = ct.clone();
            bad[pos] ^= 0x01;
            assert!(dec(&bad).is_err(), "flip at {pos} undetected");
        }
    }

    #[test]
    fn truncation_at_chunk_boundary_is_detected() {
        let cs = CS as usize;
        let ct = enc(&data(cs * 3));
        let full_chunk = cs + TAG_LEN;
        assert!(dec(&ct[..full_chunk]).is_err());
        assert!(dec(&ct[..2 * full_chunk]).is_err());
        assert!(dec(&ct[..ct.len() - 1]).is_err());
        assert!(dec(&[]).is_err());
        assert!(dec(&ct[..5]).is_err());
    }

    #[test]
    fn appended_data_is_detected() {
        let cs = CS as usize;
        let mut ct = enc(&data(cs));
        ct.push(0);
        assert!(dec(&ct).is_err());
        let mut ct = enc(&data(10));
        ct.extend_from_slice(&[0u8; 40]);
        assert!(dec(&ct).is_err());
    }

    #[test]
    fn reordered_chunks_are_detected() {
        let cs = CS as usize;
        let ct = enc(&data(cs * 3 + 5));
        let f = cs + TAG_LEN;
        let mut swapped = Vec::new();
        swapped.extend_from_slice(&ct[f..2 * f]);
        swapped.extend_from_slice(&ct[..f]);
        swapped.extend_from_slice(&ct[2 * f..]);
        assert!(dec(&swapped).is_err());
    }

    #[test]
    fn chunks_cannot_be_spliced_between_files() {
        let cs = CS as usize;
        let a = enc(&data(cs * 2));
        let mut h2 = header();
        h2.file_id = [5; 16];
        let mut b = Vec::new();
        encrypt_stream(&mut &data(cs * 2)[..], &mut b, &h2, &key(), &mut |_| Ok(())).unwrap();
        let f = cs + TAG_LEN;
        let mut mixed = a[..f].to_vec();
        mixed.extend_from_slice(&b[f..]);
        assert!(dec(&mixed).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let ct = enc(&data(100));
        let mut out = Vec::new();
        let other: Key32 = Zeroizing::new([0x43u8; 32]);
        assert!(
            decrypt_stream(&mut &ct[..], &mut out, &header(), &other, &mut |_| Ok(())).is_err()
        );
    }

    #[test]
    fn cancellation_stops_promptly() {
        let cs = CS as usize;
        let pt = data(cs * 10);
        let mut out = Vec::new();
        let mut calls = 0;
        let r = encrypt_stream(&mut &pt[..], &mut out, &header(), &key(), &mut |_| {
            calls += 1;
            if calls == 2 {
                Err(AppError::Cancelled)
            } else {
                Ok(())
            }
        });
        assert!(matches!(r, Err(AppError::Cancelled)));
        assert_eq!(calls, 2);
    }

    #[test]
    fn progress_is_monotonic_and_ends_at_total() {
        let cs = CS as usize;
        let pt = data(cs * 3 + 7);
        let mut seen = Vec::new();
        let mut out = Vec::new();
        encrypt_stream(&mut &pt[..], &mut out, &header(), &key(), &mut |b| {
            seen.push(b);
            Ok(())
        })
        .unwrap();
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(*seen.last().unwrap(), pt.len() as u64);
    }

    #[test]
    fn nonce_counter_overflow_is_refused() {
        assert!(nonce_for(&[0; 8], u64::from(u32::MAX)).is_ok());
        assert!(nonce_for(&[0; 8], u64::from(u32::MAX) + 1).is_err());
    }
}
