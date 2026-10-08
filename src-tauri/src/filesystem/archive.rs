//! Folder archive: the plaintext layout carried inside an `Archive` container.
//!
//! The archive is *not* a ZIP or tar. It is a minimal length-prefixed stream that only exists
//! inside the encrypted data section, so names, sizes and structure are never visible on disk:
//!
//! ```text
//! "VLKARCH1"                              8-byte magic
//! entry*:   0x01 dir   : u32 path_len, path
//!           0x02 file  : u32 path_len, path, u64 size, <size bytes>
//! 0x00 end             : u64 file_count, u64 dir_count      (cross-checked on extraction)
//! ```
//! Paths are UTF-8, `/`-separated and relative. Integers are little-endian.
//!
//! The writer scans the source first so the exact stream length is known up front (the container
//! uses it to detect a source that changed mid-read). The reader never follows symlinks or
//! junctions. The extractor treats every path as hostile and validates it before touching disk.

use super::names::{validate_component, validate_rel_path, MAX_DEPTH, MAX_REL_PATH_LEN};
use crate::errors::{source_changed_io, AppError, MalformedIo, Result};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

pub const ARCHIVE_MAGIC: &[u8; 8] = b"VLKARCH1";
const TAG_END: u8 = 0;
const TAG_DIR: u8 = 1;
const TAG_FILE: u8 = 2;
const TRAILER_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File { size: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `/`-separated path relative to the scanned root.
    pub rel: String,
    pub abs: PathBuf,
    pub kind: EntryKind,
    pub mtime: Option<SystemTime>,
}

/// Snapshot of a folder at scan time.
#[derive(Debug, Clone)]
pub struct Scan {
    pub entries: Vec<Entry>,
    pub file_count: u64,
    pub dir_count: u64,
    /// Sum of file sizes.
    pub content_bytes: u64,
}

impl Scan {
    /// Exact number of bytes the archive stream will contain.
    pub fn stream_len(&self) -> u64 {
        let mut n = ARCHIVE_MAGIC.len() as u64 + 1 + TRAILER_LEN as u64;
        for e in &self.entries {
            n += 1 + 4 + e.rel.len() as u64;
            if let EntryKind::File { size } = e.kind {
                n += 8 + size;
            }
        }
        n
    }

    /// True if `other` describes exactly the same tree (names, sizes, modification times).
    pub fn same_as(&self, other: &Scan) -> bool {
        self.entries == other.entries
    }
}

fn is_symlink_or_junction(md: &fs::Metadata) -> bool {
    // On Windows std reports both symlinks and junctions (mount points) as symlinks.
    md.file_type().is_symlink()
}

/// Walk `root` and record every entry. Fails on symlinks/junctions and special files rather than
/// silently following them, which could pull in data from outside the chosen folder.
pub fn scan_folder(root: &Path, cancel: &AtomicBool) -> Result<Scan> {
    let md = fs::symlink_metadata(root)?;
    if is_symlink_or_junction(&md) {
        return Err(AppError::UnsafePath(
            "the folder is a symbolic link or junction".into(),
        ));
    }
    if !md.is_dir() {
        return Err(AppError::InvalidInput("not a folder".into()));
    }
    let mut scan = Scan {
        entries: Vec::new(),
        file_count: 0,
        dir_count: 0,
        content_bytes: 0,
    };
    walk(root, "", 0, cancel, &mut scan)?;
    Ok(scan)
}

fn walk(
    dir: &Path,
    rel_prefix: &str,
    depth: usize,
    cancel: &AtomicBool,
    scan: &mut Scan,
) -> Result<()> {
    if depth >= MAX_DEPTH {
        return Err(AppError::UnsafePath("folder nesting is too deep".into()));
    }
    let mut children: Vec<(String, PathBuf)> = Vec::new();
    for item in fs::read_dir(dir)? {
        let item = item?;
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| AppError::InvalidInput("a name is not valid Unicode".into()))?;
        children.push((name, item.path()));
    }
    // Deterministic order makes the archive (and tests) reproducible.
    children.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, path) in children {
        if cancel.load(Ordering::Relaxed) {
            return Err(AppError::Cancelled);
        }
        validate_component(&name)
            .map_err(|_| AppError::UnsafePath(format!("unsupported name in folder: {name}")))?;
        let rel = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };
        if rel.len() > MAX_REL_PATH_LEN {
            return Err(AppError::UnsafePath("path too long".into()));
        }
        let md = fs::symlink_metadata(&path)?;
        if is_symlink_or_junction(&md) {
            return Err(AppError::UnsafePath(format!(
                "symbolic link or junction not supported: {rel}"
            )));
        }
        if md.is_dir() {
            scan.entries.push(Entry {
                rel: rel.clone(),
                abs: path.clone(),
                kind: EntryKind::Dir,
                mtime: md.modified().ok(),
            });
            scan.dir_count += 1;
            walk(&path, &rel, depth + 1, cancel, scan)?;
        } else if md.is_file() {
            scan.entries.push(Entry {
                rel,
                abs: path,
                kind: EntryKind::File { size: md.len() },
                mtime: md.modified().ok(),
            });
            scan.file_count += 1;
            scan.content_bytes += md.len();
        } else {
            return Err(AppError::UnsafePath(format!(
                "unsupported file type: {rel}"
            )));
        }
    }
    Ok(())
}

/// Shared "what are we working on" label, updated as the archive advances.
pub type CurrentItem = Arc<Mutex<String>>;

fn set_current(cur: &CurrentItem, s: &str) {
    if let Ok(mut g) = cur.lock() {
        g.clear();
        g.push_str(s);
    }
}

/// Streams a scanned folder as archive bytes.
pub struct ArchiveReader {
    entries: Vec<Entry>,
    next: usize,
    pending: Vec<u8>,
    pending_pos: usize,
    file: Option<(File, u64)>,
    trailer: Option<[u8; TRAILER_LEN + 1]>,
    current: CurrentItem,
}

impl ArchiveReader {
    pub fn new(scan: &Scan, current: CurrentItem) -> Self {
        let mut trailer = [0u8; TRAILER_LEN + 1];
        trailer[0] = TAG_END;
        trailer[1..9].copy_from_slice(&scan.file_count.to_le_bytes());
        trailer[9..17].copy_from_slice(&scan.dir_count.to_le_bytes());
        Self {
            entries: scan.entries.clone(),
            next: 0,
            pending: ARCHIVE_MAGIC.to_vec(),
            pending_pos: 0,
            file: None,
            trailer: Some(trailer),
            current,
        }
    }

    fn queue_next_entry(&mut self) -> io::Result<bool> {
        if self.next < self.entries.len() {
            let e = &self.entries[self.next];
            self.next += 1;
            set_current(&self.current, &e.rel);
            let mut head = Vec::with_capacity(1 + 4 + e.rel.len() + 8);
            match e.kind {
                EntryKind::Dir => head.push(TAG_DIR),
                EntryKind::File { .. } => head.push(TAG_FILE),
            }
            head.extend_from_slice(&(e.rel.len() as u32).to_le_bytes());
            head.extend_from_slice(e.rel.as_bytes());
            if let EntryKind::File { size } = e.kind {
                let f = File::open(&e.abs)?;
                // A cheap early check; the byte-exact check happens as we stream.
                if f.metadata()?.len() != size {
                    return Err(source_changed_io());
                }
                head.extend_from_slice(&size.to_le_bytes());
                self.file = Some((f, size));
            }
            self.pending = head;
            self.pending_pos = 0;
            return Ok(true);
        }
        if let Some(t) = self.trailer.take() {
            self.pending = t.to_vec();
            self.pending_pos = 0;
            return Ok(true);
        }
        Ok(false)
    }
}

impl Read for ArchiveReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pending_pos < self.pending.len() {
                let n = buf.len().min(self.pending.len() - self.pending_pos);
                buf[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                return Ok(n);
            }
            if let Some((f, remaining)) = self.file.as_mut() {
                if *remaining == 0 {
                    // The file must now be at EOF; extra bytes mean it grew while we read it.
                    let mut probe = [0u8; 1];
                    if f.read(&mut probe)? != 0 {
                        return Err(source_changed_io());
                    }
                    self.file = None;
                    continue;
                }
                let want = buf.len().min(*remaining as usize);
                let n = f.read(&mut buf[..want])?;
                if n == 0 {
                    // Shrank under us.
                    return Err(source_changed_io());
                }
                *remaining -= n as u64;
                return Ok(n);
            }
            if !self.queue_next_entry()? {
                return Ok(0);
            }
        }
    }
}

#[derive(Debug)]
enum State {
    Magic,
    Tag,
    PathLen { tag: u8 },
    Path { tag: u8, len: usize },
    Size { path: String },
    Data { remaining: u64 },
    Trailer,
    Done,
}

fn malformed(why: &'static str) -> io::Error {
    io::Error::other(MalformedIo(why))
}

/// Incrementally rebuilds a folder from archive bytes into an (empty, caller-owned) directory.
/// It is a `Write` sink so it can be fed directly by the streaming decryptor.
pub struct ArchiveExtractor {
    root: PathBuf,
    state: State,
    acc: Vec<u8>,
    file: Option<File>,
    files: u64,
    dirs: u64,
    seen: HashSet<String>,
    current: CurrentItem,
}

impl ArchiveExtractor {
    pub fn new(root: &Path, current: CurrentItem) -> Self {
        Self {
            root: root.to_path_buf(),
            state: State::Magic,
            acc: Vec::new(),
            file: None,
            files: 0,
            dirs: 0,
            seen: HashSet::new(),
            current,
        }
    }

    /// Confirm the archive ended cleanly and its counts matched. Call after the stream completes.
    pub fn finish(self) -> Result<(u64, u64)> {
        match self.state {
            State::Done => Ok((self.files, self.dirs)),
            _ => Err(AppError::Corrupted("archive ended early".into())),
        }
    }

    /// Move bytes from `input` into `acc` until it holds `need` bytes. Returns true when full.
    fn fill(&mut self, input: &mut &[u8], need: usize) -> bool {
        let take = (need - self.acc.len()).min(input.len());
        self.acc.extend_from_slice(&input[..take]);
        *input = &input[take..];
        self.acc.len() == need
    }

    fn target_path(&self, parts: &[&str]) -> PathBuf {
        let mut p = self.root.clone();
        for part in parts {
            p.push(part);
        }
        p
    }

    fn step(&mut self, input: &mut &[u8]) -> io::Result<()> {
        match std::mem::replace(&mut self.state, State::Done) {
            State::Magic => {
                if !self.fill(input, ARCHIVE_MAGIC.len()) {
                    self.state = State::Magic;
                    return Ok(());
                }
                if self.acc != ARCHIVE_MAGIC {
                    return Err(malformed("not a folder archive"));
                }
                self.acc.clear();
                self.state = State::Tag;
            }
            State::Tag => {
                if !self.fill(input, 1) {
                    self.state = State::Tag;
                    return Ok(());
                }
                let tag = self.acc[0];
                self.acc.clear();
                self.state = match tag {
                    TAG_END => State::Trailer,
                    TAG_DIR | TAG_FILE => State::PathLen { tag },
                    _ => return Err(malformed("unknown archive entry")),
                };
            }
            State::PathLen { tag } => {
                if !self.fill(input, 4) {
                    self.state = State::PathLen { tag };
                    return Ok(());
                }
                let len = u32::from_le_bytes([self.acc[0], self.acc[1], self.acc[2], self.acc[3]])
                    as usize;
                self.acc.clear();
                if len == 0 || len > MAX_REL_PATH_LEN {
                    return Err(malformed("archive path length out of range"));
                }
                self.state = State::Path { tag, len };
            }
            State::Path { tag, len } => {
                if !self.fill(input, len) {
                    self.state = State::Path { tag, len };
                    return Ok(());
                }
                let raw = std::mem::take(&mut self.acc);
                let path =
                    String::from_utf8(raw).map_err(|_| malformed("archive path is not UTF-8"))?;
                let parts =
                    validate_rel_path(&path).map_err(|_| malformed("unsafe path in archive"))?;
                // Windows is case-insensitive; "A" and "a" would collide, so treat them as dupes.
                if !self.seen.insert(path.to_lowercase()) {
                    return Err(malformed("duplicate path in archive"));
                }
                set_current(&self.current, &path);
                if tag == TAG_DIR {
                    // Parents are always emitted before children by the writer; creating a
                    // directory whose parent is missing would mean a forged archive.
                    if parts.len() > 1 && !self.target_path(&parts[..parts.len() - 1]).is_dir() {
                        return Err(malformed("folder entry without its parent"));
                    }
                    fs::create_dir(self.target_path(&parts))?;
                    self.dirs += 1;
                    self.state = State::Tag;
                } else {
                    // Parent must have been declared; refuse to invent directories implicitly.
                    if parts.len() > 1 && !self.target_path(&parts[..parts.len() - 1]).is_dir() {
                        return Err(malformed("file entry without its folder"));
                    }
                    self.state = State::Size { path };
                }
            }
            State::Size { path } => {
                if !self.fill(input, 8) {
                    self.state = State::Size { path };
                    return Ok(());
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.acc);
                self.acc.clear();
                let size = u64::from_le_bytes(b);
                let parts: Vec<&str> = path.split('/').collect();
                // create_new: never overwrite or follow anything that already exists.
                let f = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(self.target_path(&parts))?;
                self.files += 1;
                if size == 0 {
                    drop(f);
                    self.state = State::Tag;
                } else {
                    self.file = Some(f);
                    self.state = State::Data { remaining: size };
                }
            }
            State::Data { remaining } => {
                let take = (remaining.min(input.len() as u64)) as usize;
                let f = self
                    .file
                    .as_mut()
                    .ok_or_else(|| malformed("archive state error"))?;
                f.write_all(&input[..take])?;
                *input = &input[take..];
                let left = remaining - take as u64;
                if left == 0 {
                    if let Some(f) = self.file.take() {
                        f.sync_all()?;
                    }
                    self.state = State::Tag;
                } else {
                    self.state = State::Data { remaining: left };
                }
            }
            State::Trailer => {
                if !self.fill(input, TRAILER_LEN) {
                    self.state = State::Trailer;
                    return Ok(());
                }
                let mut f = [0u8; 8];
                let mut d = [0u8; 8];
                f.copy_from_slice(&self.acc[..8]);
                d.copy_from_slice(&self.acc[8..]);
                self.acc.clear();
                if u64::from_le_bytes(f) != self.files || u64::from_le_bytes(d) != self.dirs {
                    return Err(malformed("archive entry counts do not match"));
                }
                self.state = State::Done;
            }
            State::Done => {
                return Err(malformed("unexpected data after end of archive"));
            }
        }
        Ok(())
    }
}

impl Write for ArchiveExtractor {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut input = buf;
        while !input.is_empty() {
            self.step(&mut input)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn cur() -> CurrentItem {
        Arc::new(Mutex::new(String::new()))
    }

    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    fn make_tree(root: &Path) {
        fs::create_dir_all(root.join("sub/deeper")).unwrap();
        fs::create_dir_all(root.join("ملفات")).unwrap();
        fs::write(root.join("a.txt"), b"hello").unwrap();
        fs::write(root.join("empty.bin"), b"").unwrap();
        fs::write(
            root.join("sub/b.bin"),
            (0..=255u8).cycle().take(100_000).collect::<Vec<_>>(),
        )
        .unwrap();
        fs::write(root.join("sub/deeper/c d.txt"), "نص عربي").unwrap();
        fs::write(root.join("ملفات/صورة.png"), [1, 2, 3]).unwrap();
    }

    fn archive_bytes(scan: &Scan) -> Vec<u8> {
        let mut r = ArchiveReader::new(scan, cur());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        out
    }

    fn assert_same_tree(a: &Path, b: &Path) {
        let sa = scan_folder(a, &no_cancel()).unwrap();
        let sb = scan_folder(b, &no_cancel()).unwrap();
        assert_eq!(sa.entries.len(), sb.entries.len());
        for (x, y) in sa.entries.iter().zip(&sb.entries) {
            assert_eq!(x.rel, y.rel);
            assert_eq!(x.kind, y.kind);
            if matches!(x.kind, EntryKind::File { .. }) {
                assert_eq!(
                    fs::read(&x.abs).unwrap(),
                    fs::read(&y.abs).unwrap(),
                    "{}",
                    x.rel
                );
            }
        }
    }

    #[test]
    fn stream_len_is_exact_and_roundtrip_matches() {
        let src = tempfile::tempdir().unwrap();
        make_tree(src.path());
        let scan = scan_folder(src.path(), &no_cancel()).unwrap();
        assert_eq!(scan.file_count, 5);
        assert_eq!(scan.dir_count, 3);
        let bytes = archive_bytes(&scan);
        assert_eq!(bytes.len() as u64, scan.stream_len());

        let out = tempfile::tempdir().unwrap();
        let mut ex = ArchiveExtractor::new(out.path(), cur());
        ex.write_all(&bytes).unwrap();
        assert_eq!(ex.finish().unwrap(), (5, 3));
        assert_same_tree(src.path(), out.path());
    }

    #[test]
    fn extractor_handles_one_byte_writes() {
        let src = tempfile::tempdir().unwrap();
        make_tree(src.path());
        let scan = scan_folder(src.path(), &no_cancel()).unwrap();
        let bytes = archive_bytes(&scan);
        let out = tempfile::tempdir().unwrap();
        let mut ex = ArchiveExtractor::new(out.path(), cur());
        for chunk in bytes.chunks(1) {
            ex.write_all(chunk).unwrap();
        }
        ex.finish().unwrap();
        assert_same_tree(src.path(), out.path());
    }

    #[test]
    fn empty_folder_roundtrips() {
        let src = tempfile::tempdir().unwrap();
        let scan = scan_folder(src.path(), &no_cancel()).unwrap();
        let bytes = archive_bytes(&scan);
        let out = tempfile::tempdir().unwrap();
        let mut ex = ArchiveExtractor::new(out.path(), cur());
        ex.write_all(&bytes).unwrap();
        assert_eq!(ex.finish().unwrap(), (0, 0));
    }

    fn entry(tag: u8, path: &str, size: Option<(u64, &[u8])>) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend_from_slice(&(path.len() as u32).to_le_bytes());
        v.extend_from_slice(path.as_bytes());
        if let Some((n, data)) = size {
            v.extend_from_slice(&n.to_le_bytes());
            v.extend_from_slice(data);
        }
        v
    }

    fn trailer(f: u64, d: u64) -> Vec<u8> {
        let mut v = vec![TAG_END];
        v.extend_from_slice(&f.to_le_bytes());
        v.extend_from_slice(&d.to_le_bytes());
        v
    }

    fn extract(bytes: &[u8]) -> (tempfile::TempDir, io::Result<()>) {
        let out = tempfile::tempdir().unwrap();
        let mut ex = ArchiveExtractor::new(out.path(), cur());
        let r = ex.write_all(bytes).and_then(|_| {
            ex.finish()
                .map(|_| ())
                .map_err(|e| io::Error::other(e.to_string()))
        });
        (out, r)
    }

    #[test]
    fn hostile_paths_are_rejected_and_write_nothing_outside() {
        for bad in [
            "../evil.txt",
            "a/../../evil.txt",
            "/abs.txt",
            "C:/evil.txt",
            "a\\b",
            "CON",
            "x/NUL.txt",
        ] {
            let mut a = ARCHIVE_MAGIC.to_vec();
            a.extend(entry(TAG_FILE, bad, Some((1, b"x"))));
            a.extend(trailer(1, 0));
            let (out, r) = extract(&a);
            assert!(r.is_err(), "{bad:?} must be rejected");
            let leftover: Vec<_> = fs::read_dir(out.path()).unwrap().collect();
            assert!(leftover.is_empty(), "{bad:?} created {leftover:?}");
            let parent = out.path().parent().unwrap();
            assert!(!parent.join("evil.txt").exists());
        }
    }

    #[test]
    fn duplicates_missing_parent_bad_counts_and_trailing_data_are_rejected() {
        let mut a = ARCHIVE_MAGIC.to_vec();
        a.extend(entry(TAG_FILE, "a.txt", Some((1, b"x"))));
        a.extend(entry(TAG_FILE, "A.TXT", Some((1, b"y"))));
        a.extend(trailer(2, 0));
        assert!(extract(&a).1.is_err(), "case-insensitive duplicate");

        let mut a = ARCHIVE_MAGIC.to_vec();
        a.extend(entry(TAG_FILE, "nodir/a.txt", Some((1, b"x"))));
        a.extend(trailer(1, 0));
        assert!(extract(&a).1.is_err(), "undeclared parent");

        let mut a = ARCHIVE_MAGIC.to_vec();
        a.extend(entry(TAG_DIR, "x/y", None));
        a.extend(trailer(0, 1));
        assert!(extract(&a).1.is_err(), "dir without parent");

        let mut a = ARCHIVE_MAGIC.to_vec();
        a.extend(entry(TAG_FILE, "a.txt", Some((1, b"x"))));
        a.extend(trailer(5, 0));
        assert!(extract(&a).1.is_err(), "wrong counts");

        let mut a = ARCHIVE_MAGIC.to_vec();
        a.extend(trailer(0, 0));
        a.push(0xFF);
        assert!(extract(&a).1.is_err(), "trailing data");

        let mut a = ARCHIVE_MAGIC.to_vec();
        a.extend(entry(TAG_FILE, "a.txt", Some((10, b"short"))));
        assert!(extract(&a).1.is_err(), "truncated archive");

        assert!(extract(b"NOTARCH!").1.is_err(), "bad magic");

        let mut a = ARCHIVE_MAGIC.to_vec();
        a.push(TAG_FILE);
        a.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(extract(&a).1.is_err(), "huge path length");
    }

    #[test]
    fn reader_detects_file_changes() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("a.txt"), b"hello").unwrap();
        let scan = scan_folder(src.path(), &no_cancel()).unwrap();

        fs::write(src.path().join("a.txt"), b"hello world").unwrap();
        let mut r = ArchiveReader::new(&scan, cur());
        let mut out = Vec::new();
        let e = r.read_to_end(&mut out).unwrap_err();
        assert!(matches!(AppError::from(e), AppError::SourceChanged));

        fs::write(src.path().join("a.txt"), b"hi").unwrap();
        let mut r = ArchiveReader::new(&scan, cur());
        let e = r.read_to_end(&mut out).unwrap_err();
        assert!(matches!(AppError::from(e), AppError::SourceChanged));
    }

    #[test]
    fn scan_comparison_notices_modification() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("a.txt"), b"hello").unwrap();
        let s1 = scan_folder(src.path(), &no_cancel()).unwrap();
        assert!(s1.same_as(&scan_folder(src.path(), &no_cancel()).unwrap()));
        fs::write(src.path().join("b.txt"), b"new").unwrap();
        assert!(!s1.same_as(&scan_folder(src.path(), &no_cancel()).unwrap()));
    }

    #[test]
    fn scan_honours_cancel() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("a.txt"), b"x").unwrap();
        let c = AtomicBool::new(true);
        assert!(matches!(
            scan_folder(src.path(), &c),
            Err(AppError::Cancelled)
        ));
    }

    #[test]
    fn scan_rejects_too_deep_trees() {
        let src = tempfile::tempdir().unwrap();
        let mut p = src.path().to_path_buf();
        for _ in 0..(MAX_DEPTH + 1) {
            p.push("d");
        }
        fs::create_dir_all(&p).unwrap();
        assert!(matches!(
            scan_folder(src.path(), &no_cancel()),
            Err(AppError::UnsafePath(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn scan_rejects_symlinks_when_creatable() {
        let src = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("secret.txt"), b"outside").unwrap();
        // Creating symlinks needs developer mode / privileges; skip when unavailable.
        if std::os::windows::fs::symlink_dir(target.path(), src.path().join("link")).is_ok() {
            assert!(matches!(
                scan_folder(src.path(), &no_cancel()),
                Err(AppError::UnsafePath(_))
            ));
        }
    }
}
