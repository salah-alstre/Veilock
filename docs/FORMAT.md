# Veilock container format, version 1

This document specifies the on-disk formats written by Veilock. All integers are little-endian.
The reference implementation is `src-tauri/src/crypto/` (container, header, keyslot, stream,
metadata) and `src-tauri/src/vault/` (credential store, file vaults).

## 1. `.veil` container

```text
offset      size   field
0           48     core header (clear text)
48          432    key-slot region: 4 records x 108 bytes
480         4      metadata ciphertext length (u32)
484         12     metadata nonce
496         n      metadata ciphertext (AES-256-GCM, includes the 16-byte tag)
496+n       ...    data chunks
```

### 1.1 Core header (48 bytes)

| Bytes   | Field                                                                 |
|---------|-----------------------------------------------------------------------|
| 0..8    | magic `89 56 45 49 4C 0D 0A 1A` (`\x89VEIL\r\n\x1a`)                   |
| 8..10   | format version (`1`)                                                  |
| 10      | container kind: `1` file, `2` archive (folder)                        |
| 11      | cipher id: `1` = AES-256-GCM                                          |
| 12..16  | chunk size in plaintext bytes (default 1 MiB, 4 KiB to 16 MiB)        |
| 16..32  | file id (random, per file)                                            |
| 32..40  | nonce prefix (random, per file)                                       |
| 40..48  | flags and reserved, must be zero                                      |

The SHA-256 of these 48 bytes (`core_hash`) is part of the associated data of every key-slot
wrap, the metadata block and every data chunk. Changing any header bit therefore makes
authentication fail everywhere, even though the header is stored in the clear.

A reader checks the magic first (so a foreign file is reported as "not a Veilock file"), then the
version (a newer file is reported as unsupported, not corrupted), then the rest.

### 1.2 Key hierarchy

* A random 256-bit **data-encryption key (DEK)** is generated per file.
* `meta_key = HKDF-SHA256(ikm = DEK, salt = file_id, info = "veilock/meta")`
* `data_key = HKDF-SHA256(ikm = DEK, salt = file_id, info = "veilock/data")`
* The DEK is stored only wrapped inside key slots (below). It is never written in clear.

Changing the password rewrites only the slot region (432 bytes). The data section is not touched.

### 1.3 Key slots (4 x 108 bytes)

Order: `[password primary][password shadow][recovery primary][recovery shadow]`.

```text
0       state        0 empty, 1 in use
1       slot kind    1 password, 2 recovery
2       kdf id       0 none, 1 argon2id
3       reserved     0
4..8    m_cost (KiB) Argon2id memory, 0 for kdf none
8..12   t_cost       Argon2id passes
12..16  p_cost       Argon2id lanes
16..32  salt
32..44  wrap nonce
44..92  wrapped DEK  (32-byte ciphertext + 16-byte tag)
92..108 checksum     SHA-256(record[0..92])[..16]
```

* **Password slot:** `KEK = Argon2id(NFKC(password) as UTF-8, salt, m, t, p)` with output length
  32. Default parameters: **m = 64 MiB, t = 3, p = 4**. The parameters are stored per slot, so they
  can be raised later without breaking existing files. A reader rejects parameters outside a sane
  range before allocating memory (hostile-file protection).
* **Recovery slot:** `KEK = HKDF-SHA256(ikm = recovery_key, salt = slot salt, info =
  "veilock/recovery-kek")`. The recovery key is 256 random bits, so no password stretching is used.
* **Wrap:** `AES-256-GCM(KEK, wrap nonce, DEK, AAD = core_hash || slot_kind)`. The AAD stops a
  slot being moved to another file or being re-labelled.
* **Shadow copy:** a slot is always written shadow first (fsync), then primary (fsync), so a
  power failure during a password change cannot leave the file without a complete slot. The
  checksum only detects torn writes and bit rot; authenticity comes from the AEAD wrap.
* Passwords are normalised with Unicode NFKC before use, so the same visible password typed on a
  different keyboard or input method derives the same key. This is part of the format.

### 1.4 Metadata block

`AES-256-GCM(meta_key, nonce, JSON, AAD = core_hash || "meta")`. The JSON holds the original
name, kind (`file` or `folder`), original size, creation time, and file and folder counts. The
original file name is therefore **not** visible on disk. The ciphertext length is range-checked
(max 1 MiB) before any allocation and nothing is parsed before the tag verifies.

### 1.5 Data section (chunked AEAD)

The plaintext is cut into `chunk_size` pieces. Each piece is sealed with AES-256-GCM:

* nonce = `nonce_prefix (8) || chunk_index (u32)`
* AAD = `core_hash || chunk_index (u64) || final_flag (1 byte)`
* every chunk except the last is exactly `chunk_size + 16` bytes; there is no per-chunk length
  field. The last chunk is detected by one-byte look-ahead and carries `final_flag = 1`.
* an empty input is one final chunk with empty plaintext, so "zero chunks" can only mean
  truncation.

This detects reordering, duplication, splicing between files, truncation (including at a chunk
boundary) and appended data. Memory use is one chunk regardless of file size. The encoder refuses
inputs above 2^32 chunks instead of wrapping the counter.

### 1.6 Folder payload (`kind = 2`)

The plaintext of an archive container is a small length-prefixed stream (not ZIP or tar):

```text
"VLKARCH1"
entry*  :  0x01 dir  : u32 path_len, path
           0x02 file : u32 path_len, path, u64 size, <size bytes>
0x00 end:  u64 file_count, u64 dir_count      (cross-checked on extraction)
```

Paths are UTF-8, `/`-separated, relative. The extractor treats every path as hostile (no `..`,
absolute paths, drive prefixes, reserved Windows names, or over-long paths) and never follows
symlinks or junctions.

## 2. Credential store `vault/credentials.vlkc`

```text
"VLKCRED1" (8) | version u16 | m_cost u32 | t_cost u32 | p_cost u32 |
salt (16) | nonce (12) | ct_len u32 | ciphertext (ct_len, includes the GCM tag)
```

Key = `Argon2id(NFKC(master password), salt, params)`, used directly as an AES-256-GCM key. The whole
header is the AEAD associated data. A fresh nonce is used on every save and the file is replaced
atomically (write temp, fsync, rename). The plaintext is a JSON document containing the saved
passwords and the optional Default Encryption Password. The Master Password itself is not stored;
a wrong password and a tampered file both fail the AEAD check and are reported identically.

## 3. File vaults `vault/vaults/<id>/`

| File               | Content                                                                          |
|--------------------|----------------------------------------------------------------------------------|
| `vault.key`        | a `.veil` file container whose plaintext is a random 32-byte vault secret S      |
| `index.enc`        | `VLKVIDX1` encrypted item list                                                   |
| `items/<id>.veil`  | one ordinary `.veil` container per stored file or folder                         |

* S is protected by the vault password slot and, optionally, a recovery slot.
* `index_key = HKDF(S, info = "veilock/vault-index")`; `item_key = hex(HKDF(S, salt = item id,
  info = "veilock/vault-item"))`, used as the "password" of the item's own container.
* `index.enc`: `"VLKVIDX1" | version u16 | nonce (12) | ct_len u32 | ct`, AES-256-GCM, AAD =
  magic and version (the vault id is deliberately excluded so an imported vault still opens).
* Adding an item is crash-safe: a `pending` index entry is written first, then the container, then
  the entry is finalized. On the next unlock a pending entry is finalized if its container
  authenticates, otherwise dropped.
* Export bundle `.veilvault`: `"VLKVBND1" | meta_len u32 | meta JSON | VLKARCH1 archive of the vault
  directory`. Only the vault name, icon, description and creation date are in clear. Import extracts
  into a staging directory, validates strictly, then moves into place.

## 4. Compatibility

* Version 1 readers reject `version > 1` with an "unsupported version" error instead of guessing.
* KDF parameters live in each slot, so strengthening them in a later release does not require a
  format bump or a migration of old files.
* Any change to the header, key-slot layout, normalisation or AAD construction requires a new
  format version and a migration path.
