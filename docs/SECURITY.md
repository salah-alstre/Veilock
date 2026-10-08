# Veilock security model

Veilock is a local-first Windows application. It makes no network requests, has no accounts, no
telemetry and no cloud component. Everything below describes what the code does today; where
something is *not* guaranteed, that is stated explicitly.

## 1. Cryptography

| Purpose                     | Primitive                                                    |
|-----------------------------|--------------------------------------------------------------|
| File and folder encryption  | AES-256-GCM, chunked (STREAM-style), 1 MiB chunks            |
| Password to key             | Argon2id, default 64 MiB / 3 passes / 4 lanes, 16-byte salt  |
| Key separation              | HKDF-SHA256 with distinct `info` labels                      |
| Randomness                  | OS CSPRNG (`OsRng`)                                          |
| Secret comparison           | constant time (`subtle`)                                     |
| Secret memory               | `zeroize` / `Zeroizing` buffers, wiped on drop               |

All cryptography runs in Rust (`src-tauri/src/crypto/`). The JavaScript UI never sees a key, and
never performs encryption, hashing or key derivation. Passwords cross the IPC boundary once, as
typed input, and are dropped after use.

Design properties (each is covered by tests in `cargo test`):

* **Per-file random DEK.** Every file gets its own 256-bit key. The password only wraps it, so a
  password change rewrites 432 bytes of key slots and never the data.
* **Authenticated header.** The hash of the clear header is bound into every AEAD operation.
* **Truncation, reordering, splicing and appending are detected**, including at chunk boundaries.
* **Wrong password and corruption are distinct outcomes** where it is safe to distinguish them:
  a failed key-slot unwrap is `WRONG_PASSWORD`; a failed chunk or metadata tag after a correct
  password is `CORRUPTED`. Neither ever produces partial plaintext output.
* **Hostile-file hardening.** Lengths and Argon2 parameters read from a file are range-checked
  before any allocation; foreign files are reported as "not a Veilock file".
* **Unique nonces.** Per-file DEK, per-file random 64-bit nonce prefix, 32-bit chunk counter; the
  encoder refuses rather than wraps the counter.
* **Unicode-stable passwords.** NFKC normalisation, so Arabic and accented passwords are
  keyboard independent.

The container layout is specified in [FORMAT.md](FORMAT.md).

## 2. Where secrets live

| Secret                         | At rest                                                              |
|--------------------------------|----------------------------------------------------------------------|
| Master Password                | **Never stored.** Only used to derive the key of `credentials.vlkc`. |
| Saved passwords                | Inside `credentials.vlkc`, AES-256-GCM under the Master-Password key |
| Default Encryption Password    | Inside `credentials.vlkc` only                                       |
| Vault passwords                | Never stored; they wrap the vault secret in `vault.key`              |
| Recovery keys                  | **Never stored by the app.** Shown once at creation                  |
| DEKs and derived keys          | Memory only, zeroized after use                                      |

Not in `settings.json`, `localStorage`, `sessionStorage`, SQLite, logs or crash output. The SQLite
metadata database holds item names, paths, sizes, favourite flags and the activity log, none of
which is secret key material; users who consider file names sensitive can turn the activity log
off or clear it in Settings > Data & Privacy.

The release builds have `panic = abort` and symbol stripping, and the application writes no log
files containing secrets.

## 3. Recovery

* **Master Password: not recoverable.** There is no reset, backdoor, escrow or hint. If it is
  forgotten, the saved passwords and the Default Encryption Password inside the credential store
  are permanently inaccessible. The files themselves remain decryptable with their own passwords or
  recovery keys.
* **Per-file / per-vault recovery key (optional).** A 256-bit random key, displayed once as 55
  base32 characters in groups of five with a 2-byte typo check. It occupies a separate key slot
  that wraps the same DEK. The app does not keep a copy: whoever holds the key can open the file,
  and losing both password and key loses the data. Store it offline.

## 4. Data-safety guarantees

* The source file is never modified or removed before the encrypted output has been written,
  flushed and **verified** by decrypting it again through the real authenticated path.
* "Remove original after encrypting" deletes the source only after that verification succeeds.
  Cancelling at any point leaves the source untouched and removes the partial output.
* Output goes to a temporary file in the destination folder and is moved into place without
  overwriting. Existing destinations follow an explicit **Fail / Keep both / Replace** policy.
* Folder extraction validates every stored path (no `..`, absolute or drive paths, reserved
  names, over-long paths), never follows symlinks or junctions, and cross-checks entry counts.
* Credential store, settings and vault index writes are atomic (temp file, fsync, rename).
* Uninstalling removes only the application, its own registry values and context-menu entries. It
  never deletes `.veil` files or user data.

## 5. Application hardening

* Tauri 2 with a strict CSP: `default-src 'self'`, no remote scripts, styles, fonts or frames;
  `connect-src` limited to the local IPC channel.
* Only an explicit list of commands is exposed to the webview, with typed, validated arguments
  (operation ids must be alphanumeric, paths and enums are validated in Rust).
* Single-instance enforcement; opening a `.veil` file from Explorer routes to the running
  instance's unlock flow.
* **Lock states** (`locked`, `unlocking`, `unlocked`, `locking`) are owned by Rust. A compromised
  UI can delay an auto-lock by reporting activity, but cannot undo a lock that Rust has performed.
* **Panic Lock** (default `Ctrl+Shift+L`, configurable) is a global shortcut handled in Rust. It
  zeroizes the in-memory credential store and vault keys, locks every file vault and shows the lock
  screen.
* **Auto-lock** on inactivity, on minimise/background, on Windows session lock and on sleep, each
  configurable.
* **Clipboard.** Copied passwords are cleared after 10 / 30 / 60 seconds (or never), and only if
  the clipboard still contains the value the app placed there.
* **Global search** reads only metadata of unlocked content; locked vault contents are never
  included.
* Windows integration is per-user (HKCU) and optional: file association, Start with Windows and
  Explorer context-menu verbs, all removable from Settings or by uninstalling.

## 6. Threat model

**Protects against**

* Someone who obtains the encrypted files (stolen disk, backup, cloud copy, USB drive) but not the
  password: AES-256-GCM with Argon2id-stretched keys; offline guessing is slowed by 64 MiB of
  memory per guess.
* Modification of encrypted files: any change is detected and nothing is released.
* Casual access to an unattended machine, via auto-lock and Panic Lock.
* Accidental data loss during encryption (verify-then-delete, atomic writes, cancel safety).

**Does not protect against**

* **Weak passwords.** Argon2id slows guessing; it cannot rescue "password123". The app includes a
  strength meter and a generator.
* **Malware or an attacker with code execution as your user while the app is unlocked.** Keys
  necessarily exist in process memory during use; keyloggers and memory scrapers defeat any
  desktop encryption tool.
* **Metadata outside the container:** the encrypted file's name and size, timestamps, and the
  fact that Veilock is installed. (Original names are encrypted *inside* the container.)
* **Secure deletion.** "Remove original" performs a normal file delete. On SSDs, wear levelling,
  filesystem journaling, shadow copies, backups and cloud sync can leave recoverable copies of the
  plaintext. Veilock does not claim guaranteed erasure. For sensitive data, encrypt before the
  plaintext is ever synced or backed up, and use full-disk encryption (BitLocker) as well.
* **Swap/hibernation** of process memory while unlocked. Use full-disk encryption.
* **Screen capture** of decrypted content shown on screen.

## 7. Claims we deliberately do not make

No "unbreakable", "unhackable" or "military-grade" claims. The security rests on well-studied,
standard constructions used conservatively, and on the limits listed above. The software has not
undergone an independent third-party audit.

## 8. Reporting issues

Please report suspected vulnerabilities privately to the maintainers rather than opening a public
issue, including the Veilock version (Settings > About) and steps to reproduce. Do not attach
real encrypted files or passwords.
