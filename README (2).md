# Veilock

Local-first file and folder encryption for Windows. Veilock encrypts files and folders on your
computer with AES-256-GCM (keys derived with Argon2id), keeps an optional Master-Password-protected
password vault, and groups protected items into lockable vaults. It is offline by design: no
network access, accounts, analytics or telemetry.

Built with Tauri 2 (Rust) and React + TypeScript. All cryptography runs in Rust.

## Features

* Encrypt and decrypt files and folders (`.veil`), streamed with real progress and safe
  cancellation; large files use constant memory.
* Typed password, saved password, Default Encryption Password, or optional 256-bit recovery key.
* Password vault protected by a Master Password (saved passwords and the default password live only
  inside it), password generator and strength meter.
* Lockable vaults for groups of files and folders; export/import as `.veilvault`.
* App lock, auto-lock (inactivity, minimise, session lock, sleep), Panic Lock (`Ctrl+Shift+L`).
* Clipboard auto-clear, privacy-safe activity log, global search, favourites, recent items.
* English and Arabic with full RTL layout; Dark (true black), Light, System themes.
* Optional Windows integration: `.veil` association, Explorer context menu, Start with Windows.

## Requirements

* Windows 10 or 11 (x64) with WebView2 (preinstalled on current Windows)
* To build: Node.js 20+, Rust stable (MSVC toolchain), Visual Studio Build Tools (C++)

## Run (development)

```bash
npm install
npm run tauri dev
```

## Build and test

```bash
npm run typecheck          # TypeScript
npm test                   # frontend tests
npm run build              # production frontend
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cd ..
npm run tauri build        # release EXE and NSIS installer
```

Outputs (relative to the project root):

* Executable: `src-tauri/target/release/veilock.exe`
* Installer: `src-tauri/target/release/bundle/nsis/Veilock_0.1.0_x64-setup.exe`

The installer is per-user (no administrator rights). Uninstalling removes the application and
its own registry entries only; it never deletes your `.veil` files or your Veilock data folder.

## Using Veilock

1. First launch: create a Master Password. **It cannot be recovered.** There is no reset.
2. Protect a file or folder: choose it, choose how to set the password, optionally create a
   recovery key (shown once, store it offline), and optionally remove the original after
   verification.
3. Open a `.veil` file by double-clicking it (if associated) or from Unlock.
4. Lock the app at any time from the sidebar, or press `Ctrl+Shift+L`.

## Where data is stored

`%APPDATA%\app.veilock.desktop\` (settings, encrypted credential store, vaults, metadata database).
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Documentation

* [docs/SECURITY.md](docs/SECURITY.md): cryptography, secret handling, recovery, threat model, limits
* [docs/FORMAT.md](docs/FORMAT.md): container, credential store and vault file formats
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): code layout and data flow

## Known limitations

* Deleting the original after encryption is a normal delete. Secure erasure on SSDs cannot be
  guaranteed; see the SECURITY document.
* No independent security audit has been performed.
* Windows only. Installer is not code-signed, so SmartScreen may show a warning.
* A forgotten Master Password cannot be recovered; files remain decryptable with their own
  passwords or recovery keys.
