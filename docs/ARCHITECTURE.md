# Veilock architecture

```text
React UI (src/)                         Rust backend (src-tauri/src/)
────────────────                        ─────────────────────────────
pages / features / components
        │  typed calls
services/api.ts  ── Tauri invoke ──►   commands/*.rs  (validation, state, events)
        ▲                                   │
        └──── events (progress, lock) ──────┤
                                            ├─ crypto/       AES-256-GCM, Argon2id, HKDF, container, recovery
                                            ├─ filesystem/   safe copy/move, archive (folders), name validation
                                            ├─ vault/        credential store, file vaults, lock monitor
                                            ├─ security/     clipboard, generator, strength
                                            ├─ storage/      paths, atomic writes, SQLite metadata
                                            ├─ history/      privacy-safe activity log
                                            ├─ settings/     validated settings
                                            └─ integration/  HKCU registry, global shortcut, session events
```

Every user-visible workflow is traceable as **component → typed API function → `invoke` →
registered command → Rust module → real filesystem / crypto / database**. There are no mock
services, simulated progress or frontend-only secret stores.

## Frontend (`src/`)

* React 18, TypeScript (strict), Vite, Tailwind, Zustand, lucide-react icons.
* `pages/` Home, Protect, Unlock, Vaults, Vault detail, Passwords, Recent, Favorites, Activity,
  Settings, Item details. `features/` holds the feature-specific components (encryption and
  decryption flows with progress and cancel, onboarding, lock screen, global search, password
  vault, settings sections).
* `services/api.ts` is the only module that calls `invoke`. It defines the typed job shapes
  (`EncryptJob`, `DecryptJob`, `PasswordSource = typed | saved | default | recovery`) and maps
  error codes (`WRONG_PASSWORD`, `CORRUPTED`, `NOT_A_CONTAINER`, `OUTPUT_EXISTS`, `VAULT_LOCKED`,
  `NOT_FOUND`, `INVALID_INPUT`, `CANCELLED`) to translated messages with a "Show details" option.
* `i18n/` flat dotted keys in `en` and `ar` (same key set, enforced by tests). Arabic sets
  `dir="rtl"` on the document; layout uses logical properties so every component mirrors. Digits
  stay Latin in Arabic.
* Themes: `dark` (true `#000000` base), `light`, `system`; applied through `data-theme` and CSS
  variables. `prefers-reduced-motion` is honoured; focus rings are always visible.
* Branding comes from the root `branding.json` (app name, extension, shortcut default); strings do
  not hard-code the product name.

## Backend (`src-tauri/src/`)

* **Commands** are thin: validate input, take the right lock on `AppState`, call into a domain
  module, emit events. Long operations run on worker threads with a cancel flag and report real byte
  counts through `Progress` callbacks.
* **Lock state machine** (`locked → unlocking → unlocked → locking`) lives in the credential
  store. The auto-lock `Tracker` is pure and takes time as an argument, so every policy edge case
  is unit-tested.
* **Encrypt pipeline** (`filesystem/ops.rs`): snapshot source → stream to a temp file next to the
  destination → fsync → re-open and verify by authenticated decrypt → move into place without
  overwriting → only then optionally delete the source. Any failure or cancel removes the temp file
  and leaves the source untouched.
* **Decrypt pipeline**: authenticate header and key slot → decrypt into a temp file/folder →
  verify final chunk → move into place under the chosen conflict policy.
* **Credential store** (`vault/credentials.rs`): one encrypted file holding saved passwords and
  the Default Encryption Password; saved entries are keyed by the encrypted file's normalised path
  (case-insensitive, slash-insensitive, `\\?\`-prefix-insensitive on Windows).
* **File vaults** (`vault/files.rs`): a vault is a key container plus an encrypted index plus one
  `.veil` container per item, so vault password changes never re-encrypt content.
* **Metadata DB** (`storage/db.rs`): SQLite with `items`, `vaults`, `activity`, `meta`. No keys or
  passwords.
* **Integration** (`integration/`): optional per-user registry entries (Run key, `*`, `Directory`
  and `.veil` shell verbs), a global panic shortcut, and session-lock / sleep notifications.

## Data locations

| Location                                              | Content                                   |
|-------------------------------------------------------|-------------------------------------------|
| `%APPDATA%\app.veilock.desktop\config\settings.json`  | non-secret settings                       |
| `%APPDATA%\app.veilock.desktop\vault\credentials.vlkc`| encrypted credential store                |
| `%APPDATA%\app.veilock.desktop\vault\vaults\<id>\`    | file vaults                               |
| `%APPDATA%\app.veilock.desktop\db\metadata.sqlite3`   | item, vault and activity metadata         |
| `%APPDATA%\app.veilock.desktop\{cache,tmp}\`          | transient files                           |
| `%LOCALAPPDATA%\app.veilock.desktop\`                 | WebView2 profile                          |

The location is resolved by the OS known-folder API and is not affected by overriding the
`APPDATA` environment variable.

## Testing

* `cargo test` (203 tests): container round-trips, wrong password, tamper/truncate/reorder/splice
  detection, hostile headers and KDF parameters, recovery keys, credential store, vaults and bundle
  import, archive extraction safety, conflict policies, cancellation, lock policy, activity log,
  settings validation.
* `npm test` (31 tests): i18n completeness and RTL, shortcut parsing, id generation, error mapping,
  theme resolution, toast behaviour.
* Both run only against temporary data; nothing touches the user's files.
