/**
 * Wire types mirroring the Rust command layer (`src-tauri/src/commands`). Everything here is
 * plain data: keys and saved passwords never appear in these shapes. Fields that carry a user
 * secret *into* Rust (`password`, `master`) are plain strings and are never stored in state.
 */

export type ErrorCode =
  | "WRONG_PASSWORD"
  | "INVALID_RECOVERY_KEY"
  | "CORRUPTED"
  | "UNSUPPORTED"
  | "NOT_A_CONTAINER"
  | "NO_SPACE"
  | "PERMISSION_DENIED"
  | "FILE_IN_USE"
  | "OUTPUT_EXISTS"
  | "NOT_FOUND"
  | "VAULT_LOCKED"
  | "CANCELLED"
  | "VERIFICATION_FAILED"
  | "SOURCE_CHANGED"
  | "INVALID_INPUT"
  | "UNSAFE_PATH"
  | "STORAGE"
  | "BUSY"
  | "IO"
  | "INTERNAL";

export interface AppErrorPayload {
  code: ErrorCode;
  details?: string;
}

export type LockPhase = "locked" | "unlocking" | "unlocked" | "locking";
export type ThemeSetting = "system" | "dark" | "light";
export type Language = "en" | "ar";
export type PostEncrypt = "keep_original" | "remove_original";
export type DefaultPasswordMode = "auto" | "ask" | "require_master";

export interface GeneralSettings {
  startMinimized: boolean;
  lockOnMinimize: boolean;
  rememberWindowSize: boolean;
  windowWidth?: number | null;
  windowHeight?: number | null;
}

export interface SecuritySettings {
  /** seconds; 0 = when the window loses focus; null = never */
  autoLockSecs: number | null;
  lockOnSessionLock: boolean;
  lockOnSleep: boolean;
  panicShortcut: string;
  requireMasterForSensitive: boolean;
  requireMasterToReveal: boolean;
  backgroundLockMinutes: number | null;
}

export interface EncryptionSettings {
  defaultOutputDir: string | null;
  postEncrypt: PostEncrypt;
  defaultPasswordMode: DefaultPasswordMode;
}

export interface PasswordSettings {
  generatorLength: number;
  generatorUpper: boolean;
  generatorLower: boolean;
  generatorDigits: boolean;
  generatorSymbols: boolean;
  generatorAvoidAmbiguous: boolean;
  /** seconds; null = never */
  clipboardClearSecs: number | null;
}

export interface Settings {
  version: number;
  theme: ThemeSetting;
  language: Language;
  historyEnabled: boolean;
  onboarded: boolean;
  masterSkipped: boolean;
  general: GeneralSettings;
  security: SecuritySettings;
  encryption: EncryptionSettings;
  passwords: PasswordSettings;
}

export interface AppStatus {
  version: string;
  masterExists: boolean;
  lockPhase: LockPhase;
  unlockedVaults: string[];
  runningOps: string[];
  settings: Settings;
}

// ----- password sources ----------------------------------------------------------------------

export type PasswordSource =
  | { kind: "typed"; password: string }
  | { kind: "saved" }
  | { kind: "default" }
  | { kind: "recovery"; key: string };

export type ConflictPolicy = "fail" | "keepBoth" | "replace";

// ----- files ---------------------------------------------------------------------------------

export type ItemKind = "file" | "folder";

export interface ContainerInfo {
  version: number;
  kind: ItemKind;
  cipher: string;
  hasPasswordSlot: boolean;
  hasRecoverySlot: boolean;
  modifiedAt?: number | null;
  hasSavedPassword: boolean;
  itemId?: string | null;
}

export interface PathInfo {
  path: string;
  name: string;
  isDir: boolean;
  size: number;
  fileCount: number;
  dirCount: number;
  container?: ContainerInfo | null;
  error?: AppErrorPayload | null;
}

export interface EncryptJob {
  opId: string;
  paths: string[];
  password: PasswordSource;
  master?: string;
  outDir?: string;
  onConflict: ConflictPolicy;
  removeOriginal: boolean;
  withRecovery: boolean;
  savePassword: boolean;
}

export type Removal =
  | { status: "notRequested" }
  | { status: "removed" }
  | { status: "failed"; code: string };

export interface EncryptItemResult {
  path: string;
  ok: boolean;
  output?: string | null;
  name?: string | null;
  kind?: ItemKind | null;
  originalSize: number;
  encryptedSize: number;
  fileCount: number;
  removal?: Removal | null;
  recoveryKey?: string | null;
  passwordSaved: boolean;
  passwordSaveError?: AppErrorPayload | null;
  error?: AppErrorPayload | null;
}

export interface DecryptJob {
  opId: string;
  path: string;
  password: PasswordSource;
  master?: string;
  outDir?: string;
  onConflict: ConflictPolicy;
  savePassword: boolean;
}

export interface DecryptResult {
  output: string;
  name: string;
  kind: ItemKind;
  bytes: number;
  fileCount: number;
  dirCount: number;
  passwordSaved: boolean;
  passwordSaveError?: AppErrorPayload | null;
}

export type ProgressPhase =
  | "scanning"
  | "encrypting"
  | "verifying"
  | "decrypting"
  | "exporting"
  | "importing";

export interface ProgressEvent {
  opId: string;
  itemIndex: number;
  itemCount: number;
  phase: ProgressPhase;
  doneBytes: number;
  totalBytes: number;
  currentItem: string;
  bytesPerSec: number;
  etaSecs?: number | null;
}

// ----- items ---------------------------------------------------------------------------------

export interface ItemRecord {
  id: string;
  name: string;
  kind: ItemKind;
  originalPath?: string | null;
  encryptedPath: string;
  originalSize: number;
  encryptedSize: number;
  createdAt: number;
  lastOpenedAt?: number | null;
  formatVersion: number;
  algorithm: string;
  hasSavedPassword: boolean;
  hasRecovery: boolean;
  favorite: boolean;
  fileCount: number;
}

export interface ItemDetail extends ItemRecord {
  exists: boolean;
}

export interface ItemMoveResult {
  item: ItemRecord;
  originalLeftBehind: boolean;
}

export interface PasswordChangeResult {
  savedPassword: "none" | "updated";
}

// ----- vaults --------------------------------------------------------------------------------

export interface VaultRecord {
  id: string;
  name: string;
  icon: string;
  description: string;
  createdAt: number;
  lastOpenedAt?: number | null;
  hasRecovery: boolean;
  hasSavedPassword: boolean;
  favorite: boolean;
}

export interface VaultView extends VaultRecord {
  unlocked: boolean;
  itemCount?: number | null;
}

export interface VaultItemView {
  id: string;
  name: string;
  kind: ItemKind;
  originalSize: number;
  encryptedSize: number;
  createdAt: number;
  fileCount: number;
  dirCount: number;
}

export interface CreateVaultJob {
  name: string;
  icon?: string;
  description: string;
  password: string;
  withRecovery: boolean;
  savePassword: boolean;
}

export interface CreateVaultResult {
  vault: VaultView;
  recoveryKey?: string | null;
  passwordSaved: boolean;
  passwordSaveError?: AppErrorPayload | null;
}

export interface UnlockVaultJob {
  id: string;
  password: PasswordSource;
  master?: string;
  savePassword: boolean;
}

export interface UnlockVaultResult {
  vault: VaultView;
  passwordSaved: boolean;
  passwordSaveError?: AppErrorPayload | null;
}

export interface AddToVaultJob {
  opId: string;
  vaultId: string;
  paths: string[];
  removeOriginal: boolean;
  master?: string;
}

export interface AddToVaultResult {
  path: string;
  ok: boolean;
  item?: VaultItemView | null;
  removal?: Removal | null;
  error?: AppErrorPayload | null;
}

export interface ExtractJob {
  opId: string;
  vaultId: string;
  itemId: string;
  outDir: string;
  onConflict: ConflictPolicy;
}

export interface ExtractResult {
  output: string;
  name: string;
  kind: ItemKind;
  bytes: number;
  fileCount: number;
  dirCount: number;
}

export interface ExportVaultJob {
  opId: string;
  vaultId: string;
  destDir: string;
  onConflict: ConflictPolicy;
}

export interface ImportVaultJob {
  opId: string;
  bundle: string;
}

export interface VaultPasswordChanged {
  savedPasswordUpdated: boolean;
}

// ----- credential vault ----------------------------------------------------------------------

export type EntryKind = "file" | "folder" | "vault" | "other";

export interface EntryView {
  id: string;
  name: string;
  kind: EntryKind;
  originalPath?: string | null;
  encryptedPath?: string | null;
  favorite: boolean;
  createdAt: number;
  lastUsedAt?: number | null;
  itemId?: string | null;
  hasNotes: boolean;
}

export interface EditableEntry extends EntryView {
  notes: string;
}

export interface NewEntry {
  name: string;
  kind: EntryKind;
  originalPath?: string;
  encryptedPath?: string;
  password: string;
  notes: string;
  itemId?: string;
}

export interface EntryUpdate {
  name?: string;
  notes?: string;
  password?: string;
  favorite?: boolean;
}

// ----- tools ---------------------------------------------------------------------------------

export type StrengthLevel = "very_weak" | "weak" | "medium" | "strong" | "very_strong";

export interface StrengthReport {
  level: StrengthLevel;
  bits: number;
  score: 0 | 1 | 2 | 3 | 4;
}

export interface GeneratorRequest {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

// ----- windows integration -------------------------------------------------------------------

export interface IntegrationStatus {
  supported: boolean;
  autostart: boolean;
  contextMenu: boolean;
  fileAssociation: boolean;
}

// ----- activity & search ---------------------------------------------------------------------

export interface ActivityRecord {
  id: number;
  ts: number;
  kind: string;
  subject?: string | null;
  outcome: string;
}

export interface SearchHit {
  kind: "item" | "vault" | "vaultItem" | "password";
  id: string;
  title: string;
  vaultId?: string | null;
  path?: string | null;
}
