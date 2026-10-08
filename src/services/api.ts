import { call } from "./ipc";
import type {
  ActivityRecord,
  AddToVaultJob,
  AddToVaultResult,
  AppStatus,
  ConflictPolicy,
  CreateVaultJob,
  CreateVaultResult,
  DecryptJob,
  DecryptResult,
  EditableEntry,
  EncryptItemResult,
  EncryptJob,
  EntryUpdate,
  EntryView,
  ExportVaultJob,
  ExtractJob,
  ExtractResult,
  GeneratorRequest,
  ImportVaultJob,
  IntegrationStatus,
  ItemDetail,
  ItemMoveResult,
  ItemRecord,
  NewEntry,
  PasswordChangeResult,
  PasswordSource,
  PathInfo,
  SearchHit,
  Settings,
  StrengthReport,
  UnlockVaultJob,
  UnlockVaultResult,
  VaultItemView,
  VaultPasswordChanged,
  VaultView,
} from "@/types/api";

/** One typed function per Tauri command. No logic lives here, only the bridge. */

export const app = {
  status: () => call<AppStatus>("app_status"),
  updateSettings: (settings: Settings) => call<Settings>("settings_update", { settings }),
  completeOnboarding: (skipMaster: boolean) =>
    call<Settings>("onboarding_complete", { skipMaster }),
  createMaster: (master: string) => call<void>("master_create", { master }),
  unlock: (master: string) => call<void>("master_unlock", { master }),
  verifyMaster: (master: string) => call<void>("master_verify", { master }),
  changeMaster: (current: string, next: string) =>
    call<void>("master_change", { current, new: next }),
  lock: () => call<void>("app_lock"),
  panicLock: () => call<void>("panic_lock"),
  touch: () => call<void>("activity_touch"),
  reset: (master?: string) => call<void>("app_reset", { confirm: true, master }),
  cancelOp: (opId: string) => call<boolean>("op_cancel", { opId }),
  defaultPasswordConfigured: () => call<boolean>("default_password_status"),
  setDefaultPassword: (password: string, master: string) =>
    call<void>("default_password_set", { password, master }),
  clearDefaultPassword: (master: string) => call<void>("default_password_clear", { master }),
};

export const passwords = {
  list: () => call<EntryView[]>("passwords_list"),
  get: (id: string) => call<EditableEntry>("password_get", { id }),
  add: (entry: NewEntry) => call<EntryView>("password_add", { entry }),
  update: (id: string, update: EntryUpdate) => call<EntryView>("password_update", { id, update }),
  remove: (id: string) => call<void>("password_delete", { id, confirm: true }),
  reveal: (id: string, master?: string) => call<string>("password_reveal", { id, master }),
  copy: (id: string, master?: string) => call<void>("password_copy", { id, master }),
};

export const files = {
  takeLaunchPaths: () => call<string[]>("take_launch_paths"),
  inspect: (paths: string[]) => call<PathInfo[]>("inspect_paths", { paths }),
  encrypt: (job: EncryptJob) => call<EncryptItemResult[]>("encrypt_run", { job }),
  decrypt: (job: DecryptJob) => call<DecryptResult>("decrypt_run", { job }),
};

export const items = {
  recent: (limit?: number) => call<ItemDetail[]>("items_recent", { limit }),
  favorites: () => call<ItemDetail[]>("items_favorites"),
  get: (id: string) => call<ItemDetail>("item_get", { id }),
  forPath: (path: string) => call<ItemDetail | null>("item_for_path", { path }),
  setFavorite: (id: string, favorite: boolean) => call<void>("item_favorite", { id, favorite }),
  removeFromHistory: (id: string) => call<void>("item_remove_from_history", { id }),
  clearRecent: () => call<void>("recent_clear"),
  rename: (id: string, newName: string) => call<ItemRecord>("item_rename", { id, newName }),
  move: (id: string, destDir: string) => call<ItemMoveResult>("item_move", { id, destDir }),
  deleteFile: (id: string, master?: string) =>
    call<void>("item_delete_file", { id, confirm: true, master }),
  revealInFolder: (id: string) => call<void>("item_reveal_in_folder", { id }),
  changePassword: (id: string, current: PasswordSource, newPassword: string, master?: string) =>
    call<PasswordChangeResult>("item_change_password", { id, current, newPassword, master }),
  setRecovery: (id: string, current: PasswordSource, master?: string) =>
    call<string>("item_set_recovery", { id, current, master }),
  removeRecovery: (id: string, current: PasswordSource, master?: string) =>
    call<void>("item_remove_recovery", { id, current, master }),
};

export const tools = {
  generate: (req: GeneratorRequest) => call<string>("generate_password", { req }),
  strength: (password: string) => call<StrengthReport>("password_strength", { password }),
  copy: (text: string) => call<void>("clipboard_copy", { text }),
  clearOwnedClipboard: () => call<boolean>("clipboard_clear_owned"),
  saveTextFile: (path: string, text: string) => call<void>("save_text_file", { path, text }),
};

export const vaults = {
  list: () => call<VaultView[]>("vaults_list"),
  get: (id: string) => call<VaultView>("vault_get", { id }),
  items: (id: string) => call<VaultItemView[]>("vault_items", { id }),
  create: (job: CreateVaultJob) => call<CreateVaultResult>("vault_create", { job }),
  unlock: (job: UnlockVaultJob) => call<UnlockVaultResult>("vault_unlock", { job }),
  lock: (id: string) => call<void>("vault_lock", { id }),
  rename: (id: string, name: string, icon: string | undefined, description: string) =>
    call<VaultView>("vault_rename", { id, name, icon, description }),
  setFavorite: (id: string, favorite: boolean) =>
    call<VaultView>("vault_favorite", { id, favorite }),
  changePassword: (id: string, current: PasswordSource, newPassword: string, master?: string) =>
    call<VaultPasswordChanged>("vault_change_password", { id, current, newPassword, master }),
  setRecovery: (id: string, current: PasswordSource, master?: string) =>
    call<string>("vault_set_recovery", { id, current, master }),
  removeRecovery: (id: string, current: PasswordSource, master?: string) =>
    call<void>("vault_remove_recovery", { id, current, master }),
  remove: (id: string, master?: string) =>
    call<void>("vault_delete", { id, confirm: true, master }),
  addItems: (job: AddToVaultJob) => call<AddToVaultResult[]>("vault_add_items", { job }),
  extractItem: (job: ExtractJob) => call<ExtractResult>("vault_extract_item", { job }),
  removeItem: (vaultId: string, itemId: string, master?: string) =>
    call<void>("vault_remove_item", { vaultId, itemId, confirm: true, master }),
  exportBundle: (job: ExportVaultJob) => call<string>("vault_export", { job }),
  importBundle: (job: ImportVaultJob) => call<VaultView>("vault_import", { job }),
};

export const activity = {
  list: (limit?: number) => call<ActivityRecord[]>("activity_list", { limit }),
  clear: () => call<void>("activity_clear", { confirm: true }),
};

export const search = {
  all: (query: string) => call<SearchHit[]>("search_all", { query }),
};

export const integration = {
  status: () => call<IntegrationStatus>("integration_status"),
  setAutostart: (enabled: boolean) =>
    call<IntegrationStatus>("integration_set_autostart", { enabled }),
  setContextMenu: (enabled: boolean) =>
    call<IntegrationStatus>("integration_set_context_menu", { enabled }),
};

export type { ConflictPolicy };
