import { create } from "zustand";
import * as api from "@/services/api";
import { useI18n } from "@/i18n";
import { applyTheme } from "@/utils/theme";
import type { AppStatus, LockPhase, Settings } from "@/types/api";

interface AppStore {
  status: AppStatus | null;
  /** Bumped on every lock so the shell remounts and every secret-holding field is destroyed. */
  epoch: number;
  /** True once the first `app_status` has resolved or failed. */
  ready: boolean;
  loadError: boolean;
  load: () => Promise<void>;
  refresh: () => Promise<void>;
  saveSettings: (next: Settings) => Promise<void>;
  patchSettings: (fn: (s: Settings) => Settings) => Promise<void>;
  /** Called when Rust reports that everything was locked. */
  handleLocked: () => Promise<void>;
  setPhase: (phase: LockPhase) => void;
}

function applyAppearance(s: Settings): void {
  applyTheme(s.theme);
  useI18n.getState().setLang(s.language);
}

export const useApp = create<AppStore>((set, get) => ({
  status: null,
  epoch: 0,
  ready: false,
  loadError: false,

  load: async () => {
    try {
      const status = await api.app.status();
      applyAppearance(status.settings);
      set({ status, ready: true, loadError: false });
    } catch {
      set({ ready: true, loadError: true });
    }
  },

  refresh: async () => {
    const status = await api.app.status();
    applyAppearance(status.settings);
    set({ status });
  },

  saveSettings: async (next) => {
    const saved = await api.app.updateSettings(next);
    applyAppearance(saved);
    set((s) => (s.status ? { status: { ...s.status, settings: saved } } : s));
  },

  patchSettings: async (fn) => {
    const cur = get().status?.settings;
    if (!cur) return;
    await get().saveSettings(fn(cur));
  },

  handleLocked: async () => {
    set((s) => ({ epoch: s.epoch + 1 }));
    try {
      await get().refresh();
    } catch {
      /* the lock itself already happened in Rust; a failed refresh must not undo it in the UI */
      set((s) =>
        s.status ? { status: { ...s.status, lockPhase: "locked", unlockedVaults: [] } } : s,
      );
    }
  },

  setPhase: (phase) =>
    set((s) => (s.status ? { status: { ...s.status, lockPhase: phase } } : s)),
}));

/** The UI-level gate: with a master password set, nothing renders until it is unlocked. */
export function selectIsGated(status: AppStatus | null): boolean {
  return status !== null && status.masterExists && status.lockPhase !== "unlocked";
}
