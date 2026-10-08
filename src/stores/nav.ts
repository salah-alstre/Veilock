import { create } from "zustand";

export type Page =
  | { name: "home" }
  | { name: "protect" }
  | { name: "unlock" }
  | { name: "vaults" }
  | { name: "vault"; id: string }
  | { name: "passwords" }
  | { name: "recent" }
  | { name: "favorites" }
  | { name: "activity" }
  | { name: "settings" }
  | { name: "item"; id: string };

export type TopLevel = "home" | "protect" | "vaults" | "passwords" | "recent" | "favorites" | "activity" | "settings";

interface NavStore {
  page: Page;
  /** Paths staged for the Protect screen (files/folders to encrypt). */
  protectPaths: string[];
  /** Encrypted containers waiting on the Unlock screen, first is current. */
  unlockQueue: string[];
  sidebarCollapsed: boolean;
  go: (page: Page) => void;
  stageProtect: (paths: string[]) => void;
  stageUnlock: (paths: string[]) => void;
  shiftUnlock: () => void;
  clearStaged: () => void;
  toggleSidebar: () => void;
  reset: () => void;
}

export const useNav = create<NavStore>((set) => ({
  page: { name: "home" },
  protectPaths: [],
  unlockQueue: [],
  sidebarCollapsed: false,
  go: (page) => set({ page }),
  stageProtect: (paths) => set({ protectPaths: paths, page: { name: "protect" } }),
  stageUnlock: (paths) => set({ unlockQueue: paths, page: { name: "unlock" } }),
  shiftUnlock: (): void =>
    set((s) => {
      const rest = s.unlockQueue.slice(1);
      return { unlockQueue: rest, page: rest.length > 0 ? s.page : { name: "home" } };
    }),
  clearStaged: () => set({ protectPaths: [], unlockQueue: [] }),
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  reset: () => set({ page: { name: "home" }, protectPaths: [], unlockQueue: [] }),
}));

/** Which sidebar entry should look selected for a page. */
export function topLevelOf(page: Page): TopLevel {
  switch (page.name) {
    case "unlock":
      return "protect";
    case "vault":
      return "vaults";
    case "item":
      return "recent";
    default:
      return page.name;
  }
}
