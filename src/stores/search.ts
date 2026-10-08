import { create } from "zustand";

/** Only whether the global search dialog is open; the query itself stays in the dialog's state. */
interface SearchStore {
  open: boolean;
  show: () => void;
  hide: () => void;
}

export const useSearch = create<SearchStore>((set) => ({
  open: false,
  show: () => set({ open: true }),
  hide: () => set({ open: false }),
}));
