import { create } from "zustand";

export type ToastKind = "info" | "success" | "error";

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastStore {
  toasts: Toast[];
  push: (kind: ToastKind, message: string) => void;
  dismiss: (id: number) => void;
}

let nextId = 1;
const MAX_VISIBLE = 3;
const LIFETIME_MS: Record<ToastKind, number> = { info: 3500, success: 3500, error: 7000 };

export const useToasts = create<ToastStore>((set, get) => ({
  toasts: [],
  push: (kind, message) => {
    // Identical message already on screen: drop it, so a retry loop cannot flood the stack.
    if (get().toasts.some((t) => t.message === message && t.kind === kind)) return;
    const id = nextId++;
    set((s) => ({ toasts: [...s.toasts, { id, kind, message }].slice(-MAX_VISIBLE) }));
    setTimeout(() => get().dismiss(id), LIFETIME_MS[kind]);
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
