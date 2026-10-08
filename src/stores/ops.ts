import { create } from "zustand";
import type { ProgressEvent } from "@/types/api";

interface OpsStore {
  progress: Record<string, ProgressEvent>;
  setProgress: (p: ProgressEvent) => void;
  clear: (opId: string) => void;
}

export const useOps = create<OpsStore>((set) => ({
  progress: {},
  setProgress: (p) => set((s) => ({ progress: { ...s.progress, [p.opId]: p } })),
  clear: (opId) =>
    set((s) => {
      const { [opId]: _gone, ...rest } = s.progress;
      return { progress: rest };
    }),
}));
