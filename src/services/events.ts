import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import type { ProgressEvent } from "@/types/api";
import { inTauri } from "./ipc";

type Unlisten = () => void;
const noop: Unlisten = () => undefined;

/** Subscribe to a backend event. Outside Tauri (unit tests, plain-browser dev) this is a no-op. */
async function on<T>(event: string, handler: (payload: T) => void): Promise<Unlisten> {
  if (!inTauri()) return noop;
  return listen<T>(event, (e) => handler(e.payload));
}

/** Rust has locked everything (auto-lock, panic lock, session lock...). */
export const onLocked = (h: () => void): Promise<Unlisten> => on<unknown>("veilock://locked", () => h());

export const onProgress = (h: (p: ProgressEvent) => void): Promise<Unlisten> =>
  on<ProgressEvent>("veilock://progress", h);

/** A second launch (e.g. double-click on a .veil file) forwarded its file paths to us. */
export const onOpenFiles = (h: (paths: string[]) => void): Promise<Unlisten> =>
  on<string[]>("veilock://open-files", h);

export interface DropHandlers {
  onHover: (hovering: boolean) => void;
  onDrop: (paths: string[]) => void;
}

/** OS-level file drops. The webview hands us real filesystem paths, which HTML5 drag-and-drop
 * never does, and the paths go to Rust for inspection rather than being read in the UI. */
export async function onFileDrop(h: DropHandlers): Promise<Unlisten> {
  if (!inTauri()) return noop;
  return getCurrentWebview().onDragDropEvent((e) => {
    const p = e.payload;
    if (p.type === "enter" || p.type === "over") h.onHover(true);
    else if (p.type === "leave") h.onHover(false);
    else if (p.type === "drop") {
      h.onHover(false);
      if (p.paths.length > 0) h.onDrop(p.paths);
    }
  });
}
