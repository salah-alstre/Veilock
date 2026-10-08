import { useEffect, useState } from "react";
import * as api from "@/services/api";
import { onFileDrop, onLocked, onOpenFiles, onProgress } from "@/services/events";
import { useApp } from "@/stores/app";
import { useNav } from "@/stores/nav";
import { useOps } from "@/stores/ops";
import { useToasts } from "@/stores/toasts";
import { toAppError } from "@/services/errors";
import { watchSystemTheme } from "@/utils/theme";

/** Minimum gap between "the user is active" pings to Rust (it only needs second-level accuracy). */
const TOUCH_INTERVAL_MS = 5_000;

/** Sends dropped / launched paths to the right screen. Rust classifies them (by magic bytes,
 * not by extension), so a renamed container is still recognised. */
async function routePaths(paths: string[], t: (key: string) => string): Promise<void> {
  const nav = useNav.getState();
  try {
    const infos = await api.files.inspect(paths);
    const containers = infos.filter((i) => i.container && !i.error).map((i) => i.path);
    const others = infos.filter((i) => !i.container && !i.error).map((i) => i.path);
    if (others.length > 0) {
      // A mixed drop goes to Protect: it can list everything, and containers can still be
      // opened afterwards from Recent. Silently dropping either group would be worse.
      nav.stageProtect(infos.filter((i) => !i.error).map((i) => i.path));
    } else if (containers.length > 0) {
      nav.stageUnlock(containers);
    } else if (infos.length > 0) {
      useToasts.getState().push("error", t("error.NOT_FOUND"));
    }
  } catch (e) {
    useToasts.getState().push("error", t(`error.${toAppError(e).code}`));
  }
}

/**
 * Wires every backend → UI event once for the whole app: lock notifications, progress, files
 * forwarded from a second launch, OS drag-and-drop, the OS theme, and the activity heartbeat that
 * drives auto-lock. Returns whether a drag is currently hovering the window.
 */
export function useGlobalEvents(t: (key: string) => string): boolean {
  const [hovering, setHovering] = useState(false);

  useEffect(() => {
    let disposed = false;
    const unlisteners: Array<() => void> = [];
    const keep = (p: Promise<() => void>): void => {
      void p.then((un) => {
        if (disposed) un();
        else unlisteners.push(un);
      });
    };

    keep(
      onLocked(() => {
        useNav.getState().reset();
        void useApp.getState().handleLocked();
      }),
    );
    keep(onProgress((p) => useOps.getState().setProgress(p)));
    keep(
      onOpenFiles((paths) => {
        void routePaths(paths, t);
      }),
    );
    keep(
      onFileDrop({
        onHover: setHovering,
        onDrop: (paths) => {
          // Drops are only meaningful once the app is usable; a locked or onboarding window ignores them.
          const s = useApp.getState().status;
          if (!s || !s.settings.onboarded) return;
          if (s.masterExists && s.lockPhase !== "unlocked") return;
          void routePaths(paths, t);
        },
      }),
    );

    unlisteners.push(watchSystemTheme(() => useApp.getState().status?.settings.theme ?? "system"));

    // Files the app was launched with (double-click in Explorer on a cold start).
    void api.files
      .takeLaunchPaths()
      .then((paths) => {
        if (!disposed && paths.length > 0) void routePaths(paths, t);
      })
      .catch(() => undefined);

    let last = 0;
    const touch = (): void => {
      const now = Date.now();
      if (now - last < TOUCH_INTERVAL_MS) return;
      last = now;
      void api.app.touch().catch(() => undefined);
    };
    const events = ["pointerdown", "keydown", "wheel"] as const;
    for (const ev of events) window.addEventListener(ev, touch, { passive: true });

    return () => {
      disposed = true;
      for (const un of unlisteners) un();
      for (const ev of events) window.removeEventListener(ev, touch);
    };
    // `t` changes with the language; the handlers only use it for error text, so re-subscribing
    // on every language switch would drop events for no benefit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return hovering;
}
