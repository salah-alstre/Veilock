import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { toAppError } from "./errors";

/**
 * The single place the UI crosses into Rust. Every rejection is normalised to an `AppError`.
 * Arguments are never logged: they may contain passwords.
 */
export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await tauriInvoke<T>(command, args);
  } catch (e) {
    throw toAppError(e);
  }
}

/** True when running inside the Tauri webview (false in plain-browser dev and in unit tests). */
export function inTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
