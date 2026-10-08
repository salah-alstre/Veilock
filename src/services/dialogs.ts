import { open, save } from "@tauri-apps/plugin-dialog";
import { inTauri } from "./ipc";

/** Native pickers. They return real filesystem paths, which Rust then validates; the UI never
 * reads file contents itself. Outside Tauri (tests, plain browser) they resolve to nothing. */

export async function pickFiles(): Promise<string[]> {
  if (!inTauri()) return [];
  const r = await open({ multiple: true, directory: false });
  return r ?? [];
}

export async function pickFolders(): Promise<string[]> {
  if (!inTauri()) return [];
  const r = await open({ multiple: true, directory: true });
  return r ?? [];
}

export async function pickDirectory(): Promise<string | null> {
  if (!inTauri()) return null;
  const r = await open({ multiple: false, directory: true });
  return r ?? null;
}

export async function pickContainers(): Promise<string[]> {
  if (!inTauri()) return [];
  const r = await open({ multiple: true, directory: false, filters: [{ name: "Encrypted", extensions: ["veil"] }] });
  return r ?? [];
}

export async function pickBundle(): Promise<string | null> {
  if (!inTauri()) return null;
  const r = await open({ multiple: false, directory: false, filters: [{ name: "Vault bundle", extensions: ["veilvault"] }] });
  return r ?? null;
}

export async function pickSaveFile(defaultName: string, ext: string): Promise<string | null> {
  if (!inTauri()) return null;
  const r = await save({ defaultPath: defaultName, filters: [{ name: ext, extensions: [ext] }] });
  return r ?? null;
}
