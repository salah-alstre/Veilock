/** Operation ids tie progress events and cancellation to one running job. */
export function newOpId(): string {
  return globalThis.crypto.randomUUID();
}

/** Last path component for either separator style (display only; Rust does all real path work). */
export function baseName(path: string): string {
  const parts = path.split(/[\\/]+/).filter(Boolean);
  return parts[parts.length - 1] ?? path;
}

/** Parent directory of a path, display/default-picker use only. */
export function dirName(path: string): string {
  const i = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return i > 0 ? path.slice(0, i) : path;
}
