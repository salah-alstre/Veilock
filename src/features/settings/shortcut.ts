/** Builds a `Mod+Mod+Key` accelerator (the shape Rust's `parse_shortcut` accepts) from a keydown. */

const NAMED_KEYS: Record<string, string> = {
  " ": "Space",
  Escape: "Escape",
  Home: "Home",
  End: "End",
  PageUp: "PageUp",
  PageDown: "PageDown",
};

export interface KeyLike {
  key: string;
  code?: string;
  ctrlKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
  metaKey: boolean;
}

/** Returns the accelerator, or null while the combination is incomplete or unsupported. */
export function acceleratorFromEvent(e: KeyLike): string | null {
  if (["Control", "Shift", "Alt", "Meta", "AltGraph"].includes(e.key)) return null;
  if (!(e.ctrlKey || e.altKey || e.metaKey)) return null;

  let key: string | null = null;
  if (/^F([1-9]|1[0-2])$/.test(e.key)) {
    key = e.key;
  } else if (NAMED_KEYS[e.key]) {
    key = NAMED_KEYS[e.key] ?? null;
  } else if (e.code && /^Key[A-Z]$/.test(e.code)) {
    // `code` is layout-independent, so Ctrl+Shift+L stays "L" on an Arabic keyboard layout.
    key = e.code.slice(3);
  } else if (e.code && /^Digit[0-9]$/.test(e.code)) {
    key = e.code.slice(5);
  } else if (e.key.length === 1 && /^[a-zA-Z0-9]$/.test(e.key)) {
    key = e.key.toUpperCase();
  }
  if (!key) return null;

  const parts: string[] = [];
  if (e.ctrlKey) parts.push("Ctrl");
  if (e.altKey) parts.push("Alt");
  if (e.shiftKey) parts.push("Shift");
  if (e.metaKey) parts.push("Super");
  parts.push(key);
  return parts.length >= 2 && parts.length <= 4 ? parts.join("+") : null;
}
