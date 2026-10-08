import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DICTIONARIES, RTL_LANGUAGES, formatBytes, formatNumber, translate } from "./index";

const en = DICTIONARIES.en;
const ar = DICTIONARIES.ar;
const placeholders = (s: string): string => (s.match(/\{\w+\}/g) ?? []).sort().join(",");

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) sourceFiles(p, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.test\./.test(name)) out.push(p);
  }
  return out;
}

describe("locale files", () => {
  it("are non-empty", () => {
    expect(Object.keys(en).length).toBeGreaterThan(400);
    expect(Object.keys(ar).length).toBeGreaterThan(400);
  });

  it("have identical key sets", () => {
    const e = Object.keys(en).sort();
    const a = Object.keys(ar).sort();
    expect(e.filter((k) => !(k in ar))).toEqual([]);
    expect(a.filter((k) => !(k in en))).toEqual([]);
  });

  it("have no empty values", () => {
    expect(Object.entries(en).filter(([, v]) => !v.trim())).toEqual([]);
    expect(Object.entries(ar).filter(([, v]) => !v.trim())).toEqual([]);
  });

  it("use identical interpolation placeholders", () => {
    const bad = Object.keys(en).filter((k) => ar[k] !== undefined && placeholders(en[k] ?? "") !== placeholders(ar[k] ?? ""));
    expect(bad).toEqual([]);
  });

  it("actually translate (Arabic strings are not copies of English)", () => {
    const same = Object.keys(en).filter((k) => en[k] === ar[k] && /[A-Za-z]{4,}/.test(en[k] ?? ""));
    // Only language endonyms, units and product names may be identical.
    expect(same.filter((k) => !["settings.lang.en"].includes(k)).length).toBeLessThan(5);
  });

  it("covers every literal t(\"…\") key used in the source", () => {
    const used = new Set<string>();
    for (const f of sourceFiles(resolve(__dirname, ".."))) {
      const text = readFileSync(f, "utf8");
      for (const m of text.matchAll(/\bt\(\s*["']([A-Za-z0-9_.]+)["']/g)) used.add(m[1] ?? "");
    }
    expect(used.size).toBeGreaterThan(100);
    expect([...used].filter((k) => !(k in en))).toEqual([]);
    expect([...used].filter((k) => !(k in ar))).toEqual([]);
  });

  it("covers every dynamic key family", () => {
    const codes = [
      "WRONG_PASSWORD", "INVALID_RECOVERY_KEY", "CORRUPTED", "UNSUPPORTED", "NOT_A_CONTAINER", "NO_SPACE",
      "PERMISSION_DENIED", "FILE_IN_USE", "OUTPUT_EXISTS", "NOT_FOUND", "VAULT_LOCKED", "CANCELLED",
      "VERIFICATION_FAILED", "SOURCE_CHANGED", "INVALID_INPUT", "UNSAFE_PATH", "STORAGE", "BUSY", "IO", "INTERNAL",
    ];
    const kinds = [
      "encrypt", "decrypt", "vault_create", "vault_open", "vault_lock", "vault_delete", "vault_import",
      "vault_export", "password_change", "recovery_key_create", "app_unlock", "app_lock", "panic_lock",
      "password_saved", "password_deleted", "master_change", "vault_rename", "vault_item_add",
      "vault_item_extract", "vault_item_remove",
    ];
    const keys = [
      ...codes.map((c) => `error.${c}`),
      ...kinds.map((k) => `activity.kind.${k}`),
      ...["very_weak", "weak", "medium", "strong", "very_strong"].map((s) => `strength.${s}`),
      ...["scanning", "encrypting", "verifying", "decrypting", "exporting", "importing"].map((p) => `progress.phase.${p}`),
      ...["item", "vault", "vaultItem", "password"].map((k) => `search.kind.${k}`),
      ...["file", "folder", "vault", "other"].map((k) => `passwords.kind.${k}`),
      ...["typed", "saved", "default", "recovery"].map((k) => `picker.${k}`),
      ...["home", "protect", "vaults", "passwords", "recent", "favorites", "activity", "settings"].map((n) => `nav.${n}`),
      ...["dark", "light", "system"].map((t) => `theme.${t}`),
      ...["B", "KB", "MB", "GB", "TB"].map((u) => `unit.${u}`),
      ...["general", "security", "encryption", "passwords", "appearance", "language", "windows", "privacy", "about"].map((c) => `settings.cat.${c}`),
    ];
    for (const k of keys) {
      expect(en[k], `en ${k}`).toBeTruthy();
      expect(ar[k], `ar ${k}`).toBeTruthy();
    }
  });
});

describe("translate", () => {
  it("interpolates and falls back to the key", () => {
    expect(translate("en", "progress.item", { i: 2, n: 5 })).toBe("Item 2 of 5");
    expect(translate("ar", "progress.item", { i: 2, n: 5 })).toContain("2");
    expect(translate("en", "no.such.key")).toBe("no.such.key");
  });

  it("marks Arabic as RTL only", () => {
    expect(RTL_LANGUAGES.has("ar")).toBe(true);
    expect(RTL_LANGUAGES.has("en")).toBe(false);
  });

  it("formats numbers and sizes with Latin digits in both languages", () => {
    expect(formatNumber("ar", 1234)).toMatch(/^[0-9,٬.]+$/);
    expect(formatNumber("ar", 12)).toBe("12");
    expect(formatBytes("en", 0)).toBe("0 B");
    expect(formatBytes("en", 1536)).toBe("1.5 KB");
    expect(formatBytes("en", -1)).toBe("—");
  });
});
