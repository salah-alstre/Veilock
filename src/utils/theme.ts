import type { ThemeSetting } from "@/types/api";

export type ResolvedTheme = "dark" | "light";

export function systemTheme(): ResolvedTheme {
  if (typeof window === "undefined" || !window.matchMedia) return "dark";
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function resolveTheme(setting: ThemeSetting): ResolvedTheme {
  return setting === "system" ? systemTheme() : setting;
}

export function applyTheme(setting: ThemeSetting): void {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = resolveTheme(setting);
}

/** Re-applies the theme when the OS preference flips, but only while the setting is "system". */
export function watchSystemTheme(getSetting: () => ThemeSetting): () => void {
  if (typeof window === "undefined" || !window.matchMedia) return () => undefined;
  const mq = window.matchMedia("(prefers-color-scheme: light)");
  const handler = (): void => {
    if (getSetting() === "system") applyTheme("system");
  };
  mq.addEventListener("change", handler);
  return () => mq.removeEventListener("change", handler);
}
