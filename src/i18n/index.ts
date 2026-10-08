import { useMemo } from "react";
import { create } from "zustand";
import en from "./locales/en.json";
import ar from "./locales/ar.json";
import type { Language } from "@/types/api";

type Tree = { [k: string]: string | Tree };

const flatten = (tree: Tree, prefix = "", out: Record<string, string> = {}): Record<string, string> => {
  for (const [k, v] of Object.entries(tree)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "string") out[key] = v;
    else flatten(v, key, out);
  }
  return out;
};

export const DICTIONARIES: Record<Language, Record<string, string>> = {
  en: flatten(en as Tree),
  ar: flatten(ar as Tree),
};

export const RTL_LANGUAGES: ReadonlySet<Language> = new Set<Language>(["ar"]);

export type Params = Record<string, string | number>;

function interpolate(text: string, params?: Params): string {
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (m, name: string) => {
    const v = params[name];
    return v === undefined ? m : String(v);
  });
}

/** Look a key up in `lang`, falling back to English, then to the key itself (visible in dev). */
export function translate(lang: Language, key: string, params?: Params): string {
  const text = DICTIONARIES[lang][key] ?? DICTIONARIES.en[key] ?? key;
  return interpolate(text, params);
}

/** Pluralised lookup using the language's real CLDR rules: tries `key.<category>`, then `key.other`.
 * Arabic has six categories, so "{n} items" cannot be done with a single string. */
export function translatePlural(lang: Language, key: string, n: number, params?: Params): string {
  const category = new Intl.PluralRules(lang).select(n);
  const dict = DICTIONARIES[lang];
  const k = dict[`${key}.${category}`] !== undefined ? `${key}.${category}` : `${key}.other`;
  return translate(lang, k, { n: formatNumber(lang, n), ...params });
}

const locale = (lang: Language): string => (lang === "ar" ? "ar-u-nu-latn" : "en");

export function formatNumber(lang: Language, n: number): string {
  return new Intl.NumberFormat(locale(lang)).format(n);
}

export function formatDate(lang: Language, unixSecs: number): string {
  return new Intl.DateTimeFormat(locale(lang), { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(unixSecs * 1000),
  );
}

export function formatDay(lang: Language, unixSecs: number): string {
  return new Intl.DateTimeFormat(locale(lang), { dateStyle: "medium" }).format(new Date(unixSecs * 1000));
}

const UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

/** Binary-scaled sizes with decimal-style unit labels, as Explorer shows them. */
export function formatBytes(lang: Language, bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = i === 0 ? 0 : v >= 100 ? 0 : v >= 10 ? 1 : 2;
  const num = new Intl.NumberFormat(locale(lang), { maximumFractionDigits: digits }).format(v);
  return `${num} ${translate(lang, `unit.${UNITS[i] ?? "B"}`)}`;
}

export function formatDuration(_lang: Language, secs: number): string {
  const s = Math.max(0, Math.round(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  const pad = (n: number): string => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(r)}` : `${m}:${pad(r)}`;
}

interface I18nState {
  lang: Language;
  setLang: (lang: Language) => void;
}

/** Applies language and direction to the document so Tailwind's logical utilities and the
 * native widgets (inputs, scrollbars, dialogs) all mirror with no reload. */
export function applyDocumentLanguage(lang: Language): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.lang = lang;
  root.dir = RTL_LANGUAGES.has(lang) ? "rtl" : "ltr";
}

export const useI18n = create<I18nState>((set) => ({
  lang: "en",
  setLang: (lang) => {
    applyDocumentLanguage(lang);
    set({ lang });
  },
}));

export interface Translator {
  lang: Language;
  dir: "ltr" | "rtl";
  t: (key: string, params?: Params) => string;
  tn: (key: string, n: number, params?: Params) => string;
  bytes: (n: number) => string;
  date: (unixSecs: number) => string;
  day: (unixSecs: number) => string;
  duration: (secs: number) => string;
  number: (n: number) => string;
}

export function makeTranslator(lang: Language): Translator {
  return {
    lang,
    dir: RTL_LANGUAGES.has(lang) ? "rtl" : "ltr",
    t: (key, params) => translate(lang, key, params),
    tn: (key, n, params) => translatePlural(lang, key, n, params),
    bytes: (n) => formatBytes(lang, n),
    date: (s) => formatDate(lang, s),
    day: (s) => formatDay(lang, s),
    duration: (s) => formatDuration(lang, s),
    number: (n) => formatNumber(lang, n),
  };
}

export function useT(): Translator {
  const lang = useI18n((s) => s.lang);
  return useMemo(() => makeTranslator(lang), [lang]);
}
