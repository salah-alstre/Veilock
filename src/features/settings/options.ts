/** Choice lists shared by Onboarding and Settings. Values are strings because the native
 * <select> deals in strings; `null` ("never") is encoded as "never". */

export const AUTO_LOCK_CHOICES: ReadonlyArray<{ value: string; secs: number | null; key: string }> = [
  { value: "0", secs: 0, key: "autolock.immediately" },
  { value: "60", secs: 60, key: "autolock.m1" },
  { value: "300", secs: 300, key: "autolock.m5" },
  { value: "600", secs: 600, key: "autolock.m10" },
  { value: "1800", secs: 1800, key: "autolock.m30" },
  { value: "never", secs: null, key: "autolock.never" },
];

export const CLIPBOARD_CHOICES: ReadonlyArray<{ value: string; secs: number | null; key: string }> = [
  { value: "10", secs: 10, key: "clipboard.s10" },
  { value: "30", secs: 30, key: "clipboard.s30" },
  { value: "60", secs: 60, key: "clipboard.s60" },
  { value: "never", secs: null, key: "clipboard.never" },
];

export const BACKGROUND_LOCK_CHOICES: ReadonlyArray<{ value: string; minutes: number | null; key: string }> = [
  { value: "1", minutes: 1, key: "autolock.m1" },
  { value: "5", minutes: 5, key: "autolock.m5" },
  { value: "10", minutes: 10, key: "autolock.m10" },
  { value: "30", minutes: 30, key: "autolock.m30" },
  { value: "never", minutes: null, key: "autolock.never" },
];

export function secsToChoice(
  list: ReadonlyArray<{ value: string; secs: number | null }>,
  secs: number | null,
): string {
  const hit = list.find((c) => c.secs === secs);
  // An unlisted value (hand-edited config) falls back to the shipped default entry for display.
  return hit ? hit.value : (list.find((c) => c.value === "300" || c.value === "30")?.value ?? "never");
}

export function choiceToSecs(
  list: ReadonlyArray<{ value: string; secs: number | null }>,
  value: string,
): number | null {
  return list.find((c) => c.value === value)?.secs ?? null;
}
