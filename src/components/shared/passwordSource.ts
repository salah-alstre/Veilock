import type { PasswordSource } from "@/types/api";
import { useApp } from "@/stores/app";

export type PickKind = "typed" | "saved" | "default" | "recovery";

/** Form state behind a password selector. Lives only in component state, never in a store. */
export interface PickerValue {
  kind: PickKind;
  text: string;
  confirm: string;
}

export const emptyPick = (kind: PickKind = "typed"): PickerValue => ({ kind, text: "", confirm: "" });

/** Whether the selection is complete enough to submit. */
export function pickReady(v: PickerValue, needConfirm: boolean): boolean {
  switch (v.kind) {
    case "typed":
      return v.text !== "" && (!needConfirm || v.text === v.confirm);
    case "recovery":
      return v.text.trim() !== "";
    default:
      return true;
  }
}

export function toSource(v: PickerValue): PasswordSource {
  switch (v.kind) {
    case "typed":
      return { kind: "typed", password: v.text };
    case "recovery":
      return { kind: "recovery", key: v.text.trim() };
    case "saved":
      return { kind: "saved" };
    case "default":
      return { kind: "default" };
  }
}

/** The default password needs the master password to be re-entered in "require master" mode. */
export function needsMasterForSource(v: PickerValue): boolean {
  const status = useApp.getState().status;
  return (
    v.kind === "default" &&
    !!status?.masterExists &&
    status.settings.encryption.defaultPasswordMode === "require_master"
  );
}

/** Saving a typed password requires the credential vault to be open. */
export function canSavePasswords(): boolean {
  const status = useApp.getState().status;
  return !!status?.masterExists && status.lockPhase === "unlocked";
}
