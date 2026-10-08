import { useEffect, useState } from "react";
import clsx from "clsx";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useApp } from "@/stores/app";
import { PasswordField, TextField } from "@/components/ui/Field";
import { StrengthMeter } from "@/components/ui/StrengthMeter";
import { Switch } from "@/components/ui/Switch";
import { canSavePasswords, type PickerValue, type PickKind } from "./passwordSource";

interface PasswordPickerProps {
  value: PickerValue;
  onChange: (next: PickerValue) => void;
  /** Which sources the caller can accept, in display order. */
  kinds: PickKind[];
  /** Ask for the typed password twice and show its strength (creating a new password). */
  confirm?: boolean;
  disabled?: boolean;
  /** "Remember this password" switch; shown only when provided. */
  save?: boolean;
  onSaveChange?: (next: boolean) => void;
  label?: string;
}

function useDefaultConfigured(enabled: boolean): boolean {
  const [configured, setConfigured] = useState(false);
  const phase = useApp((s) => s.status?.lockPhase);
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    api.app
      .defaultPasswordConfigured()
      .then((c) => live && setConfigured(c))
      .catch(() => live && setConfigured(false));
    return () => {
      live = false;
    };
  }, [enabled, phase]);
  return configured;
}

/**
 * One control for every way of supplying a password: typed, saved, default or recovery key. Only
 * the secret text it edits is kept in the parent's state; nothing is persisted here.
 */
export function PasswordPicker({
  value,
  onChange,
  kinds,
  confirm,
  disabled,
  save,
  onSaveChange,
  label,
}: PasswordPickerProps) {
  const { t } = useT();
  const defaultConfigured = useDefaultConfigured(kinds.includes("default"));
  const canSave = useApp((s) => !!s.status?.masterExists && s.status.lockPhase === "unlocked");

  const shown = kinds.filter((k) => k !== "default" || defaultConfigured);
  const selected = shown.includes(value.kind) ? value.kind : (shown[0] ?? "typed");
  useEffect(() => {
    if (selected !== value.kind) onChange({ kind: selected, text: "", confirm: "" });
  }, [selected, value.kind, onChange]);

  const mismatch = confirm && value.confirm !== "" && value.text !== value.confirm;

  return (
    <div className="flex flex-col gap-3">
      {shown.length > 1 ? (
        <div role="radiogroup" aria-label={label ?? t("picker.label")} className="flex flex-wrap gap-1.5">
          {shown.map((k) => (
            <button
              key={k}
              type="button"
              role="radio"
              aria-checked={selected === k}
              disabled={disabled}
              onClick={() => onChange({ kind: k, text: "", confirm: "" })}
              className={clsx(
                "rounded-lg border px-3 py-1.5 text-sm transition-colors",
                selected === k
                  ? "border-accent bg-accent-soft text-accent"
                  : "border-line text-fg-muted hover:bg-surface-3 hover:text-fg",
              )}
            >
              {t(`picker.${k}`)}
            </button>
          ))}
        </div>
      ) : null}

      {selected === "typed" ? (
        <>
          <PasswordField
            label={label ?? t("picker.password")}
            value={value.text}
            onChange={(e) => onChange({ ...value, text: e.target.value })}
            disabled={disabled}
          />
          {confirm ? (
            <>
              <StrengthMeter password={value.text} />
              <PasswordField
                label={t("picker.confirm")}
                value={value.confirm}
                onChange={(e) => onChange({ ...value, confirm: e.target.value })}
                error={mismatch ? t("picker.mismatch") : undefined}
                disabled={disabled}
              />
            </>
          ) : null}
        </>
      ) : null}

      {selected === "recovery" ? (
        <TextField
          label={t("picker.recoveryKey")}
          hint={t("picker.recoveryHint")}
          ltr
          value={value.text}
          onChange={(e) => onChange({ ...value, text: e.target.value })}
          disabled={disabled}
          autoComplete="off"
          spellCheck={false}
        />
      ) : null}

      {selected === "saved" ? <p className="text-sm text-fg-muted">{t("picker.savedHint")}</p> : null}
      {selected === "default" ? (
        <p className="text-sm text-fg-muted">{t("picker.defaultHint")}</p>
      ) : null}

      {onSaveChange && selected === "typed" ? (
        <Switch
          checked={!!save && canSave}
          onChange={onSaveChange}
          disabled={disabled || !canSave || !canSavePasswords()}
          label={t("picker.save")}
          description={canSave ? t("picker.saveHint") : t("picker.saveUnavailable")}
        />
      ) : null}
    </div>
  );
}
