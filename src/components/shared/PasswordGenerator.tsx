import { useCallback, useEffect, useRef, useState } from "react";
import { Copy, RefreshCw } from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useApp } from "@/stores/app";
import { useToasts } from "@/stores/toasts";
import { useErrorText } from "@/components/ui/ErrorNotice";
import { Button } from "@/components/ui/Button";
import { StrengthMeter } from "@/components/ui/StrengthMeter";
import { Switch } from "@/components/ui/Switch";
import type { GeneratorRequest } from "@/types/api";

interface PasswordGeneratorProps {
  /** Called with the generated password when the user chooses to use it. */
  onUse?: (password: string) => void;
}

/** Generation happens in Rust (OS CSPRNG); this only edits the options and displays the result. */
export function PasswordGenerator({ onUse }: PasswordGeneratorProps) {
  const { t, number } = useT();
  const errorText = useErrorText();
  const defaults = useApp((s) => s.status?.settings.passwords);
  const [req, setReq] = useState<GeneratorRequest>({
    length: defaults?.generatorLength ?? 20,
    upper: defaults?.generatorUpper ?? true,
    lower: defaults?.generatorLower ?? true,
    digits: defaults?.generatorDigits ?? true,
    symbols: defaults?.generatorSymbols ?? true,
    avoidAmbiguous: defaults?.generatorAvoidAmbiguous ?? true,
  });
  const [value, setValue] = useState("");

  // `errorText` is a new function every render; keep the latest in a ref so `generate` is stable.
  const errorTextRef = useRef(errorText);
  errorTextRef.current = errorText;

  const generate = useCallback(async (r: GeneratorRequest): Promise<void> => {
    try {
      setValue(await api.tools.generate(r));
    } catch (e) {
      setValue("");
      useToasts.getState().push("error", errorTextRef.current(e));
    }
  }, []);

  useEffect(() => {
    void generate(req);
  }, [req, generate]);

  const classes = [req.upper, req.lower, req.digits, req.symbols].filter(Boolean).length;
  const toggle = (key: "upper" | "lower" | "digits" | "symbols") => (next: boolean) => {
    // At least one character class must stay on, otherwise there is nothing to generate from.
    if (!next && classes <= 1) return;
    setReq((r) => ({ ...r, [key]: next }));
  };

  const copy = async (): Promise<void> => {
    try {
      await api.tools.copy(value);
      useToasts.getState().push("success", t("generator.copied"));
    } catch (e) {
      useToasts.getState().push("error", errorText(e));
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 rounded-xl border border-line bg-surface-2 p-3">
        <p className="ltr-text selectable min-w-0 flex-1 break-all font-mono text-sm text-fg">{value}</p>
        <Button
          size="sm"
          variant="ghost"
          aria-label={t("generator.regenerate")}
          title={t("generator.regenerate")}
          icon={<RefreshCw className="h-4 w-4" />}
          onClick={() => void generate(req)}
        />
        <Button
          size="sm"
          variant="ghost"
          aria-label={t("common.copy")}
          title={t("common.copy")}
          icon={<Copy className="h-4 w-4" />}
          disabled={value === ""}
          onClick={() => void copy()}
        />
      </div>
      <StrengthMeter password={value} />

      <div className="flex flex-col gap-2">
        <label htmlFor="gen-length" className="flex items-center justify-between text-[13px] font-medium text-fg-muted">
          <span>{t("generator.length")}</span>
          <span className="tabular-nums text-fg">{number(req.length)}</span>
        </label>
        <input
          id="gen-length"
          type="range"
          min={8}
          max={64}
          value={req.length}
          onChange={(e) => setReq((r) => ({ ...r, length: Number(e.target.value) }))}
          className="w-full accent-accent"
        />
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <Switch checked={req.upper} onChange={toggle("upper")} label={t("generator.upper")} />
        <Switch checked={req.lower} onChange={toggle("lower")} label={t("generator.lower")} />
        <Switch checked={req.digits} onChange={toggle("digits")} label={t("generator.digits")} />
        <Switch checked={req.symbols} onChange={toggle("symbols")} label={t("generator.symbols")} />
        <Switch
          checked={req.avoidAmbiguous}
          onChange={(v) => setReq((r) => ({ ...r, avoidAmbiguous: v }))}
          label={t("generator.ambiguous")}
        />
      </div>

      {onUse ? (
        <div>
          <Button variant="primary" disabled={value === ""} onClick={() => onUse(value)}>
            {t("generator.use")}
          </Button>
        </div>
      ) : null}
    </div>
  );
}
