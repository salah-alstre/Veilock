import { useEffect, useState } from "react";
import clsx from "clsx";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import type { StrengthLevel, StrengthReport } from "@/types/api";

const TONE: Record<StrengthLevel, string> = {
  very_weak: "bg-danger",
  weak: "bg-danger",
  medium: "bg-warn",
  strong: "bg-ok",
  very_strong: "bg-ok",
};

const SEGMENTS = [0, 1, 2, 3, 4] as const;

/** Fetches the estimate from the backend (one implementation, one set of thresholds). The
 * password is sent over the local IPC bridge only and is never stored or logged. */
export function useStrength(password: string): StrengthReport | null {
  const [report, setReport] = useState<StrengthReport | null>(null);
  useEffect(() => {
    if (password === "") {
      setReport(null);
      return;
    }
    let live = true;
    const timer = window.setTimeout(() => {
      api.tools
        .strength(password)
        .then((r) => {
          if (live) setReport(r);
        })
        .catch(() => {
          if (live) setReport(null);
        });
    }, 150);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [password]);
  return report;
}

export function StrengthMeter({ password }: { password: string }) {
  const { t } = useT();
  const report = useStrength(password);
  return (
    <div aria-live="polite" className="flex items-center gap-3">
      <div className="flex flex-1 gap-1" aria-hidden="true">
        {SEGMENTS.map((i) => (
          <span
            key={i}
            className={clsx(
              "h-1.5 flex-1 rounded-full transition-colors",
              report && i <= report.score ? TONE[report.level] : "bg-surface-4",
            )}
          />
        ))}
      </div>
      <span className="w-20 text-end text-xs text-fg-muted">
        {report ? t(`strength.${report.level}`) : ""}
      </span>
    </div>
  );
}
