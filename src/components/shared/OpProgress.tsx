import { X } from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { baseName } from "@/utils/ids";
import { useOps } from "@/stores/ops";
import { Button } from "@/components/ui/Button";
import { ProgressBar } from "@/components/ui/ProgressBar";

interface OpProgressProps {
  opId: string;
  /** Shown before the first progress event arrives (the job is queued in Rust). */
  fallbackLabel?: string;
  cancellable?: boolean;
}

/**
 * Live progress of one backend job. Everything shown comes from `veilock://progress` events
 * emitted by the Rust worker; cancelling asks Rust to stop and the job ends with CANCELLED.
 */
export function OpProgress({ opId, fallbackLabel, cancellable = true }: OpProgressProps) {
  const { t, bytes, duration, number } = useT();
  const p = useOps((s) => s.progress[opId]);

  const fraction = p && p.totalBytes > 0 ? p.doneBytes / p.totalBytes : null;
  const label = p ? t(`progress.phase.${p.phase}`) : (fallbackLabel ?? t("progress.starting"));

  return (
    <div className="flex flex-col gap-3" aria-live="polite">
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="font-medium text-fg">{label}</span>
        {fraction !== null ? (
          <span className="text-fg-muted tabular-nums">{number(Math.round(fraction * 100))}%</span>
        ) : null}
      </div>
      <ProgressBar value={fraction} label={label} />
      {p ? (
        <div className="flex flex-col gap-1 text-xs text-fg-muted">
          {p.currentItem ? (
            <span className="ltr-text truncate" title={p.currentItem}>
              {p.itemCount > 1
                ? t("progress.item", { i: number(p.itemIndex + 1), n: number(p.itemCount) }) + " · "
                : ""}
              {baseName(p.currentItem)}
            </span>
          ) : null}
          <span className="tabular-nums">
            {bytes(p.doneBytes)} / {bytes(p.totalBytes)}
            {p.bytesPerSec > 0 ? ` · ${bytes(p.bytesPerSec)}/${t("progress.sec")}` : ""}
            {p.etaSecs != null && p.etaSecs > 0
              ? ` · ${t("progress.eta", { time: duration(p.etaSecs) })}`
              : ""}
          </span>
        </div>
      ) : null}
      {cancellable ? (
        <div>
          <Button
            size="sm"
            variant="ghost"
            icon={<X className="h-4 w-4" />}
            onClick={() => void api.app.cancelOp(opId).catch(() => undefined)}
          >
            {t("common.cancel")}
          </Button>
        </div>
      ) : null}
    </div>
  );
}
