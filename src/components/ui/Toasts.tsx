import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";
import clsx from "clsx";
import { useT } from "@/i18n";
import { useToasts, type ToastKind } from "@/stores/toasts";

const ICONS: Record<ToastKind, typeof Info> = { info: Info, success: CheckCircle2, error: AlertCircle };
const TONES: Record<ToastKind, string> = { info: "text-accent", success: "text-ok", error: "text-danger" };

export function Toasts() {
  const { t } = useT();
  const toasts = useToasts((s) => s.toasts);
  const dismiss = useToasts((s) => s.dismiss);
  return (
    <div
      aria-live="polite"
      className="pointer-events-none fixed bottom-4 end-4 z-[60] flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2"
    >
      {toasts.map((toast) => {
        const Icon = ICONS[toast.kind];
        return (
          <div
            key={toast.id}
            role={toast.kind === "error" ? "alert" : "status"}
            className="pointer-events-auto flex animate-rise-in items-start gap-3 rounded-xl border border-line bg-surface-3 px-4 py-3 shadow-lg"
          >
            <Icon className={clsx("mt-0.5 h-4 w-4 shrink-0", TONES[toast.kind])} aria-hidden="true" />
            <p className="min-w-0 flex-1 text-sm text-fg">{toast.message}</p>
            <button
              type="button"
              aria-label={t("common.dismiss")}
              onClick={() => dismiss(toast.id)}
              className="text-fg-faint hover:text-fg"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
