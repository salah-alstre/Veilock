import { useState } from "react";
import { AlertCircle, ChevronDown } from "lucide-react";
import clsx from "clsx";
import { useT } from "@/i18n";
import { toAppError } from "@/services/errors";

/** Human text for any rejected value. Always derived from the stable code. */
export function useErrorText(): (e: unknown) => string {
  const { t } = useT();
  return (e) => t(`error.${toAppError(e).code}`);
}

interface ErrorNoticeProps {
  error: unknown;
  className?: string;
}

/** Inline error with the technical detail folded away behind "Show details". */
export function ErrorNotice({ error, className }: ErrorNoticeProps) {
  const { t } = useT();
  const [open, setOpen] = useState(false);
  const err = toAppError(error);
  return (
    <div
      role="alert"
      className={clsx("rounded-xl border border-danger/40 bg-danger/10 px-4 py-3 text-sm", className)}
    >
      <div className="flex items-start gap-2.5">
        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden="true" />
        <p className="min-w-0 flex-1 text-fg">{t(`error.${err.code}`)}</p>
      </div>
      {err.details ? (
        <div className="mt-2 ps-6">
          <button
            type="button"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
            className="flex items-center gap-1 text-xs text-fg-muted hover:text-fg"
          >
            <ChevronDown className={clsx("h-3 w-3 transition-transform", open && "rotate-180")} />
            {open ? t("error.hideDetails") : t("error.showDetails")}
          </button>
          {open ? (
            <p className="ltr-text selectable mt-1.5 break-words rounded-lg bg-surface-2 px-3 py-2 font-mono text-xs text-fg-muted">
              {err.code}: {err.details}
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
