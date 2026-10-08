import clsx from "clsx";

interface ProgressBarProps {
  /** 0..1, or null for an indeterminate bar (work whose total is not known yet). */
  value: number | null;
  label: string;
  className?: string;
}

export function ProgressBar({ value, label, className }: ProgressBarProps) {
  const pct = value === null ? null : Math.max(0, Math.min(1, value)) * 100;
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={pct === null ? undefined : Math.round(pct)}
      className={clsx("h-2 w-full overflow-hidden rounded-full bg-surface-4", className)}
    >
      <div
        className={clsx("h-full rounded-full bg-accent", pct === null ? "w-1/3 animate-pulse" : "transition-[width] duration-150")}
        style={pct === null ? undefined : { width: `${pct}%` }}
      />
    </div>
  );
}
