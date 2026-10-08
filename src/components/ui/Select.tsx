import { useId } from "react";
import { ChevronDown } from "lucide-react";
import clsx from "clsx";

export interface SelectOption<V extends string> {
  value: V;
  label: string;
}

interface SelectProps<V extends string> {
  value: V;
  options: ReadonlyArray<SelectOption<V>>;
  onChange: (next: V) => void;
  label: string;
  /** Show the label above the control (forms) instead of visually hiding it (settings rows). */
  showLabel?: boolean;
  disabled?: boolean;
  className?: string;
}

/** A native <select>: keyboard, screen-reader and RTL behaviour come from the platform. */
export function Select<V extends string>({
  value,
  options,
  onChange,
  label,
  showLabel,
  disabled,
  className,
}: SelectProps<V>) {
  const id = useId();
  return (
    <div className={clsx("flex flex-col gap-1.5", className)}>
      <label htmlFor={id} className={showLabel ? "text-[13px] font-medium text-fg-muted" : "sr-only"}>
        {label}
      </label>
      <div className="relative">
        <select
          id={id}
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value as V)}
          className="h-10 w-full appearance-none rounded-xl border border-line bg-surface-2 ps-3 pe-9 text-sm text-fg transition-colors hover:border-fg-faint focus:border-accent disabled:opacity-50"
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <ChevronDown
          aria-hidden="true"
          className="pointer-events-none absolute end-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint"
        />
      </div>
    </div>
  );
}
