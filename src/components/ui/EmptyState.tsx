import type { ComponentType, ReactNode } from "react";

interface EmptyStateProps {
  icon: ComponentType<{ className?: string }>;
  title: string;
  body?: string;
  action?: ReactNode;
}

export function EmptyState({ icon: Icon, title, body, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-2xl border border-dashed border-line px-6 py-14 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-3 text-fg-muted">
        <Icon className="h-6 w-6" />
      </div>
      <h2 className="text-sm font-medium text-fg">{title}</h2>
      {body ? <p className="max-w-sm text-sm text-fg-muted">{body}</p> : null}
      {action}
    </div>
  );
}
