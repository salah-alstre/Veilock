import type { ReactNode } from "react";
import { FileLock2, FolderLock, Star } from "lucide-react";
import clsx from "clsx";
import { useT } from "@/i18n";
import type { ItemDetail } from "@/types/api";

interface ItemRowProps {
  item: ItemDetail;
  onOpen: (item: ItemDetail) => void;
  onToggleFavorite?: (item: ItemDetail) => void;
  actions?: ReactNode;
}

/** One protected item. The "missing" badge is computed by Rust (`exists`), not guessed here. */
export function ItemRow({ item, onOpen, onToggleFavorite, actions }: ItemRowProps) {
  const { t, bytes, date } = useT();
  const Icon = item.kind === "folder" ? FolderLock : FileLock2;
  const when = item.lastOpenedAt ?? item.createdAt;

  return (
    <li className="flex items-center gap-3 rounded-xl border border-line bg-surface-1 px-3 py-2.5 transition-colors hover:bg-surface-2">
      <button
        type="button"
        onClick={() => onOpen(item)}
        className="flex min-w-0 flex-1 items-center gap-3 text-start"
      >
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-surface-3 text-fg-muted">
          <Icon className="h-[18px] w-[18px]" aria-hidden="true" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-fg">{item.name}</span>
          <span className="block truncate text-xs text-fg-muted">
            {t(`item.kind.${item.kind}`)} · {bytes(item.originalSize)} · {date(when)}
          </span>
        </span>
        {item.exists ? null : (
          <span className="shrink-0 rounded-md bg-warn/15 px-2 py-0.5 text-xs text-warn">
            {t("item.missing")}
          </span>
        )}
      </button>
      {actions}
      {onToggleFavorite ? (
        <button
          type="button"
          onClick={() => onToggleFavorite(item)}
          aria-pressed={item.favorite}
          aria-label={item.favorite ? t("item.unfavorite") : t("item.favorite")}
          title={item.favorite ? t("item.unfavorite") : t("item.favorite")}
          className={clsx(
            "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-colors hover:bg-surface-3",
            item.favorite ? "text-warn" : "text-fg-faint hover:text-fg",
          )}
        >
          <Star className={clsx("h-4 w-4", item.favorite && "fill-current")} aria-hidden="true" />
        </button>
      ) : null}
    </li>
  );
}

export function ItemList({ children }: { children: ReactNode }) {
  return <ul className="flex flex-col gap-2">{children}</ul>;
}
