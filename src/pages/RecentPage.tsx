import { useState } from "react";
import { Clock, Trash2 } from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useNav } from "@/stores/nav";
import { useLoad } from "@/hooks/useLoad";
import { Button } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { Spinner } from "@/components/ui/Spinner";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { ItemList, ItemRow } from "@/components/shared/ItemList";
import type { ItemDetail } from "@/types/api";

export function RecentPage() {
  const { t } = useT();
  const go = useNav((s) => s.go);
  const list = useLoad(() => api.items.recent(200), []);
  const [actionError, setActionError] = useState<unknown>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const toggle = async (item: ItemDetail): Promise<void> => {
    setActionError(null);
    try {
      await api.items.setFavorite(item.id, !item.favorite);
      await list.reload();
    } catch (e) {
      setActionError(e);
    }
  };

  const items = list.data ?? [];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={t("recent.title")}
        subtitle={t("recent.subtitle")}
        actions={
          items.length > 0 ? (
            <Button
              size="sm"
              variant="secondary"
              icon={<Trash2 className="h-4 w-4" />}
              onClick={() => setConfirmClear(true)}
            >
              {t("recent.clear")}
            </Button>
          ) : null
        }
      />

      {list.error ? <ErrorNotice error={list.error} /> : null}
      {actionError ? <ErrorNotice error={actionError} /> : null}

      {list.loading && !list.data ? (
        <div className="flex justify-center py-10">
          <Spinner className="h-5 w-5" />
        </div>
      ) : items.length === 0 && !list.error ? (
        <EmptyState icon={Clock} title={t("recent.empty.title")} body={t("recent.empty.body")} />
      ) : (
        <ItemList>
          {items.map((item) => (
            <ItemRow
              key={item.id}
              item={item}
              onOpen={(i) => go({ name: "item", id: i.id })}
              onToggleFavorite={(i) => void toggle(i)}
            />
          ))}
        </ItemList>
      )}

      <ConfirmDialog
        open={confirmClear}
        title={t("recent.clear")}
        body={t("recent.clearBody")}
        confirmLabel={t("recent.clear")}
        danger
        onClose={() => setConfirmClear(false)}
        onConfirm={async () => {
          await api.items.clearRecent();
          await list.reload();
          setConfirmClear(false);
        }}
      />
    </div>
  );
}
