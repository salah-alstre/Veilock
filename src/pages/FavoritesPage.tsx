import { useState } from "react";
import { Star } from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useNav } from "@/stores/nav";
import { useLoad } from "@/hooks/useLoad";
import { PageHeader } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { Spinner } from "@/components/ui/Spinner";
import { ItemList, ItemRow } from "@/components/shared/ItemList";
import type { ItemDetail, VaultView } from "@/types/api";

export function FavoritesPage() {
  const { t } = useT();
  const go = useNav((s) => s.go);
  const data = useLoad(async () => {
    const [items, vaults] = await Promise.all([api.items.favorites(), api.vaults.list()]);
    return { items, vaults: vaults.filter((v) => v.favorite) };
  }, []);
  const [actionError, setActionError] = useState<unknown>(null);

  const unfavoriteItem = async (item: ItemDetail): Promise<void> => {
    setActionError(null);
    try {
      await api.items.setFavorite(item.id, false);
      await data.reload();
    } catch (e) {
      setActionError(e);
    }
  };

  const unfavoriteVault = async (vault: VaultView): Promise<void> => {
    setActionError(null);
    try {
      await api.vaults.setFavorite(vault.id, false);
      await data.reload();
    } catch (e) {
      setActionError(e);
    }
  };

  const d = data.data;
  const empty = d !== null && d.items.length === 0 && d.vaults.length === 0;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={t("favorites.title")} subtitle={t("favorites.subtitle")} />

      {data.error ? <ErrorNotice error={data.error} /> : null}
      {actionError ? <ErrorNotice error={actionError} /> : null}

      {data.loading && !d ? (
        <div className="flex justify-center py-10">
          <Spinner className="h-5 w-5" />
        </div>
      ) : empty ? (
        <EmptyState icon={Star} title={t("favorites.empty.title")} body={t("favorites.empty.body")} />
      ) : d ? (
        <>
          {d.vaults.length > 0 ? (
            <section className="flex flex-col gap-2" aria-labelledby="fav-vaults">
              <h2 id="fav-vaults" className="text-sm font-semibold text-fg">
                {t("favorites.vaults")}
              </h2>
              <ul className="flex flex-col gap-2">
                {d.vaults.map((v) => (
                  <li
                    key={v.id}
                    className="flex items-center gap-3 rounded-xl border border-line bg-surface-1 px-3 py-2.5 hover:bg-surface-2"
                  >
                    <button
                      type="button"
                      onClick={() => go({ name: "vault", id: v.id })}
                      className="min-w-0 flex-1 truncate text-start text-sm font-medium text-fg"
                    >
                      {v.name}
                    </button>
                    <button
                      type="button"
                      aria-pressed
                      aria-label={t("item.unfavorite")}
                      title={t("item.unfavorite")}
                      onClick={() => void unfavoriteVault(v)}
                      className="flex h-8 w-8 items-center justify-center rounded-lg text-warn hover:bg-surface-3"
                    >
                      <Star className="h-4 w-4 fill-current" aria-hidden="true" />
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
          {d.items.length > 0 ? (
            <section className="flex flex-col gap-2" aria-labelledby="fav-items">
              <h2 id="fav-items" className="text-sm font-semibold text-fg">
                {t("favorites.items")}
              </h2>
              <ItemList>
                {d.items.map((item) => (
                  <ItemRow
                    key={item.id}
                    item={item}
                    onOpen={(i) => go({ name: "item", id: i.id })}
                    onToggleFavorite={(i) => void unfavoriteItem(i)}
                  />
                ))}
              </ItemList>
            </section>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
