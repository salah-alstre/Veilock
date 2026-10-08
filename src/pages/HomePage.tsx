import { FolderLock, KeyRound, LockOpen, ShieldCheck, Star } from "lucide-react";
import type { ComponentType } from "react";
import branding from "@branding";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useApp } from "@/stores/app";
import { useNav } from "@/stores/nav";
import { useLoad } from "@/hooks/useLoad";
import { pickContainers } from "@/services/dialogs";
import { Card, PageHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { ItemList, ItemRow } from "@/components/shared/ItemList";

function Stat({
  icon: Icon,
  label,
  value,
  onClick,
}: {
  icon: ComponentType<{ className?: string }>;
  label: string;
  value: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-3 rounded-2xl border border-line bg-surface-1 p-4 text-start transition-colors hover:bg-surface-2"
    >
      <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-surface-3 text-fg-muted">
        <Icon className="h-5 w-5" aria-hidden="true" />
      </span>
      <span>
        <span className="block text-lg font-semibold tabular-nums text-fg">{value}</span>
        <span className="block text-xs text-fg-muted">{label}</span>
      </span>
    </button>
  );
}

export function HomePage() {
  const { t, number } = useT();
  const go = useNav((s) => s.go);
  const stageUnlock = useNav((s) => s.stageUnlock);
  const status = useApp((s) => s.status);

  const data = useLoad(async () => {
    const [recent, favorites, vaults] = await Promise.all([
      api.items.recent(100),
      api.items.favorites(),
      api.vaults.list(),
    ]);
    return { recent, favorites, vaults };
  }, []);

  const chooseToUnlock = async (): Promise<void> => {
    const picked = await pickContainers();
    if (picked.length > 0) stageUnlock(picked);
  };

  const d = data.data;
  const unlockedCount = status?.unlockedVaults.length ?? 0;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={branding.appName} subtitle={t("home.subtitle")} />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Card className="flex flex-col gap-3">
          <ShieldCheck className="h-6 w-6 text-accent" aria-hidden="true" />
          <div>
            <h2 className="text-base font-semibold text-fg">{t("home.protect.title")}</h2>
            <p className="mt-1 text-sm text-fg-muted">{t("home.protect.body")}</p>
          </div>
          <div>
            <Button variant="primary" onClick={() => go({ name: "protect" })}>
              {t("home.protect.action")}
            </Button>
          </div>
        </Card>
        <Card className="flex flex-col gap-3">
          <LockOpen className="h-6 w-6 text-accent" aria-hidden="true" />
          <div>
            <h2 className="text-base font-semibold text-fg">{t("home.unlock.title")}</h2>
            <p className="mt-1 text-sm text-fg-muted">{t("home.unlock.body")}</p>
          </div>
          <div>
            <Button variant="secondary" onClick={() => void chooseToUnlock()}>
              {t("home.unlock.action")}
            </Button>
          </div>
        </Card>
      </div>

      {data.error ? <ErrorNotice error={data.error} /> : null}

      {d ? (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat
            icon={ShieldCheck}
            label={t("home.stat.items")}
            value={number(d.recent.length)}
            onClick={() => go({ name: "recent" })}
          />
          <Stat
            icon={FolderLock}
            label={t("home.stat.vaults")}
            value={number(d.vaults.length)}
            onClick={() => go({ name: "vaults" })}
          />
          <Stat
            icon={LockOpen}
            label={t("home.stat.unlocked")}
            value={number(unlockedCount)}
            onClick={() => go({ name: "vaults" })}
          />
          <Stat
            icon={Star}
            label={t("home.stat.favorites")}
            value={number(d.favorites.length)}
            onClick={() => go({ name: "favorites" })}
          />
        </div>
      ) : null}

      <section aria-labelledby="home-recent" className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h2 id="home-recent" className="text-sm font-semibold text-fg">
            {t("home.recent")}
          </h2>
          <Button size="sm" variant="ghost" onClick={() => go({ name: "recent" })}>
            {t("home.viewAll")}
          </Button>
        </div>
        {d && d.recent.length === 0 ? (
          <EmptyState
            icon={KeyRound}
            title={t("home.empty.title")}
            body={t("home.empty.body")}
            action={
              <Button variant="primary" onClick={() => go({ name: "protect" })}>
                {t("home.protect.action")}
              </Button>
            }
          />
        ) : d ? (
          <ItemList>
            {d.recent.slice(0, 5).map((item) => (
              <ItemRow key={item.id} item={item} onOpen={(i) => go({ name: "item", id: i.id })} />
            ))}
          </ItemList>
        ) : null}
      </section>
    </div>
  );
}
