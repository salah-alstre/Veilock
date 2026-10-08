import { useState } from "react";
import { ChevronRight, DatabaseBackup, FolderLock, Lock, LockOpen, Plus, Star } from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { pickBundle } from "@/services/dialogs";
import { newOpId } from "@/utils/ids";
import { useNav } from "@/stores/nav";
import { useToasts } from "@/stores/toasts";
import { useLoad } from "@/hooks/useLoad";
import { Button } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { TextField } from "@/components/ui/Field";
import { Spinner } from "@/components/ui/Spinner";
import { Switch } from "@/components/ui/Switch";
import { OpProgress } from "@/components/shared/OpProgress";
import { PasswordPicker } from "@/components/shared/PasswordPicker";
import { RecoveryKeyDialog } from "@/components/shared/RecoveryKeyDialog";
import { emptyPick, pickReady, type PickerValue } from "@/components/shared/passwordSource";
import type { VaultView } from "@/types/api";

export function VaultsPage() {
  const { t, number, date } = useT();
  const go = useNav((s) => s.go);
  const list = useLoad(() => api.vaults.list(), []);
  const [actionError, setActionError] = useState<unknown>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [password, setPassword] = useState<PickerValue>(emptyPick());
  const [save, setSave] = useState(false);
  const [withRecovery, setWithRecovery] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<unknown>(null);
  const [recoveryKey, setRecoveryKey] = useState<{ key: string; name: string; id: string } | null>(null);

  const [importOp, setImportOp] = useState<string | null>(null);

  const vaults = list.data ?? [];

  const openCreate = (): void => {
    setName("");
    setDescription("");
    setPassword(emptyPick());
    setSave(false);
    setWithRecovery(false);
    setCreateError(null);
    setCreateOpen(true);
  };

  const canCreate = name.trim().length > 0 && pickReady(password, true) && !creating;

  const create = async (): Promise<void> => {
    setCreating(true);
    setCreateError(null);
    try {
      const out = await api.vaults.create({
        name: name.trim(),
        description: description.trim(),
        password: password.text,
        withRecovery,
        savePassword: save,
      });
      setPassword(emptyPick());
      setCreateOpen(false);
      await list.reload();
      useToasts.getState().push("success", t("vaults.created", { name: out.vault.name }));
      if (out.passwordSaveError) {
        useToasts.getState().push("error", t("vaults.saveFailed"));
      }
      if (out.recoveryKey) {
        setRecoveryKey({ key: out.recoveryKey, name: out.vault.name, id: out.vault.id });
      } else {
        go({ name: "vault", id: out.vault.id });
      }
    } catch (e) {
      setCreateError(e);
    } finally {
      setCreating(false);
    }
  };

  const importBundle = async (): Promise<void> => {
    setActionError(null);
    try {
      const bundle = await pickBundle();
      if (!bundle) return;
      const opId = newOpId();
      setImportOp(opId);
      try {
        const vault = await api.vaults.importBundle({ opId, bundle });
        await list.reload();
        useToasts.getState().push("success", t("vaults.imported", { name: vault.name }));
      } finally {
        setImportOp(null);
      }
    } catch (e) {
      setActionError(e);
    }
  };

  const toggleFavorite = async (v: VaultView): Promise<void> => {
    setActionError(null);
    try {
      await api.vaults.setFavorite(v.id, !v.favorite);
      await list.reload();
    } catch (e) {
      setActionError(e);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={t("vaults.title")}
        subtitle={t("vaults.subtitle")}
        actions={
          <>
            <Button
              variant="secondary"
              size="sm"
              disabled={importOp !== null}
              icon={<DatabaseBackup className="h-4 w-4" />}
              onClick={() => void importBundle()}
            >
              {t("vaults.import")}
            </Button>
            <Button variant="primary" size="sm" icon={<Plus className="h-4 w-4" />} onClick={openCreate}>
              {t("vaults.create")}
            </Button>
          </>
        }
      />

      {list.error ? <ErrorNotice error={list.error} /> : null}
      {actionError ? <ErrorNotice error={actionError} /> : null}

      {importOp ? (
        <div className="rounded-2xl border border-line bg-surface-1 p-4">
          <OpProgress opId={importOp} fallbackLabel={t("vaults.importing")} />
        </div>
      ) : null}

      {list.loading && !list.data ? (
        <div className="flex justify-center py-10">
          <Spinner className="h-5 w-5" />
        </div>
      ) : vaults.length === 0 && !list.error ? (
        <EmptyState
          icon={FolderLock}
          title={t("vaults.empty.title")}
          body={t("vaults.empty.body")}
          action={
            <Button variant="primary" icon={<Plus className="h-4 w-4" />} onClick={openCreate}>
              {t("vaults.create")}
            </Button>
          }
        />
      ) : (
        <ul className="flex flex-col gap-2">
          {vaults.map((v) => (
            <li
              key={v.id}
              className="flex items-center gap-3 rounded-2xl border border-line bg-surface-1 px-4 py-3 hover:bg-surface-2"
            >
              <span
                className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-surface-3 text-fg-muted"
                aria-hidden="true"
              >
                {v.unlocked ? <LockOpen className="h-5 w-5 text-ok" /> : <Lock className="h-5 w-5" />}
              </span>
              <button
                type="button"
                onClick={() => go({ name: "vault", id: v.id })}
                className="min-w-0 flex-1 text-start"
              >
                <span className="block truncate text-sm font-medium text-fg">{v.name}</span>
                <span className="block truncate text-xs text-fg-muted">
                  {v.unlocked
                    ? v.itemCount != null
                      ? t("vaults.itemCount", { n: number(v.itemCount) })
                      : t("vaults.unlocked")
                    : t("vaults.locked")}
                  {" · "}
                  {v.lastOpenedAt ? t("vaults.lastOpened", { date: date(v.lastOpenedAt) }) : t("vaults.neverOpened")}
                </span>
              </button>
              <button
                type="button"
                aria-pressed={v.favorite}
                aria-label={v.favorite ? t("item.unfavorite") : t("item.favorite")}
                title={v.favorite ? t("item.unfavorite") : t("item.favorite")}
                onClick={() => void toggleFavorite(v)}
                className="flex h-8 w-8 items-center justify-center rounded-lg text-fg-muted hover:bg-surface-3 hover:text-fg"
              >
                <Star className={v.favorite ? "h-4 w-4 fill-current text-warn" : "h-4 w-4"} aria-hidden="true" />
              </button>
              <ChevronRight className="h-4 w-4 shrink-0 text-fg-faint rtl:rotate-180" aria-hidden="true" />
            </li>
          ))}
        </ul>
      )}

      <Dialog
        open={createOpen}
        wide
        title={t("vaults.create")}
        description={t("vaults.createHint")}
        onClose={() => setCreateOpen(false)}
        dismissible={!creating}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={creating}>
              {t("common.cancel")}
            </Button>
            <Button variant="primary" busy={creating} disabled={!canCreate} onClick={() => void create()}>
              {t("vaults.create")}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <TextField
            label={t("vaults.name")}
            value={name}
            autoFocus
            maxLength={80}
            disabled={creating}
            onChange={(e) => setName(e.target.value)}
          />
          <TextField
            label={t("vaults.description")}
            value={description}
            maxLength={200}
            disabled={creating}
            onChange={(e) => setDescription(e.target.value)}
          />
          <PasswordPicker
            value={password}
            onChange={setPassword}
            kinds={["typed"]}
            confirm
            disabled={creating}
            save={save}
            onSaveChange={setSave}
          />
          <Switch
            checked={withRecovery}
            onChange={setWithRecovery}
            disabled={creating}
            label={t("vaults.recovery")}
            description={t("vaults.recoveryHint")}
          />
          {createError ? <ErrorNotice error={createError} /> : null}
        </div>
      </Dialog>

      <RecoveryKeyDialog
        recoveryKey={recoveryKey?.key ?? null}
        subject={recoveryKey?.name ?? ""}
        onClose={() => {
          const id = recoveryKey?.id;
          setRecoveryKey(null);
          if (id) go({ name: "vault", id });
        }}
      />
    </div>
  );
}
