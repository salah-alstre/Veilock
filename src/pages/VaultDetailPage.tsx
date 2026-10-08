import { useState } from "react";
import {
  DatabaseBackup,
  FileLock2,
  FilePlus2,
  FolderLock,
  FolderPlus,
  KeyRound,
  LifeBuoy,
  Lock,
  LockOpen,
  Pencil,
  Star,
  Trash2,
  Upload,
} from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { pickDirectory, pickFiles, pickFolders } from "@/services/dialogs";
import { newOpId } from "@/utils/ids";
import { useNav } from "@/stores/nav";
import { useToasts } from "@/stores/toasts";
import { useLoad } from "@/hooks/useLoad";
import { Button } from "@/components/ui/Button";
import { Card, PageHeader } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { TextField } from "@/components/ui/Field";
import { Select } from "@/components/ui/Select";
import { Spinner } from "@/components/ui/Spinner";
import { Switch } from "@/components/ui/Switch";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { ChangePasswordDialog, RecoveryDialog } from "@/components/shared/CredentialDialogs";
import { OpProgress } from "@/components/shared/OpProgress";
import { PasswordPicker } from "@/components/shared/PasswordPicker";
import { useMasterGate } from "@/components/shared/useMasterGate";
import {
  emptyPick,
  needsMasterForSource,
  pickReady,
  toSource,
  type PickerValue,
} from "@/components/shared/passwordSource";
import { toAppError } from "@/services/errors";
import type { AddToVaultResult, ConflictPolicy, VaultItemView, VaultView } from "@/types/api";

interface UnlockFormProps {
  vault: VaultView;
  onUnlocked: () => void;
}

function UnlockForm({ vault, onUnlocked }: UnlockFormProps) {
  const { t } = useT();
  const gate = useMasterGate();
  const [pick, setPick] = useState<PickerValue>(emptyPick(vault.hasSavedPassword ? "saved" : "typed"));
  const [save, setSave] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const kinds = [
    ...(vault.hasSavedPassword ? (["saved"] as const) : []),
    "typed" as const,
    "default" as const,
    ...(vault.hasRecovery ? (["recovery"] as const) : []),
  ];

  const submit = async (): Promise<void> => {
    setError(null);
    const master = needsMasterForSource(pick) ? await gate.ask("always") : undefined;
    if (master === null) return;
    setBusy(true);
    try {
      const out = await api.vaults.unlock({
        id: vault.id,
        password: toSource(pick),
        master,
        savePassword: save && pick.kind === "typed",
      });
      setPick(emptyPick());
      if (out.passwordSaveError) useToasts.getState().push("error", t("vaults.saveFailed"));
      onUnlocked();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="flex max-w-xl flex-col gap-4">
      <div>
        <h2 className="text-sm font-semibold text-fg">{t("vault.unlockTitle")}</h2>
        <p className="mt-1 text-sm text-fg-muted">{t("vault.unlockBody")}</p>
      </div>
      <PasswordPicker
        value={pick}
        onChange={setPick}
        kinds={kinds}
        disabled={busy}
        save={save}
        onSaveChange={setSave}
      />
      {error ? <ErrorNotice error={error} /> : null}
      <div>
        <Button
          variant="primary"
          busy={busy}
          disabled={!pickReady(pick, false) || busy}
          icon={<LockOpen className="h-4 w-4" />}
          onClick={() => void submit()}
        >
          {t("vault.unlock")}
        </Button>
      </div>
      {gate.dialog}
    </Card>
  );
}

export function VaultDetailPage({ id }: { id: string }) {
  const { t, bytes, date, number } = useT();
  const go = useNav((s) => s.go);
  const gate = useMasterGate();
  const vaultLoad = useLoad(() => api.vaults.get(id), [id]);
  const vault = vaultLoad.data;
  const unlocked = vault?.unlocked ?? false;
  const itemsLoad = useLoad<VaultItemView[]>(
    () => (unlocked ? api.vaults.items(id) : Promise.resolve([])),
    [id, unlocked],
  );

  const [actionError, setActionError] = useState<unknown>(null);
  const [op, setOp] = useState<{ id: string; label: string } | null>(null);
  const [conflict, setConflict] = useState<ConflictPolicy>("keepBoth");
  const [removeOriginal, setRemoveOriginal] = useState(false);
  const [addResults, setAddResults] = useState<AddToVaultResult[]>([]);

  const [renameOpen, setRenameOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [renameBusy, setRenameBusy] = useState(false);
  const [renameError, setRenameError] = useState<unknown>(null);

  const [passwordOpen, setPasswordOpen] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<VaultItemView | null>(null);

  const guard = async (fn: () => Promise<void>): Promise<void> => {
    setActionError(null);
    try {
      await fn();
    } catch (e) {
      setActionError(e);
    }
  };

  const refresh = async (): Promise<void> => {
    await vaultLoad.reload();
    await itemsLoad.reload();
  };

  if (vaultLoad.loading && !vault) {
    return (
      <div className="flex justify-center py-16">
        <Spinner className="h-5 w-5" />
      </div>
    );
  }

  if (!vault) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title={t("vault.title")} />
        {vaultLoad.error ? <ErrorNotice error={vaultLoad.error} /> : null}
        <EmptyState
          icon={FolderLock}
          title={t("vault.notFound.title")}
          body={t("vault.notFound.body")}
          action={
            <Button variant="secondary" onClick={() => go({ name: "vaults" })}>
              {t("common.back")}
            </Button>
          }
        />
      </div>
    );
  }

  const items = itemsLoad.data ?? [];
  const busyOp = op !== null;

  const lock = (): Promise<void> =>
    guard(async () => {
      await api.vaults.lock(vault.id);
      await vaultLoad.reload();
    });

  const toggleFavorite = (): Promise<void> =>
    guard(async () => {
      await api.vaults.setFavorite(vault.id, !vault.favorite);
      await vaultLoad.reload();
    });

  const openRename = (): void => {
    setNewName(vault.name);
    setNewDescription(vault.description);
    setRenameError(null);
    setRenameOpen(true);
  };

  const submitRename = async (): Promise<void> => {
    setRenameBusy(true);
    setRenameError(null);
    try {
      await api.vaults.rename(vault.id, newName.trim(), vault.icon || undefined, newDescription.trim());
      await vaultLoad.reload();
      setRenameOpen(false);
    } catch (e) {
      setRenameError(e);
    } finally {
      setRenameBusy(false);
    }
  };

  const addPaths = async (paths: string[]): Promise<void> => {
    if (paths.length === 0) return;
    const master = removeOriginal ? await gate.ask("sensitive") : undefined;
    if (master === null) return;
    setAddResults([]);
    const opId = newOpId();
    setOp({ id: opId, label: t("vault.adding") });
    try {
      const results = await api.vaults.addItems({
        opId,
        vaultId: vault.id,
        paths,
        removeOriginal,
        master,
      });
      setAddResults(results);
      await refresh();
      const okCount = results.filter((r) => r.ok).length;
      if (okCount > 0) useToasts.getState().push("success", t("vault.added", { n: number(okCount) }));
    } finally {
      setOp(null);
    }
  };

  const addFiles = (): Promise<void> => guard(async () => addPaths(await pickFiles()));
  const addFolders = (): Promise<void> => guard(async () => addPaths(await pickFolders()));

  const extract = (item: VaultItemView): Promise<void> =>
    guard(async () => {
      const outDir = await pickDirectory();
      if (!outDir) return;
      const opId = newOpId();
      setOp({ id: opId, label: t("vault.extracting") });
      try {
        await api.vaults.extractItem({
          opId,
          vaultId: vault.id,
          itemId: item.id,
          outDir,
          onConflict: conflict,
        });
        useToasts.getState().push("success", t("vault.extracted", { name: item.name }));
      } finally {
        setOp(null);
      }
    });

  const exportVault = (): Promise<void> =>
    guard(async () => {
      const destDir = await pickDirectory();
      if (!destDir) return;
      const opId = newOpId();
      setOp({ id: opId, label: t("vault.exporting") });
      try {
        await api.vaults.exportBundle({ opId, vaultId: vault.id, destDir, onConflict: conflict });
        useToasts.getState().push("success", t("vault.exported"));
      } finally {
        setOp(null);
      }
    });

  const removeItem = async (): Promise<void> => {
    const target = removeTarget;
    if (!target) return;
    const master = await gate.ask("sensitive");
    if (master === null) return;
    await api.vaults.removeItem(vault.id, target.id, master);
    setRemoveTarget(null);
    await refresh();
  };

  const deleteVault = async (): Promise<void> => {
    const master = await gate.ask("sensitive");
    if (master === null) return;
    await api.vaults.remove(vault.id, master);
    setConfirmDelete(false);
    useToasts.getState().push("success", t("vault.deleted"));
    go({ name: "vaults" });
  };

  const conflictOptions = [
    { value: "keepBoth" as const, label: t("conflict.keepBoth") },
    { value: "replace" as const, label: t("conflict.replace") },
    { value: "fail" as const, label: t("conflict.cancel") },
  ];

  const resultLabel = (r: AddToVaultResult): string => {
    if (!r.ok) return r.error ? t(`error.${toAppError(r.error).code}`) : t("vault.addFailed");
    if (r.removal?.status === "removed") return t("protect.originalRemoved");
    if (r.removal?.status === "failed") return t("protect.originalKept");
    return t("protect.originalUntouched");
  };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={vault.name}
        subtitle={vault.description || t("vault.subtitle")}
        actions={
          <>
            <Button
              variant="secondary"
              size="sm"
              aria-pressed={vault.favorite}
              icon={<Star className={vault.favorite ? "h-4 w-4 fill-current text-warn" : "h-4 w-4"} />}
              onClick={() => void toggleFavorite()}
            >
              {vault.favorite ? t("item.unfavorite") : t("item.favorite")}
            </Button>
            {unlocked ? (
              <Button
                variant="primary"
                size="sm"
                disabled={busyOp}
                icon={<Lock className="h-4 w-4" />}
                onClick={() => void lock()}
              >
                {t("vault.lock")}
              </Button>
            ) : null}
          </>
        }
      />

      {vaultLoad.error ? <ErrorNotice error={vaultLoad.error} /> : null}
      {itemsLoad.error ? <ErrorNotice error={itemsLoad.error} /> : null}
      {actionError ? <ErrorNotice error={actionError} /> : null}

      {!unlocked ? (
        <UnlockForm vault={vault} onUnlocked={() => void refresh()} />
      ) : (
        <>
          {op ? (
            <div className="rounded-2xl border border-line bg-surface-1 p-4">
              <OpProgress opId={op.id} fallbackLabel={op.label} />
            </div>
          ) : null}

          <Card className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="primary"
                size="sm"
                disabled={busyOp}
                icon={<FilePlus2 className="h-4 w-4" />}
                onClick={() => void addFiles()}
              >
                {t("vault.addFiles")}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyOp}
                icon={<FolderPlus className="h-4 w-4" />}
                onClick={() => void addFolders()}
              >
                {t("vault.addFolders")}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyOp}
                icon={<DatabaseBackup className="h-4 w-4" />}
                onClick={() => void exportVault()}
              >
                {t("vault.export")}
              </Button>
            </div>
            <Switch
              checked={removeOriginal}
              onChange={setRemoveOriginal}
              disabled={busyOp}
              label={t("protect.removeOriginal")}
              description={t("protect.removeOriginalHint")}
            />
            <Select
              value={conflict}
              options={conflictOptions}
              onChange={setConflict}
              label={t("protect.conflict")}
              disabled={busyOp}
              className="max-w-xs"
            />
          </Card>

          {addResults.length > 0 ? (
            <ul className="flex flex-col divide-y divide-line overflow-hidden rounded-2xl border border-line bg-surface-1">
              {addResults.map((r) => (
                <li key={r.path} className="flex flex-col gap-0.5 px-4 py-2.5">
                  <span className="ltr-text truncate text-sm text-fg" title={r.path}>
                    {r.path}
                  </span>
                  <span className={r.ok ? "text-xs text-ok" : "text-xs text-danger"}>{resultLabel(r)}</span>
                </li>
              ))}
            </ul>
          ) : null}

          <section className="flex flex-col gap-2" aria-labelledby="vault-items">
            <h2 id="vault-items" className="text-sm font-semibold text-fg">
              {t("vault.items")}
            </h2>
            {itemsLoad.loading && !itemsLoad.data ? (
              <div className="flex justify-center py-8">
                <Spinner className="h-5 w-5" />
              </div>
            ) : items.length === 0 ? (
              <EmptyState icon={FileLock2} title={t("vault.empty.title")} body={t("vault.empty.body")} />
            ) : (
              <ul className="flex flex-col gap-2">
                {items.map((item) => (
                  <li
                    key={item.id}
                    className="flex items-center gap-3 rounded-xl border border-line bg-surface-1 px-3 py-2.5"
                  >
                    <span
                      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-surface-3 text-fg-muted"
                      aria-hidden="true"
                    >
                      <FileLock2 className="h-4 w-4" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="ltr-text truncate text-sm font-medium text-fg" title={item.name}>
                        {item.name}
                      </p>
                      <p className="truncate text-xs text-fg-muted">
                        {t(`item.kind.${item.kind}`)} · {bytes(item.originalSize)} · {date(item.createdAt)}
                      </p>
                    </div>
                    <Button
                      variant="secondary"
                      size="sm"
                      disabled={busyOp}
                      icon={<Upload className="h-4 w-4" />}
                      onClick={() => void extract(item)}
                    >
                      {t("vault.extract")}
                    </Button>
                    <button
                      type="button"
                      disabled={busyOp}
                      aria-label={t("vault.removeItem")}
                      title={t("vault.removeItem")}
                      onClick={() => setRemoveTarget(item)}
                      className="flex h-8 w-8 items-center justify-center rounded-lg text-fg-muted hover:bg-surface-3 hover:text-danger disabled:opacity-50"
                    >
                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <Card className="flex flex-col gap-3">
            <h2 className="text-sm font-semibold text-fg">{t("vault.manage")}</h2>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="secondary"
                size="sm"
                disabled={busyOp}
                icon={<Pencil className="h-4 w-4" />}
                onClick={openRename}
              >
                {t("vault.rename")}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyOp}
                icon={<KeyRound className="h-4 w-4" />}
                onClick={() => setPasswordOpen(true)}
              >
                {t("details.changePassword")}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={busyOp}
                icon={<LifeBuoy className="h-4 w-4" />}
                onClick={() => setRecoveryOpen(true)}
              >
                {vault.hasRecovery ? t("details.removeRecovery") : t("details.addRecovery")}
              </Button>
            </div>
          </Card>
        </>
      )}

      <Card className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-danger">{t("details.danger")}</h2>
        <div>
          <Button
            variant="danger"
            size="sm"
            disabled={busyOp}
            icon={<Trash2 className="h-4 w-4" />}
            onClick={() => setConfirmDelete(true)}
          >
            {t("vault.delete")}
          </Button>
        </div>
        <p className="text-xs text-fg-faint">{t("vault.deleteHint")}</p>
      </Card>

      <Dialog
        open={renameOpen}
        title={t("vault.rename")}
        onClose={() => setRenameOpen(false)}
        dismissible={!renameBusy}
        footer={
          <>
            <Button variant="ghost" onClick={() => setRenameOpen(false)} disabled={renameBusy}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              busy={renameBusy}
              disabled={newName.trim().length === 0}
              onClick={() => void submitRename()}
            >
              {t("vault.rename")}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <TextField
            label={t("vaults.name")}
            value={newName}
            autoFocus
            maxLength={80}
            onChange={(e) => setNewName(e.target.value)}
          />
          <TextField
            label={t("vaults.description")}
            value={newDescription}
            maxLength={200}
            onChange={(e) => setNewDescription(e.target.value)}
          />
          {renameError ? <ErrorNotice error={renameError} /> : null}
        </div>
      </Dialog>

      <ChangePasswordDialog
        open={passwordOpen}
        subject={vault.name}
        hasSaved={vault.hasSavedPassword}
        hasRecovery={vault.hasRecovery}
        onClose={() => setPasswordOpen(false)}
        onSubmit={async (current, next, master) => {
          const out = await api.vaults.changePassword(vault.id, current, next, master);
          await vaultLoad.reload();
          useToasts
            .getState()
            .push("success", out.savedPasswordUpdated ? t("details.passwordChangedSaved") : t("details.passwordChanged"));
        }}
      />

      <RecoveryDialog
        open={recoveryOpen}
        subject={vault.name}
        hasSaved={vault.hasSavedPassword}
        hasRecovery={vault.hasRecovery}
        onClose={() => setRecoveryOpen(false)}
        onSet={(current, master) => api.vaults.setRecovery(vault.id, current, master)}
        onRemove={(current, master) => api.vaults.removeRecovery(vault.id, current, master)}
        onChanged={() => void vaultLoad.reload()}
      />

      <ConfirmDialog
        open={removeTarget !== null}
        danger
        title={t("vault.removeItem")}
        body={t("vault.removeItemBody", { name: removeTarget?.name ?? "" })}
        confirmLabel={t("vault.removeItem")}
        onClose={() => setRemoveTarget(null)}
        onConfirm={removeItem}
      />
      <ConfirmDialog
        open={confirmDelete}
        danger
        title={t("vault.delete")}
        body={t("vault.deleteBody", { name: vault.name })}
        confirmLabel={t("vault.delete")}
        onClose={() => setConfirmDelete(false)}
        onConfirm={deleteVault}
      />
      {gate.dialog}
    </div>
  );
}
