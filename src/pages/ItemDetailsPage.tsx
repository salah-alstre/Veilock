import { useState } from "react";
import {
  FileLock2,
  FolderInput,
  FolderOpen,
  KeyRound,
  LifeBuoy,
  LockOpen,
  Pencil,
  Star,
  Trash2,
} from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { pickDirectory } from "@/services/dialogs";
import { useNav } from "@/stores/nav";
import { useToasts } from "@/stores/toasts";
import { useLoad } from "@/hooks/useLoad";
import { Button } from "@/components/ui/Button";
import { Card, PageHeader } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { TextField } from "@/components/ui/Field";
import { Spinner } from "@/components/ui/Spinner";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { ChangePasswordDialog, RecoveryDialog } from "@/components/shared/CredentialDialogs";
import { useMasterGate } from "@/components/shared/useMasterGate";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 py-2 sm:flex-row sm:items-baseline sm:gap-4">
      <dt className="w-44 shrink-0 text-xs font-medium text-fg-muted">{label}</dt>
      <dd className="min-w-0 flex-1 break-words text-sm text-fg">{children}</dd>
    </div>
  );
}

export function ItemDetailsPage({ id }: { id: string }) {
  const { t, bytes, date, number } = useT();
  const go = useNav((s) => s.go);
  const stageUnlock = useNav((s) => s.stageUnlock);
  const gate = useMasterGate();
  const load = useLoad(() => api.items.get(id), [id]);
  const item = load.data;

  const [actionError, setActionError] = useState<unknown>(null);
  const [renameOpen, setRenameOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [renameBusy, setRenameBusy] = useState(false);
  const [renameError, setRenameError] = useState<unknown>(null);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmForget, setConfirmForget] = useState(false);

  const guard = async (fn: () => Promise<void>): Promise<void> => {
    setActionError(null);
    try {
      await fn();
    } catch (e) {
      setActionError(e);
    }
  };

  if (load.loading && !item) {
    return (
      <div className="flex justify-center py-16">
        <Spinner className="h-5 w-5" />
      </div>
    );
  }

  if (!item) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title={t("details.title")} />
        {load.error ? <ErrorNotice error={load.error} /> : null}
        <EmptyState
          icon={FileLock2}
          title={t("details.notFound.title")}
          body={t("details.notFound.body")}
          action={
            <Button variant="secondary" onClick={() => go({ name: "recent" })}>
              {t("common.back")}
            </Button>
          }
        />
      </div>
    );
  }

  const openRename = (): void => {
    setNewName(item.name);
    setRenameError(null);
    setRenameOpen(true);
  };

  const submitRename = async (): Promise<void> => {
    setRenameBusy(true);
    setRenameError(null);
    try {
      await api.items.rename(item.id, newName.trim());
      await load.reload();
      setRenameOpen(false);
    } catch (e) {
      setRenameError(e);
    } finally {
      setRenameBusy(false);
    }
  };

  const move = (): Promise<void> =>
    guard(async () => {
      const dir = await pickDirectory();
      if (!dir) return;
      const out = await api.items.move(item.id, dir);
      await load.reload();
      useToasts.getState().push("success", t("details.moved"));
      if (out.originalLeftBehind) useToasts.getState().push("info", t("details.originalLeftBehind"));
    });

  const toggleFavorite = (): Promise<void> =>
    guard(async () => {
      await api.items.setFavorite(item.id, !item.favorite);
      await load.reload();
    });

  const unlock = (): void => {
    stageUnlock([item.encryptedPath]);
    go({ name: "unlock" });
  };

  const deleteFile = async (): Promise<void> => {
    const master = await gate.ask("sensitive");
    if (master === null) return;
    await api.items.deleteFile(item.id, master);
    useToasts.getState().push("success", t("details.deleted"));
    setConfirmDelete(false);
    go({ name: "recent" });
  };

  const forget = async (): Promise<void> => {
    await api.items.removeFromHistory(item.id);
    setConfirmForget(false);
    go({ name: "recent" });
  };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={item.name}
        subtitle={t("details.subtitle")}
        actions={
          <>
            <Button
              variant="secondary"
              size="sm"
              aria-pressed={item.favorite}
              icon={<Star className={item.favorite ? "h-4 w-4 fill-current text-warn" : "h-4 w-4"} />}
              onClick={() => void toggleFavorite()}
            >
              {item.favorite ? t("item.unfavorite") : t("item.favorite")}
            </Button>
            <Button
              variant="primary"
              size="sm"
              disabled={!item.exists}
              icon={<LockOpen className="h-4 w-4" />}
              onClick={unlock}
            >
              {t("details.unlock")}
            </Button>
          </>
        }
      />

      {load.error ? <ErrorNotice error={load.error} /> : null}
      {actionError ? <ErrorNotice error={actionError} /> : null}

      {!item.exists ? (
        <Card className="border-warn/40">
          <p className="text-sm font-medium text-warn">{t("details.missing.title")}</p>
          <p className="mt-1 text-sm text-fg-muted">{t("details.missing.body")}</p>
        </Card>
      ) : null}

      <Card>
        <dl className="divide-y divide-line">
          <Row label={t("details.type")}>{t(`item.kind.${item.kind}`)}</Row>
          <Row label={t("details.location")}>
            <span className="ltr-text selectable break-all">{item.encryptedPath}</span>
          </Row>
          {item.originalPath ? (
            <Row label={t("details.original")}>
              <span className="ltr-text selectable break-all">{item.originalPath}</span>
            </Row>
          ) : null}
          <Row label={t("details.originalSize")}>{bytes(item.originalSize)}</Row>
          <Row label={t("details.encryptedSize")}>{bytes(item.encryptedSize)}</Row>
          {item.kind === "folder" ? <Row label={t("details.files")}>{number(item.fileCount)}</Row> : null}
          <Row label={t("details.created")}>{date(item.createdAt)}</Row>
          {item.lastOpenedAt ? <Row label={t("details.lastOpened")}>{date(item.lastOpenedAt)}</Row> : null}
          <Row label={t("details.algorithm")}>
            <span className="ltr-text">{item.algorithm}</span> · {t("details.format", { v: item.formatVersion })}
          </Row>
          <Row label={t("details.savedPassword")}>
            {item.hasSavedPassword ? t("details.yes") : t("details.no")}
          </Row>
          <Row label={t("details.recovery")}>{item.hasRecovery ? t("details.yes") : t("details.no")}</Row>
        </dl>
      </Card>

      <Card className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-fg">{t("details.actions")}</h2>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="secondary"
            size="sm"
            disabled={!item.exists}
            icon={<FolderOpen className="h-4 w-4" />}
            onClick={() => void guard(() => api.items.revealInFolder(item.id))}
          >
            {t("details.reveal")}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={!item.exists}
            icon={<Pencil className="h-4 w-4" />}
            onClick={openRename}
          >
            {t("details.rename")}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={!item.exists}
            icon={<FolderInput className="h-4 w-4" />}
            onClick={() => void move()}
          >
            {t("details.move")}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={!item.exists}
            icon={<KeyRound className="h-4 w-4" />}
            onClick={() => setPasswordOpen(true)}
          >
            {t("details.changePassword")}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={!item.exists}
            icon={<LifeBuoy className="h-4 w-4" />}
            onClick={() => setRecoveryOpen(true)}
          >
            {item.hasRecovery ? t("details.removeRecovery") : t("details.addRecovery")}
          </Button>
        </div>
      </Card>

      <Card className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-danger">{t("details.danger")}</h2>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" size="sm" onClick={() => setConfirmForget(true)}>
            {t("details.forget")}
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={!item.exists}
            icon={<Trash2 className="h-4 w-4" />}
            onClick={() => setConfirmDelete(true)}
          >
            {t("details.delete")}
          </Button>
        </div>
        <p className="text-xs text-fg-faint">{t("details.forgetHint")}</p>
      </Card>

      <Dialog
        open={renameOpen}
        title={t("details.rename")}
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
              disabled={newName.trim().length === 0 || newName.trim() === item.name}
              onClick={() => void submitRename()}
            >
              {t("details.rename")}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <TextField
            label={t("details.newName")}
            value={newName}
            ltr
            autoFocus
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && newName.trim() && newName.trim() !== item.name) void submitRename();
            }}
          />
          {renameError ? <ErrorNotice error={renameError} /> : null}
        </div>
      </Dialog>

      <ChangePasswordDialog
        open={passwordOpen}
        subject={item.name}
        hasSaved={item.hasSavedPassword}
        hasRecovery={item.hasRecovery}
        onClose={() => setPasswordOpen(false)}
        onSubmit={async (current, next, master) => {
          const out = await api.items.changePassword(item.id, current, next, master);
          await load.reload();
          useToasts
            .getState()
            .push("success", out.savedPassword === "updated" ? t("details.passwordChangedSaved") : t("details.passwordChanged"));
        }}
      />

      <RecoveryDialog
        open={recoveryOpen}
        subject={item.name}
        hasSaved={item.hasSavedPassword}
        hasRecovery={item.hasRecovery}
        onClose={() => setRecoveryOpen(false)}
        onSet={(current, master) => api.items.setRecovery(item.id, current, master)}
        onRemove={(current, master) => api.items.removeRecovery(item.id, current, master)}
        onChanged={() => void load.reload()}
      />

      <ConfirmDialog
        open={confirmDelete}
        danger
        title={t("details.delete")}
        body={t("details.deleteBody", { name: item.name })}
        confirmLabel={t("details.delete")}
        onClose={() => setConfirmDelete(false)}
        onConfirm={deleteFile}
      />
      <ConfirmDialog
        open={confirmForget}
        title={t("details.forget")}
        body={t("details.forgetBody")}
        confirmLabel={t("details.forget")}
        onClose={() => setConfirmForget(false)}
        onConfirm={forget}
      />
      {gate.dialog}
    </div>
  );
}
