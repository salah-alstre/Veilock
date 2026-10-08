import { useEffect, useMemo, useRef, useState } from "react";
import {
  Copy,
  Eye,
  FileText,
  Folder,
  FolderLock,
  KeyRound,
  Lock,
  Pencil,
  Plus,
  Search,
  ShieldCheck,
  Star,
  StickyNote,
  Trash2,
} from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useApp } from "@/stores/app";
import { useNav } from "@/stores/nav";
import { useToasts } from "@/stores/toasts";
import { useLoad } from "@/hooks/useLoad";
import { Button, IconButton } from "@/components/ui/Button";
import { Card, PageHeader } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { PasswordField, TextArea, TextField } from "@/components/ui/Field";
import { Select } from "@/components/ui/Select";
import { Spinner } from "@/components/ui/Spinner";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { PasswordGenerator } from "@/components/shared/PasswordGenerator";
import { useMasterGate } from "@/components/shared/useMasterGate";
import type { EntryKind, EntryView } from "@/types/api";

const KINDS: EntryKind[] = ["file", "folder", "vault", "other"];
/** How long a revealed password stays on screen before it is wiped from the UI. */
const REVEAL_SECS = 30;

function KindIcon({ kind }: { kind: EntryKind }) {
  const cls = "h-5 w-5";
  if (kind === "folder") return <Folder className={cls} aria-hidden="true" />;
  if (kind === "vault") return <FolderLock className={cls} aria-hidden="true" />;
  if (kind === "file") return <FileText className={cls} aria-hidden="true" />;
  return <KeyRound className={cls} aria-hidden="true" />;
}

/* ------------------------------------------------------------------ */
/* Create the Master Password (needed before the Password Vault exists) */
/* ------------------------------------------------------------------ */

function CreateMasterDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useT();
  const refresh = useApp((s) => s.refresh);
  const [master, setMaster] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (open) {
      setMaster("");
      setConfirm("");
      setError(null);
    }
  }, [open]);

  const mismatch = confirm.length > 0 && master !== confirm;
  const ready = master.length > 0 && master === confirm && !busy;

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await api.app.createMaster(master);
      setMaster("");
      setConfirm("");
      await refresh();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      title={t("master.title")}
      description={t("master.body")}
      onClose={onClose}
      dismissible={!busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" busy={busy} disabled={!ready} onClick={() => void submit()}>
            {t("passwords.createMaster")}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <PasswordField
          label={t("lock.masterPassword")}
          value={master}
          autoFocus
          autoComplete="new-password"
          onChange={(e) => setMaster(e.target.value)}
        />
        <PasswordField
          label={t("master.confirm")}
          value={confirm}
          autoComplete="new-password"
          error={mismatch ? t("picker.mismatch") : undefined}
          onChange={(e) => setConfirm(e.target.value)}
        />
        <p className="text-xs text-fg-muted">{t("passwords.masterWarning")}</p>
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Add / edit an entry                                                  */
/* ------------------------------------------------------------------ */

interface EditorProps {
  open: boolean;
  /** Entry id when editing, null when adding. */
  editId: string | null;
  onClose: () => void;
  onSaved: () => void;
}

function EntryEditor({ open, editId, onClose, onSaved }: EditorProps) {
  const { t } = useT();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<EntryKind>("other");
  const [password, setPassword] = useState("");
  const [notes, setNotes] = useState("");
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const editing = editId !== null;

  useEffect(() => {
    if (!open) return;
    setName("");
    setKind("other");
    setPassword("");
    setNotes("");
    setError(null);
    if (editId === null) return;
    let alive = true;
    setLoading(true);
    api.passwords
      .get(editId)
      .then((e) => {
        if (!alive) return;
        setName(e.name);
        setKind(e.kind);
        setNotes(e.notes);
      })
      .catch((e) => alive && setError(e))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [open, editId]);

  const ready = name.trim().length > 0 && (editing || password.length > 0) && !busy && !loading;

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      if (editId === null) {
        await api.passwords.add({ name: name.trim(), kind, password, notes });
      } else {
        await api.passwords.update(editId, {
          name: name.trim(),
          notes,
          // An empty field on edit means "keep the stored password".
          ...(password.length > 0 ? { password } : {}),
        });
      }
      setPassword("");
      onSaved();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      wide
      title={editing ? t("passwords.editTitle") : t("passwords.addTitle")}
      onClose={onClose}
      dismissible={!busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" busy={busy} disabled={!ready} onClick={() => void submit()}>
            {t("passwords.save")}
          </Button>
        </>
      }
    >
      {loading ? (
        <div className="flex justify-center py-8">
          <Spinner className="h-5 w-5" />
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          <TextField
            label={t("passwords.name")}
            value={name}
            autoFocus
            maxLength={120}
            disabled={busy}
            onChange={(e) => setName(e.target.value)}
          />
          {!editing ? (
            <Select
              label={t("passwords.kind")}
              showLabel
              value={kind}
              onChange={setKind}
              disabled={busy}
              options={KINDS.map((k) => ({ value: k, label: t(`passwords.kind.${k}`) }))}
            />
          ) : null}
          <PasswordField
            label={editing ? t("passwords.newPassword") : t("passwords.password")}
            hint={editing ? t("passwords.keepHint") : undefined}
            value={password}
            autoComplete="new-password"
            disabled={busy}
            onChange={(e) => setPassword(e.target.value)}
          />
          <PasswordGenerator onUse={(p) => setPassword(p)} />
          <TextArea
            label={t("passwords.notes")}
            value={notes}
            rows={3}
            maxLength={2000}
            disabled={busy}
            onChange={(e) => setNotes(e.target.value)}
          />
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      )}
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Reveal dialog: value lives only in component state and is wiped      */
/* ------------------------------------------------------------------ */

function RevealDialog({
  name,
  value,
  onClose,
}: {
  name: string;
  value: string | null;
  onClose: () => void;
}) {
  const { t, number } = useT();
  const [left, setLeft] = useState(REVEAL_SECS);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    if (value === null) return;
    setLeft(REVEAL_SECS);
    const timer = window.setInterval(() => {
      setLeft((n) => {
        if (n <= 1) {
          window.clearInterval(timer);
          closeRef.current();
          return 0;
        }
        return n - 1;
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [value]);

  return (
    <Dialog
      open={value !== null}
      title={name}
      description={t("passwords.revealHint", { n: number(left) })}
      onClose={onClose}
      footer={
        <Button variant="primary" onClick={onClose}>
          {t("common.close")}
        </Button>
      }
    >
      <p className="ltr-text selectable break-all rounded-xl border border-line bg-surface-2 px-3 py-3 font-mono text-sm text-fg">
        {value}
      </p>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Default Encryption Password                                          */
/* ------------------------------------------------------------------ */

function DefaultPasswordCard() {
  const { t } = useT();
  const gate = useMasterGate();
  const configured = useLoad(() => api.app.defaultPasswordConfigured(), []);
  const [setOpen, setSetOpen] = useState(false);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  useEffect(() => {
    if (setOpen) {
      setValue("");
      setError(null);
    }
  }, [setOpen]);

  const save = async (): Promise<void> => {
    setError(null);
    const master = await gate.ask("always");
    if (master === null || master === undefined) return;
    setBusy(true);
    try {
      await api.app.setDefaultPassword(value, master);
      setValue("");
      setSetOpen(false);
      await configured.reload();
      useToasts.getState().push("success", t("passwords.default.saved"));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const clear = async (): Promise<void> => {
    const master = await gate.ask("always");
    if (master === null || master === undefined) return;
    await api.app.clearDefaultPassword(master);
    await configured.reload();
    setConfirmClear(false);
    useToasts.getState().push("success", t("passwords.default.cleared"));
  };

  const isSet = configured.data === true;

  return (
    <Card className="flex flex-col gap-3">
      <div className="flex items-start gap-3">
        <span
          className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-surface-3 text-fg-muted"
          aria-hidden="true"
        >
          <ShieldCheck className="h-5 w-5" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-semibold text-fg">{t("passwords.default.title")}</h2>
          <p className="mt-0.5 text-xs text-fg-muted">{t("passwords.default.body")}</p>
          <p className={isSet ? "mt-2 text-xs font-medium text-ok" : "mt-2 text-xs font-medium text-fg-muted"}>
            {configured.loading && configured.data === null
              ? t("common.loading")
              : isSet
                ? t("passwords.default.configured")
                : t("passwords.default.notConfigured")}
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button variant="secondary" size="sm" onClick={() => setSetOpen(true)}>
            {isSet ? t("passwords.default.change") : t("passwords.default.set")}
          </Button>
          {isSet ? (
            <Button variant="ghost" size="sm" onClick={() => setConfirmClear(true)}>
              {t("passwords.default.clear")}
            </Button>
          ) : null}
        </div>
      </div>
      {configured.error ? <ErrorNotice error={configured.error} /> : null}

      <Dialog
        open={setOpen}
        wide
        title={isSet ? t("passwords.default.change") : t("passwords.default.set")}
        description={t("passwords.default.dialogBody")}
        onClose={() => setSetOpen(false)}
        dismissible={!busy}
        footer={
          <>
            <Button variant="ghost" onClick={() => setSetOpen(false)} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button variant="primary" busy={busy} disabled={value.length === 0 || busy} onClick={() => void save()}>
              {t("passwords.save")}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <PasswordField
            label={t("passwords.password")}
            value={value}
            autoFocus
            autoComplete="new-password"
            disabled={busy}
            onChange={(e) => setValue(e.target.value)}
          />
          <PasswordGenerator onUse={(p) => setValue(p)} />
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      </Dialog>

      <ConfirmDialog
        open={confirmClear}
        danger
        title={t("passwords.default.clear")}
        body={t("passwords.default.clearBody")}
        confirmLabel={t("passwords.default.clear")}
        onClose={() => setConfirmClear(false)}
        onConfirm={clear}
      />
      {gate.dialog}
    </Card>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                 */
/* ------------------------------------------------------------------ */

export function PasswordsPage() {
  const { t, date } = useT();
  const go = useNav((s) => s.go);
  const status = useApp((s) => s.status);
  const gate = useMasterGate();
  const masterExists = status?.masterExists ?? false;
  const unlocked = status?.lockPhase === "unlocked";

  const list = useLoad(() => (masterExists && unlocked ? api.passwords.list() : Promise.resolve([])), [
    masterExists,
    unlocked,
  ]);
  const [query, setQuery] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [masterOpen, setMasterOpen] = useState(false);
  const [editor, setEditor] = useState<{ open: boolean; id: string | null }>({ open: false, id: null });
  const [revealed, setRevealed] = useState<{ name: string; value: string } | null>(null);
  const [toDelete, setToDelete] = useState<EntryView | null>(null);

  const entries = list.data ?? [];
  const filtered = useMemo(() => {
    const q = query.trim().toLocaleLowerCase();
    if (!q) return entries;
    return entries.filter((e) => e.name.toLocaleLowerCase().includes(q));
  }, [entries, query]);

  // Never keep a revealed secret around once the app is locked.
  useEffect(() => {
    if (!unlocked) setRevealed(null);
  }, [unlocked]);

  const guard = async (fn: () => Promise<void>): Promise<void> => {
    setActionError(null);
    try {
      await fn();
    } catch (e) {
      setActionError(e);
    }
  };

  const reveal = (e: EntryView): Promise<void> =>
    guard(async () => {
      const master = await gate.ask("reveal");
      if (master === null) return;
      const value = await api.passwords.reveal(e.id, master);
      setRevealed({ name: e.name, value });
    });

  const copy = (e: EntryView): Promise<void> =>
    guard(async () => {
      const master = await gate.ask("reveal");
      if (master === null) return;
      await api.passwords.copy(e.id, master);
      useToasts.getState().push("success", t("passwords.copied"));
    });

  const toggleFavorite = (e: EntryView): Promise<void> =>
    guard(async () => {
      await api.passwords.update(e.id, { favorite: !e.favorite });
      await list.reload();
    });

  const remove = async (): Promise<void> => {
    if (!toDelete) return;
    await api.passwords.remove(toDelete.id);
    setToDelete(null);
    await list.reload();
    useToasts.getState().push("success", t("passwords.deleted"));
  };

  /* No Master Password -> there is no Password Vault yet. */
  if (status && !masterExists) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title={t("passwords.title")} subtitle={t("passwords.subtitle")} />
        <EmptyState
          icon={Lock}
          title={t("passwords.noMaster.title")}
          body={t("passwords.noMaster.body")}
          action={
            <Button variant="primary" onClick={() => setMasterOpen(true)}>
              {t("passwords.createMaster")}
            </Button>
          }
        />
        <CreateMasterDialog open={masterOpen} onClose={() => setMasterOpen(false)} />
      </div>
    );
  }

  if (status && !unlocked) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title={t("passwords.title")} subtitle={t("passwords.subtitle")} />
        <EmptyState icon={Lock} title={t("passwords.locked.title")} body={t("passwords.locked.body")} />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={t("passwords.title")}
        subtitle={t("passwords.subtitle")}
        actions={
          <Button
            variant="primary"
            size="sm"
            icon={<Plus className="h-4 w-4" />}
            onClick={() => setEditor({ open: true, id: null })}
          >
            {t("passwords.add")}
          </Button>
        }
      />

      <DefaultPasswordCard />

      {list.error ? <ErrorNotice error={list.error} /> : null}
      {actionError ? <ErrorNotice error={actionError} /> : null}

      {entries.length > 0 ? (
        <div className="relative">
          <Search
            className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint"
            aria-hidden="true"
          />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("passwords.filter")}
            aria-label={t("passwords.filter")}
            className="h-10 w-full rounded-xl border border-line bg-surface-1 ps-9 pe-3 text-sm text-fg placeholder:text-fg-faint focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
        </div>
      ) : null}

      {list.loading && !list.data ? (
        <div className="flex justify-center py-10">
          <Spinner className="h-5 w-5" />
        </div>
      ) : entries.length === 0 && !list.error ? (
        <EmptyState
          icon={KeyRound}
          title={t("passwords.empty.title")}
          body={t("passwords.empty.body")}
          action={
            <Button
              variant="primary"
              icon={<Plus className="h-4 w-4" />}
              onClick={() => setEditor({ open: true, id: null })}
            >
              {t("passwords.add")}
            </Button>
          }
        />
      ) : filtered.length === 0 ? (
        <p className="py-6 text-center text-sm text-fg-muted">{t("passwords.noMatches")}</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {filtered.map((e) => (
            <li
              key={e.id}
              className="flex items-center gap-3 rounded-2xl border border-line bg-surface-1 px-4 py-3"
            >
              <span
                className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-surface-3 text-fg-muted"
                aria-hidden="true"
              >
                <KindIcon kind={e.kind} />
              </span>
              <div className="min-w-0 flex-1">
                <p className="flex items-center gap-1.5 truncate text-sm font-medium text-fg">
                  <span className="truncate">{e.name}</span>
                  {e.hasNotes ? (
                    <StickyNote
                      className="h-3.5 w-3.5 shrink-0 text-fg-faint"
                      aria-label={t("passwords.hasNotes")}
                    />
                  ) : null}
                </p>
                <p className="truncate text-xs text-fg-muted">
                  {t(`passwords.kind.${e.kind}`)}
                  {" · "}
                  {e.lastUsedAt
                    ? t("passwords.lastUsed", { date: date(e.lastUsedAt) })
                    : t("passwords.added", { date: date(e.createdAt) })}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-0.5">
                <IconButton
                  label={e.favorite ? t("item.unfavorite") : t("item.favorite")}
                  aria-pressed={e.favorite}
                  onClick={() => void toggleFavorite(e)}
                >
                  <Star className={e.favorite ? "h-4 w-4 fill-current text-warn" : "h-4 w-4"} />
                </IconButton>
                <IconButton label={t("passwords.reveal")} onClick={() => void reveal(e)}>
                  <Eye className="h-4 w-4" />
                </IconButton>
                <IconButton label={t("common.copy")} onClick={() => void copy(e)}>
                  <Copy className="h-4 w-4" />
                </IconButton>
                <IconButton label={t("passwords.edit")} onClick={() => setEditor({ open: true, id: e.id })}>
                  <Pencil className="h-4 w-4" />
                </IconButton>
                <IconButton label={t("common.remove")} onClick={() => setToDelete(e)}>
                  <Trash2 className="h-4 w-4" />
                </IconButton>
              </div>
            </li>
          ))}
        </ul>
      )}

      <p className="text-xs text-fg-faint">
        {t("passwords.settingsHint")}{" "}
        <button
          type="button"
          onClick={() => go({ name: "settings" })}
          className="text-accent underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {t("nav.settings")}
        </button>
      </p>

      <EntryEditor
        open={editor.open}
        editId={editor.id}
        onClose={() => setEditor({ open: false, id: null })}
        onSaved={() => void list.reload()}
      />

      <RevealDialog name={revealed?.name ?? ""} value={revealed?.value ?? null} onClose={() => setRevealed(null)} />

      <ConfirmDialog
        open={toDelete !== null}
        danger
        title={t("passwords.deleteTitle")}
        body={t("passwords.deleteBody", { name: toDelete?.name ?? "" })}
        confirmLabel={t("common.remove")}
        onClose={() => setToDelete(null)}
        onConfirm={remove}
      />
      {gate.dialog}
    </div>
  );
}
