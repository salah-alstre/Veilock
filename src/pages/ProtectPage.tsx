import { useCallback, useEffect, useMemo, useState } from "react";
import { CheckCircle2, File, FilePlus2, Folder, FolderPlus, ShieldCheck, X, XCircle } from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { toAppError } from "@/services/errors";
import { pickDirectory, pickFiles, pickFolders } from "@/services/dialogs";
import { useApp } from "@/stores/app";
import { useNav } from "@/stores/nav";
import { useOps } from "@/stores/ops";
import { useToasts } from "@/stores/toasts";
import { baseName, newOpId } from "@/utils/ids";
import { Button, IconButton } from "@/components/ui/Button";
import { Card, PageHeader } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { Select } from "@/components/ui/Select";
import { Switch } from "@/components/ui/Switch";
import { OpProgress } from "@/components/shared/OpProgress";
import { PasswordPicker } from "@/components/shared/PasswordPicker";
import { RecoveryKeyDialog } from "@/components/shared/RecoveryKeyDialog";
import { useMasterGate } from "@/components/shared/useMasterGate";
import {
  emptyPick,
  needsMasterForSource,
  pickReady,
  toSource,
  type PickerValue,
} from "@/components/shared/passwordSource";
import type { ConflictPolicy, EncryptItemResult, PathInfo } from "@/types/api";

interface PendingKey {
  key: string;
  subject: string;
}

export function ProtectPage() {
  const { t, bytes, number } = useT();
  const staged = useNav((s) => s.protectPaths);
  const clearStaged = useNav((s) => s.clearStaged);
  const go = useNav((s) => s.go);
  const settings = useApp((s) => s.status?.settings);
  const gate = useMasterGate();

  const [paths, setPaths] = useState<string[]>([]);
  const [infos, setInfos] = useState<Record<string, PathInfo>>({});
  const [pick, setPick] = useState<PickerValue>(emptyPick());
  const [save, setSave] = useState(false);
  const [withRecovery, setWithRecovery] = useState(false);
  const [removeOriginal, setRemoveOriginal] = useState(settings?.encryption.postEncrypt === "remove_original");
  const [outDir, setOutDir] = useState<string | null>(settings?.encryption.defaultOutputDir || null);
  const [conflict, setConflict] = useState<ConflictPolicy>("keepBoth");
  const [opId, setOpId] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [results, setResults] = useState<EncryptItemResult[] | null>(null);
  const [keys, setKeys] = useState<PendingKey[]>([]);

  const running = opId !== null;

  const addPaths = useCallback((incoming: string[]) => {
    if (incoming.length === 0) return;
    setResults(null);
    setPaths((cur) => [...cur, ...incoming.filter((p) => !cur.includes(p))]);
  }, []);

  // Paths staged by drag-and-drop, the Explorer context menu or file arguments.
  useEffect(() => {
    if (staged.length > 0) {
      addPaths(staged);
      clearStaged();
    }
  }, [staged, addPaths, clearStaged]);

  // Real sizes and file counts come from Rust; the UI never reads the filesystem itself.
  useEffect(() => {
    const missing = paths.filter((p) => !(p in infos));
    if (missing.length === 0) return;
    let live = true;
    api.files
      .inspect(missing)
      .then((list) => {
        if (!live) return;
        setInfos((cur) => {
          const next = { ...cur };
          for (const info of list) next[info.path] = info;
          return next;
        });
      })
      .catch((e: unknown) => live && setError(e));
    return () => {
      live = false;
    };
  }, [paths, infos]);

  const remove = (p: string): void => setPaths((cur) => cur.filter((x) => x !== p));

  const totals = useMemo(() => {
    let size = 0;
    for (const p of paths) size += infos[p]?.size ?? 0;
    return size;
  }, [paths, infos]);

  const blocked = paths.some((p) => infos[p]?.container || infos[p]?.error);
  const ready = paths.length > 0 && pickReady(pick, true) && !blocked && !running;

  const conflictOptions = [
    { value: "keepBoth" as const, label: t("conflict.keepBoth") },
    { value: "replace" as const, label: t("conflict.replace") },
    { value: "fail" as const, label: t("conflict.cancel") },
  ];

  const run = async (): Promise<void> => {
    setError(null);
    setResults(null);

    // Re-authenticate before anything irreversible: the default password may demand the master, and
    // removing the original is a sensitive action.
    let master: string | undefined;
    if (needsMasterForSource(pick)) {
      const r = await gate.ask("always");
      if (r === null) return;
      master = r;
    }
    if (removeOriginal) {
      const r = await gate.ask("sensitive");
      if (r === null) return;
      master = r ?? master;
    }

    const id = newOpId();
    setOpId(id);
    try {
      const out = await api.files.encrypt({
        opId: id,
        paths,
        password: toSource(pick),
        master,
        outDir: outDir ?? undefined,
        onConflict: conflict,
        removeOriginal,
        withRecovery,
        savePassword: save,
      });
      setResults(out);
      setKeys(
        out
          .filter((r) => r.ok && r.recoveryKey)
          .map((r) => ({ key: r.recoveryKey ?? "", subject: r.name ?? baseName(r.path) })),
      );
      const failed = out.filter((r) => !r.ok).map((r) => r.path);
      setPaths(failed);
      if (failed.length === 0) {
        setPick(emptyPick());
        useToasts.getState().push("success", t("protect.done", { n: out.length }));
      }
    } catch (e) {
      setError(e);
    } finally {
      useOps.getState().clear(id);
      setOpId(null);
    }
  };

  const chooseOutDir = async (): Promise<void> => {
    const dir = await pickDirectory();
    if (dir) setOutDir(dir);
  };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={t("protect.title")} subtitle={t("protect.subtitle")} />

      <Card className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-fg">{t("protect.items")}</h2>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="secondary"
              icon={<FilePlus2 className="h-4 w-4" />}
              disabled={running}
              onClick={() => void pickFiles().then(addPaths)}
            >
              {t("protect.addFiles")}
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<FolderPlus className="h-4 w-4" />}
              disabled={running}
              onClick={() => void pickFolders().then(addPaths)}
            >
              {t("protect.addFolders")}
            </Button>
          </div>
        </div>

        {paths.length === 0 ? (
          <EmptyState icon={ShieldCheck} title={t("protect.empty.title")} body={t("protect.empty.body")} />
        ) : (
          <>
            <ul className="flex flex-col gap-1.5">
              {paths.map((p) => {
                const info = infos[p];
                const Icon = info?.isDir ? Folder : File;
                return (
                  <li key={p} className="flex items-center gap-3 rounded-xl border border-line bg-surface-2 px-3 py-2">
                    <Icon className="h-4 w-4 shrink-0 text-fg-muted" aria-hidden="true" />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-fg">{baseName(p)}</p>
                      <p className="truncate text-xs text-fg-faint ltr-text" title={p}>
                        {p}
                      </p>
                      {info?.container ? (
                        <p className="text-xs text-warn">{t("protect.alreadyProtected")}</p>
                      ) : null}
                      {info?.error ? (
                        <p className="text-xs text-danger">{t(`error.${toAppError(info.error).code}`)}</p>
                      ) : null}
                    </div>
                    {info ? (
                      <span className="shrink-0 text-xs tabular-nums text-fg-muted">
                        {info.isDir
                          ? t("protect.folderMeta", { n: number(info.fileCount), size: bytes(info.size) })
                          : bytes(info.size)}
                      </span>
                    ) : null}
                    <IconButton label={t("common.remove")} disabled={running} onClick={() => remove(p)}>
                      <X className="h-4 w-4" />
                    </IconButton>
                  </li>
                );
              })}
            </ul>
            <p className="text-xs text-fg-muted">{t("protect.total", { size: bytes(totals) })}</p>
          </>
        )}
      </Card>

      <Card className="flex flex-col gap-4">
        <h2 className="text-sm font-semibold text-fg">{t("protect.password")}</h2>
        <PasswordPicker
          value={pick}
          onChange={setPick}
          kinds={["typed", "default"]}
          confirm
          disabled={running}
          save={save}
          onSaveChange={setSave}
        />
      </Card>

      <Card className="flex flex-col gap-4">
        <h2 className="text-sm font-semibold text-fg">{t("protect.options")}</h2>
        <div className="flex flex-col gap-1.5">
          <span className="text-[13px] font-medium text-fg-muted">{t("protect.outDir")}</span>
          <div className="flex flex-wrap items-center gap-2">
            <p className="ltr-text min-w-0 flex-1 truncate rounded-xl border border-line bg-surface-2 px-3 py-2 text-sm text-fg-muted">
              {outDir ?? t("protect.outDirSame")}
            </p>
            <Button size="sm" variant="secondary" disabled={running} onClick={() => void chooseOutDir()}>
              {t("common.choose")}
            </Button>
            {outDir ? (
              <Button size="sm" variant="ghost" disabled={running} onClick={() => setOutDir(null)}>
                {t("common.reset")}
              </Button>
            ) : null}
          </div>
        </div>
        <Select
          showLabel
          label={t("protect.conflict")}
          value={conflict}
          options={conflictOptions}
          onChange={setConflict}
          disabled={running}
        />
        <Switch
          checked={withRecovery}
          onChange={setWithRecovery}
          disabled={running}
          label={t("protect.recovery")}
          description={t("protect.recoveryHint")}
        />
        <Switch
          checked={removeOriginal}
          onChange={setRemoveOriginal}
          disabled={running}
          label={t("protect.removeOriginal")}
          description={t("protect.removeOriginalHint")}
        />
      </Card>

      {error ? <ErrorNotice error={error} /> : null}

      {running && opId ? (
        <Card>
          <OpProgress opId={opId} fallbackLabel={t("progress.phase.encrypting")} />
        </Card>
      ) : null}

      {results ? (
        <Card className="flex flex-col gap-3">
          <h2 className="text-sm font-semibold text-fg">{t("protect.results")}</h2>
          <ul className="flex flex-col gap-2">
            {results.map((r) => (
              <li key={r.path} className="flex items-start gap-2.5 text-sm">
                {r.ok ? (
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" aria-hidden="true" />
                ) : (
                  <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden="true" />
                )}
                <div className="min-w-0 flex-1">
                  <p className="truncate text-fg">{r.name ?? baseName(r.path)}</p>
                  {r.ok ? (
                    <p className="text-xs text-fg-muted">
                      {r.removal?.status === "removed"
                        ? t("protect.originalRemoved")
                        : r.removal?.status === "failed"
                          ? t("protect.originalKept")
                          : t("protect.originalUntouched")}
                      {r.passwordSaveError ? ` · ${t("protect.saveFailed")}` : null}
                    </p>
                  ) : (
                    <p className="text-xs text-danger">{t(`error.${toAppError(r.error).code}`)}</p>
                  )}
                </div>
              </li>
            ))}
          </ul>
          <div>
            <Button variant="secondary" size="sm" onClick={() => go({ name: "recent" })}>
              {t("protect.viewRecent")}
            </Button>
          </div>
        </Card>
      ) : null}

      <div className="flex justify-end gap-2">
        <Button variant="primary" size="lg" busy={running} disabled={!ready} onClick={() => void run()}>
          {t("protect.start")}
        </Button>
      </div>

      {gate.dialog}
      <RecoveryKeyDialog
        recoveryKey={keys[0]?.key ?? null}
        subject={keys[0]?.subject ?? ""}
        onClose={() => setKeys((cur) => cur.slice(1))}
      />
    </div>
  );
}
