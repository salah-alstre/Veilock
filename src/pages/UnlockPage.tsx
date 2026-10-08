import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, FileLock2, FolderOpen, LockOpen } from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { isCode, toAppError } from "@/services/errors";
import { pickContainers, pickDirectory } from "@/services/dialogs";
import { useNav } from "@/stores/nav";
import { useOps } from "@/stores/ops";
import { useToasts } from "@/stores/toasts";
import { baseName, newOpId } from "@/utils/ids";
import { Button } from "@/components/ui/Button";
import { Card, PageHeader } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { Select } from "@/components/ui/Select";
import { OpProgress } from "@/components/shared/OpProgress";
import { PasswordPicker } from "@/components/shared/PasswordPicker";
import { useMasterGate } from "@/components/shared/useMasterGate";
import {
  emptyPick,
  needsMasterForSource,
  pickReady,
  toSource,
  type PickKind,
  type PickerValue,
} from "@/components/shared/passwordSource";
import type { ConflictPolicy, DecryptResult, PathInfo } from "@/types/api";

/** Unlock (decrypt) the container at the head of the queue, one at a time. */
export function UnlockPage() {
  const { t, bytes } = useT();
  const queue = useNav((s) => s.unlockQueue);
  const shift = useNav((s) => s.shiftUnlock);
  const stageUnlock = useNav((s) => s.stageUnlock);
  const go = useNav((s) => s.go);
  const gate = useMasterGate();

  const path = queue[0];
  const [info, setInfo] = useState<PathInfo | null>(null);
  const [pick, setPick] = useState<PickerValue>(emptyPick());
  const [save, setSave] = useState(false);
  const [outDir, setOutDir] = useState<string | null>(null);
  const [conflict, setConflict] = useState<ConflictPolicy>("keepBoth");
  const [opId, setOpId] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<DecryptResult | null>(null);

  // A new head of the queue starts from a clean form; secrets never carry across items.
  useEffect(() => {
    setInfo(null);
    setPick(emptyPick());
    setSave(false);
    setError(null);
    setResult(null);
    if (!path) return;
    let live = true;
    api.files
      .inspect([path])
      .then((list) => {
        if (!live) return;
        const first = list[0] ?? null;
        setInfo(first);
        if (first?.container?.hasSavedPassword) setPick(emptyPick("saved"));
      })
      .catch((e: unknown) => live && setError(e));
    return () => {
      live = false;
    };
  }, [path]);

  const kinds = useMemo<PickKind[]>(() => {
    const list: PickKind[] = [];
    if (info?.container?.hasSavedPassword) list.push("saved");
    list.push("typed", "default");
    if (info?.container?.hasRecoverySlot) list.push("recovery");
    return list;
  }, [info]);

  const running = opId !== null;
  const notContainer = !!info && !info.container;
  const ready = !!path && !!info?.container && pickReady(pick, false) && !running && !result;

  const chooseFiles = async (): Promise<void> => {
    const picked = await pickContainers();
    if (picked.length > 0) stageUnlock(picked);
  };

  const run = async (): Promise<void> => {
    if (!path) return;
    setError(null);
    let master: string | undefined;
    if (needsMasterForSource(pick)) {
      const r = await gate.ask("always");
      if (r === null) return;
      master = r;
    }
    const id = newOpId();
    setOpId(id);
    try {
      const out = await api.files.decrypt({
        opId: id,
        path,
        password: toSource(pick),
        master,
        outDir: outDir ?? undefined,
        onConflict: conflict,
        savePassword: save,
      });
      setResult(out);
      setPick(emptyPick());
      useToasts.getState().push("success", t("unlock.done", { name: out.name }));
    } catch (e) {
      // A wrong password keeps the form so the user can retry; the field is cleared so a stale value
      // is never resubmitted by accident.
      if (isCode(toAppError(e), "WRONG_PASSWORD", "INVALID_RECOVERY_KEY")) {
        setPick((p) => ({ ...p, text: "" }));
      }
      setError(e);
    } finally {
      useOps.getState().clear(id);
      setOpId(null);
    }
  };

  if (!path) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title={t("unlock.title")} subtitle={t("unlock.subtitle")} />
        <EmptyState
          icon={FileLock2}
          title={t("unlock.empty.title")}
          body={t("unlock.empty.body")}
          action={
            <Button variant="primary" onClick={() => void chooseFiles()}>
              {t("unlock.choose")}
            </Button>
          }
        />
      </div>
    );
  }

  const conflictOptions = [
    { value: "keepBoth" as const, label: t("conflict.keepBoth") },
    { value: "replace" as const, label: t("conflict.replace") },
    { value: "fail" as const, label: t("conflict.cancel") },
  ];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={t("unlock.title")}
        subtitle={queue.length > 1 ? t("unlock.queue", { n: queue.length - 1 }) : t("unlock.subtitle")}
      />

      <Card className="flex items-center gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-surface-3 text-fg-muted">
          <FileLock2 className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-fg">{baseName(path)}</p>
          <p className="ltr-text truncate text-xs text-fg-faint" title={path}>
            {path}
          </p>
          {info?.container ? (
            <p className="mt-0.5 text-xs text-fg-muted">
              {t(`item.kind.${info.container.kind}`)} · {bytes(info.size)}
            </p>
          ) : null}
        </div>
      </Card>

      {notContainer ? (
        <ErrorNotice error={{ code: "NOT_A_CONTAINER" }} />
      ) : info?.error ? (
        <ErrorNotice error={info.error} />
      ) : null}

      {result ? (
        <Card className="flex flex-col gap-3">
          <div className="flex items-start gap-2.5">
            <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-ok" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-sm font-medium text-fg">{t("unlock.success")}</p>
              <p className="ltr-text selectable mt-1 break-all text-xs text-fg-muted">{result.output}</p>
              <p className="mt-1 text-xs text-fg-faint">
                {result.kind === "folder"
                  ? t("unlock.folderMeta", { files: result.fileCount, size: bytes(result.bytes) })
                  : bytes(result.bytes)}
              </p>
              {result.passwordSaveError ? (
                <p className="mt-1 text-xs text-warn">{t("protect.saveFailed")}</p>
              ) : null}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" size="sm" onClick={() => shift()}>
              {queue.length > 1 ? t("unlock.next") : t("common.done")}
            </Button>
            {info?.container?.itemId ? (
              <Button
                variant="secondary"
                size="sm"
                icon={<FolderOpen className="h-4 w-4" />}
                onClick={() => go({ name: "item", id: info.container?.itemId ?? "" })}
              >
                {t("unlock.details")}
              </Button>
            ) : null}
          </div>
        </Card>
      ) : (
        <>
          <Card className="flex flex-col gap-4">
            <h2 className="text-sm font-semibold text-fg">{t("unlock.password")}</h2>
            <PasswordPicker
              value={pick}
              onChange={setPick}
              kinds={kinds}
              disabled={running || notContainer}
              save={save}
              onSaveChange={setSave}
            />
          </Card>

          <Card className="flex flex-col gap-4">
            <h2 className="text-sm font-semibold text-fg">{t("protect.options")}</h2>
            <div className="flex flex-col gap-1.5">
              <span className="text-[13px] font-medium text-fg-muted">{t("unlock.outDir")}</span>
              <div className="flex flex-wrap items-center gap-2">
                <p className="ltr-text min-w-0 flex-1 truncate rounded-xl border border-line bg-surface-2 px-3 py-2 text-sm text-fg-muted">
                  {outDir ?? t("unlock.outDirSame")}
                </p>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={running}
                  onClick={() => void pickDirectory().then((d) => d && setOutDir(d))}
                >
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
          </Card>

          {error ? <ErrorNotice error={error} /> : null}

          {running && opId ? (
            <Card>
              <OpProgress opId={opId} fallbackLabel={t("progress.phase.decrypting")} />
            </Card>
          ) : null}

          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="lg" disabled={running} onClick={() => shift()}>
              {queue.length > 1 ? t("unlock.skip") : t("common.cancel")}
            </Button>
            <Button
              variant="primary"
              size="lg"
              busy={running}
              disabled={!ready}
              icon={<LockOpen className="h-4 w-4" />}
              onClick={() => void run()}
            >
              {t("unlock.start")}
            </Button>
          </div>
        </>
      )}

      {gate.dialog}
    </div>
  );
}
