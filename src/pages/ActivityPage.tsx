import { useState } from "react";
import { Activity, AlertCircle, CheckCircle2, Trash2 } from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useApp } from "@/stores/app";
import { useLoad } from "@/hooks/useLoad";
import { Button } from "@/components/ui/Button";
import { Card, PageHeader } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { Spinner } from "@/components/ui/Spinner";
import { Switch } from "@/components/ui/Switch";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import type { ActivityRecord } from "@/types/api";

const KNOWN_KINDS = new Set([
  "encrypt",
  "decrypt",
  "vault_create",
  "vault_open",
  "vault_lock",
  "vault_delete",
  "vault_import",
  "vault_export",
  "password_change",
  "recovery_key_create",
  "app_unlock",
  "app_lock",
  "panic_lock",
  "password_saved",
  "password_deleted",
  "master_change",
  "vault_rename",
  "vault_item_add",
  "vault_item_extract",
  "vault_item_remove",
]);

const KNOWN_ERRORS = new Set([
  "WRONG_PASSWORD",
  "INVALID_RECOVERY_KEY",
  "CORRUPTED",
  "UNSUPPORTED",
  "NOT_A_CONTAINER",
  "NO_SPACE",
  "PERMISSION_DENIED",
  "FILE_IN_USE",
  "OUTPUT_EXISTS",
  "NOT_FOUND",
  "VAULT_LOCKED",
  "CANCELLED",
  "VERIFICATION_FAILED",
  "SOURCE_CHANGED",
  "INVALID_INPUT",
  "UNSAFE_PATH",
  "STORAGE",
  "BUSY",
  "IO",
  "INTERNAL",
]);

export function ActivityPage() {
  const { t, date } = useT();
  const list = useLoad(() => api.activity.list(300), []);
  const enabled = useApp((s) => s.status?.settings.historyEnabled ?? true);
  const patchSettings = useApp((s) => s.patchSettings);
  const [actionError, setActionError] = useState<unknown>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const kindLabel = (kind: string): string =>
    KNOWN_KINDS.has(kind) ? t(`activity.kind.${kind}`) : t("activity.kind.unknown");

  const outcomeLabel = (outcome: string): string =>
    outcome === "ok"
      ? t("activity.ok")
      : KNOWN_ERRORS.has(outcome)
        ? t(`error.${outcome}`)
        : t("activity.failed");

  const toggle = async (next: boolean): Promise<void> => {
    setActionError(null);
    try {
      await patchSettings((s) => ({ ...s, historyEnabled: next }));
    } catch (e) {
      setActionError(e);
    }
  };

  const rows: ActivityRecord[] = list.data ?? [];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={t("activity.title")}
        subtitle={t("activity.subtitle")}
        actions={
          rows.length > 0 ? (
            <Button
              size="sm"
              variant="secondary"
              icon={<Trash2 className="h-4 w-4" />}
              onClick={() => setConfirmClear(true)}
            >
              {t("activity.clear")}
            </Button>
          ) : null
        }
      />

      <Card>
        <Switch
          checked={enabled}
          onChange={(v) => void toggle(v)}
          label={t("activity.enabled")}
          description={t("activity.enabledHint")}
        />
      </Card>

      {list.error ? <ErrorNotice error={list.error} /> : null}
      {actionError ? <ErrorNotice error={actionError} /> : null}

      {list.loading && !list.data ? (
        <div className="flex justify-center py-10">
          <Spinner className="h-5 w-5" />
        </div>
      ) : rows.length === 0 && !list.error ? (
        <EmptyState
          icon={Activity}
          title={t("activity.empty.title")}
          body={enabled ? t("activity.empty.body") : t("activity.empty.disabled")}
        />
      ) : (
        <ul className="flex flex-col divide-y divide-line overflow-hidden rounded-2xl border border-line bg-surface-1">
          {rows.map((r) => {
            const ok = r.outcome === "ok";
            return (
              <li key={r.id} className="flex items-start gap-3 px-4 py-3">
                {ok ? (
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" aria-hidden="true" />
                ) : (
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" aria-hidden="true" />
                )}
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-fg">{kindLabel(r.kind)}</p>
                  {r.subject ? (
                    <p className="ltr-text truncate text-xs text-fg-muted" title={r.subject}>
                      {r.subject}
                    </p>
                  ) : null}
                  {!ok ? <p className="text-xs text-danger">{outcomeLabel(r.outcome)}</p> : null}
                </div>
                <time className="shrink-0 text-xs text-fg-faint" dateTime={new Date(r.ts * 1000).toISOString()}>
                  {date(r.ts)}
                </time>
              </li>
            );
          })}
        </ul>
      )}

      <ConfirmDialog
        open={confirmClear}
        danger
        title={t("activity.clear")}
        body={t("activity.clearBody")}
        confirmLabel={t("activity.clear")}
        onClose={() => setConfirmClear(false)}
        onConfirm={async () => {
          await api.activity.clear();
          await list.reload();
          setConfirmClear(false);
        }}
      />
    </div>
  );
}
