import { useState } from "react";
import { Copy, Download, KeyRound } from "lucide-react";
import branding from "@branding";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { pickSaveFile } from "@/services/dialogs";
import { useToasts } from "@/stores/toasts";
import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { Switch } from "@/components/ui/Switch";

interface RecoveryKeyDialogProps {
  recoveryKey: string | null;
  /** Name of the item or vault the key belongs to, shown for context and in the saved file. */
  subject: string;
  onClose: () => void;
}

/**
 * Shows a freshly created recovery key. The user must confirm they stored it before the dialog can
 * be closed: the key cannot be displayed again.
 */
export function RecoveryKeyDialog({ recoveryKey, subject, onClose }: RecoveryKeyDialogProps) {
  const { t } = useT();
  const push = useToasts((s) => s.push);
  const [stored, setStored] = useState(false);
  const [error, setError] = useState<unknown>(null);

  if (recoveryKey === null) return null;

  const copy = async (): Promise<void> => {
    try {
      await api.tools.copy(recoveryKey);
      push("success", t("recovery.copied"));
    } catch (e) {
      setError(e);
    }
  };

  const save = async (): Promise<void> => {
    try {
      const path = await pickSaveFile(`${branding.productSlug}-recovery-key.txt`, "txt");
      if (!path) return;
      const text = `${branding.appName} - ${t("recovery.fileHeader")}\n${subject}\n\n${recoveryKey}\n\n${t("recovery.fileWarning")}\n`;
      await api.tools.saveTextFile(path, text);
      push("success", t("recovery.saved"));
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Dialog
      open
      dismissible={false}
      title={t("recovery.title")}
      description={t("recovery.body", { name: subject })}
      onClose={onClose}
      footer={
        <Button variant="primary" disabled={!stored} onClick={onClose}>
          {t("common.done")}
        </Button>
      }
    >
      <div className="flex flex-col gap-4">
        <div className="flex items-start gap-3 rounded-xl border border-line bg-surface-2 p-4">
          <KeyRound className="mt-0.5 h-5 w-5 shrink-0 text-accent" aria-hidden="true" />
          <p className="ltr-text selectable break-all font-mono text-sm leading-relaxed text-fg">
            {recoveryKey}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" icon={<Copy className="h-4 w-4" />} onClick={() => void copy()}>
            {t("common.copy")}
          </Button>
          <Button size="sm" icon={<Download className="h-4 w-4" />} onClick={() => void save()}>
            {t("recovery.saveFile")}
          </Button>
        </div>
        <p className="text-xs text-fg-muted">{t("recovery.warning")}</p>
        <Switch checked={stored} onChange={setStored} label={t("recovery.confirmStored")} />
        {error ? <ErrorNotice error={error} /> : null}
      </div>
    </Dialog>
  );
}
