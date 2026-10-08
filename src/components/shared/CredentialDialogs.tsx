import { useEffect, useMemo, useState } from "react";
import { useT } from "@/i18n";
import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { PasswordPicker } from "@/components/shared/PasswordPicker";
import { RecoveryKeyDialog } from "@/components/shared/RecoveryKeyDialog";
import { useMasterGate } from "@/components/shared/useMasterGate";
import {
  emptyPick,
  needsMasterForSource,
  pickReady,
  toSource,
  type PickKind,
  type PickerValue,
} from "@/components/shared/passwordSource";
import type { PasswordSource } from "@/types/api";

interface Target {
  open: boolean;
  /** Display name of the item or vault being changed. */
  subject: string;
  hasSaved: boolean;
  hasRecovery: boolean;
  onClose: () => void;
}

/** Current-password choices offered when proving ownership of an item or vault. */
function currentKinds(hasSaved: boolean, hasRecovery: boolean): PickKind[] {
  const kinds: PickKind[] = [];
  if (hasSaved) kinds.push("saved");
  kinds.push("typed", "default");
  if (hasRecovery) kinds.push("recovery");
  return kinds;
}

/** Master-gate kind for an action that is sensitive and may also use the default password. */
function gateKind(current: PickerValue): "always" | "sensitive" {
  return needsMasterForSource(current) ? "always" : "sensitive";
}

interface ChangePasswordProps extends Target {
  onSubmit: (current: PasswordSource, newPassword: string, master?: string) => Promise<void>;
}

export function ChangePasswordDialog({
  open,
  subject,
  hasSaved,
  hasRecovery,
  onSubmit,
  onClose,
}: ChangePasswordProps) {
  const { t } = useT();
  const gate = useMasterGate();
  const [current, setCurrent] = useState<PickerValue>(emptyPick(hasSaved ? "saved" : "typed"));
  const [next, setNext] = useState<PickerValue>(emptyPick());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const kinds = useMemo(() => currentKinds(hasSaved, hasRecovery), [hasSaved, hasRecovery]);

  useEffect(() => {
    if (!open) return;
    setCurrent(emptyPick(hasSaved ? "saved" : "typed"));
    setNext(emptyPick());
    setError(null);
  }, [open, hasSaved]);

  const ready = pickReady(current, false) && pickReady(next, true) && !busy;

  const run = async (): Promise<void> => {
    setError(null);
    const master = await gate.ask(gateKind(current));
    if (master === null) return;
    setBusy(true);
    try {
      await onSubmit(toSource(current), next.text, master);
      setCurrent(emptyPick());
      setNext(emptyPick());
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Dialog
        open={open}
        wide
        title={t("credential.changeTitle")}
        description={subject}
        onClose={onClose}
        dismissible={!busy}
        footer={
          <>
            <Button variant="ghost" onClick={onClose} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button variant="primary" busy={busy} disabled={!ready} onClick={() => void run()}>
              {t("credential.change")}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-5">
          <section className="flex flex-col gap-2">
            <h3 className="text-sm font-semibold text-fg">{t("credential.current")}</h3>
            <PasswordPicker value={current} onChange={setCurrent} kinds={kinds} disabled={busy} />
          </section>
          <section className="flex flex-col gap-2">
            <h3 className="text-sm font-semibold text-fg">{t("credential.new")}</h3>
            <PasswordPicker value={next} onChange={setNext} kinds={["typed"]} confirm disabled={busy} />
            <p className="text-xs text-fg-muted">{t("credential.changeHint")}</p>
          </section>
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      </Dialog>
      {gate.dialog}
    </>
  );
}

interface RecoveryProps extends Target {
  /** Creates a recovery key and returns it. */
  onSet: (current: PasswordSource, master?: string) => Promise<string>;
  onRemove: (current: PasswordSource, master?: string) => Promise<void>;
  /** Called after the recovery slot changed so the caller can refresh. */
  onChanged: () => void;
}

/** Adds a recovery key when there is none, or removes the existing one. */
export function RecoveryDialog({
  open,
  subject,
  hasSaved,
  hasRecovery,
  onSet,
  onRemove,
  onChanged,
  onClose,
}: RecoveryProps) {
  const { t } = useT();
  const gate = useMasterGate();
  const [current, setCurrent] = useState<PickerValue>(emptyPick(hasSaved ? "saved" : "typed"));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [key, setKey] = useState<string | null>(null);
  // Only a typed/saved/default password may authorise changing the recovery slot.
  const kinds = useMemo(() => currentKinds(hasSaved, false), [hasSaved]);

  useEffect(() => {
    if (!open) return;
    setCurrent(emptyPick(hasSaved ? "saved" : "typed"));
    setError(null);
  }, [open, hasSaved]);

  const run = async (): Promise<void> => {
    setError(null);
    const master = await gate.ask(gateKind(current));
    if (master === null) return;
    setBusy(true);
    try {
      if (hasRecovery) {
        await onRemove(toSource(current), master);
        onChanged();
        onClose();
      } else {
        const created = await onSet(toSource(current), master);
        setKey(created);
        onChanged();
        onClose();
      }
      setCurrent(emptyPick());
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Dialog
        open={open}
        title={hasRecovery ? t("credential.recoveryRemoveTitle") : t("credential.recoveryAddTitle")}
        description={subject}
        onClose={onClose}
        dismissible={!busy}
        footer={
          <>
            <Button variant="ghost" onClick={onClose} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button
              variant={hasRecovery ? "danger" : "primary"}
              busy={busy}
              disabled={!pickReady(current, false) || busy}
              onClick={() => void run()}
            >
              {hasRecovery ? t("credential.recoveryRemove") : t("credential.recoveryAdd")}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <p className="text-sm text-fg-muted">
            {hasRecovery ? t("credential.recoveryRemoveBody") : t("credential.recoveryAddBody")}
          </p>
          <PasswordPicker value={current} onChange={setCurrent} kinds={kinds} disabled={busy} />
          {error ? <ErrorNotice error={error} /> : null}
        </div>
      </Dialog>
      {gate.dialog}
      <RecoveryKeyDialog recoveryKey={key} subject={subject} onClose={() => setKey(null)} />
    </>
  );
}
