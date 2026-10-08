import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useApp } from "@/stores/app";
import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { PasswordField } from "@/components/ui/Field";

/**
 * What an action needs from the master password:
 * - `sensitive`: deleting, changing passwords or recovery (setting `requireMasterForSensitive`)
 * - `reveal`: showing or copying a saved password (setting `requireMasterToReveal`)
 * - `always`: unconditional re-authentication (default password in "require master" mode)
 */
export type GateKind = "sensitive" | "reveal" | "always";

/** `undefined`: no master needed. `string`: the verified master. `null`: the user cancelled. */
export type GateResult = string | null | undefined;

export function gateNeeded(kind: GateKind): boolean {
  const status = useApp.getState().status;
  if (!status || !status.masterExists) return false;
  if (kind === "always") return true;
  return kind === "sensitive"
    ? status.settings.security.requireMasterForSensitive
    : status.settings.security.requireMasterToReveal;
}

interface Pending {
  resolve: (r: GateResult) => void;
}

/**
 * Re-authentication prompt. `ask(kind)` resolves immediately when the current settings do not
 * require the master password; otherwise it shows a dialog, verifies the typed master in Rust, and
 * hands the verified value back for the single call that needs it. The value is never stored.
 */
export function useMasterGate(): {
  ask: (kind: GateKind) => Promise<GateResult>;
  dialog: ReactNode;
} {
  const [pending, setPending] = useState<Pending | null>(null);
  const ref = useRef<Pending | null>(null);

  const finish = useCallback((r: GateResult) => {
    const p = ref.current;
    ref.current = null;
    setPending(null);
    p?.resolve(r);
  }, []);

  const ask = useCallback((kind: GateKind): Promise<GateResult> => {
    if (!gateNeeded(kind)) return Promise.resolve(undefined);
    return new Promise<GateResult>((resolve) => {
      ref.current?.resolve(null);
      const p = { resolve };
      ref.current = p;
      setPending(p);
    });
  }, []);

  // A pending prompt must not leak an unresolved promise when the owner unmounts (e.g. on lock).
  useEffect(() => () => ref.current?.resolve(null), []);

  return { ask, dialog: pending ? <MasterDialog onDone={finish} /> : null };
}

function MasterDialog({ onDone }: { onDone: (r: GateResult) => void }) {
  const { t } = useT();
  const [master, setMaster] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    if (busy || master === "") return;
    setBusy(true);
    setError(null);
    try {
      await api.app.verifyMaster(master);
      onDone(master);
    } catch (err) {
      setError(err);
      setMaster("");
      setBusy(false);
    }
  };

  return (
    <Dialog
      open
      title={t("master.title")}
      description={t("master.body")}
      onClose={() => onDone(null)}
      footer={
        <>
          <Button variant="ghost" onClick={() => onDone(null)} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            busy={busy}
            disabled={master === ""}
            type="submit"
            form="master-gate-form"
          >
            {t("master.confirm")}
          </Button>
        </>
      }
    >
      <form id="master-gate-form" onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
        <PasswordField
          label={t("lock.masterPassword")}
          value={master}
          onChange={(e) => setMaster(e.target.value)}
          disabled={busy}
        />
        {error ? <ErrorNotice error={error} /> : null}
      </form>
    </Dialog>
  );
}
