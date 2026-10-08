import { useRef, useState, type FormEvent } from "react";
import { Lock } from "lucide-react";
import branding from "@branding";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useApp } from "@/stores/app";
import { Button } from "@/components/ui/Button";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { PasswordField } from "@/components/ui/Field";

/**
 * Gate shown while the credential vault is locked. The master password lives only in this
 * component's input for the duration of one submit: it is cleared from the field as soon as the
 * attempt finishes, whether or not it succeeded.
 */
export function LockScreen() {
  const { t } = useT();
  const refresh = useApp((s) => s.refresh);
  const [master, setMaster] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const submit = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    if (busy || master.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      await api.app.unlock(master);
      setMaster("");
      await refresh();
    } catch (err) {
      setError(err);
      setMaster("");
      inputRef.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="flex h-full items-center justify-center bg-bg px-6">
      <form
        onSubmit={(e) => void submit(e)}
        className="flex w-full max-w-sm flex-col gap-5 rounded-2xl border border-line bg-surface-1 p-8 animate-rise-in"
      >
        <div className="flex flex-col items-center gap-3 text-center">
          <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-accent-soft text-accent">
            <Lock className="h-6 w-6" aria-hidden="true" />
          </span>
          <h1 className="text-xl font-semibold text-fg">{t("lock.title")}</h1>
          <p className="text-sm text-fg-muted">{t("lock.subtitle", { app: branding.appName })}</p>
        </div>

        <PasswordField
          ref={inputRef}
          label={t("lock.masterPassword")}
          value={master}
          onChange={(e) => setMaster(e.target.value)}
          autoFocus
          disabled={busy}
        />

        {error ? <ErrorNotice error={error} /> : null}

        <Button type="submit" variant="primary" size="lg" busy={busy} disabled={master.length === 0}>
          {busy ? t("lock.unlocking") : t("lock.unlock")}
        </Button>
      </form>
    </main>
  );
}
