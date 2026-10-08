import { useState } from "react";
import clsx from "clsx";
import { ArrowLeft, ArrowRight, CheckCircle2, KeyRound, ShieldCheck, SlidersHorizontal } from "lucide-react";
import branding from "@branding";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useApp } from "@/stores/app";
import { Button } from "@/components/ui/Button";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { PasswordField } from "@/components/ui/Field";
import { Select } from "@/components/ui/Select";
import { StrengthMeter } from "@/components/ui/StrengthMeter";
import { AUTO_LOCK_CHOICES, choiceToSecs, secsToChoice } from "@/features/settings/options";
import type { Language, ThemeSetting } from "@/types/api";

/** Mirrors `MIN_MASTER_CHARS` in the Rust credential vault; Rust re-checks it authoritatively. */
const MIN_MASTER_CHARS = 8;

type Step = 0 | 1 | 2 | 3;
const LAST: Step = 3;

export function Onboarding() {
  const { t, dir } = useT();
  const settings = useApp((s) => s.status?.settings);
  const masterExists = useApp((s) => s.status?.masterExists ?? false);
  const patchSettings = useApp((s) => s.patchSettings);
  const refresh = useApp((s) => s.refresh);

  const [step, setStep] = useState<Step>(0);
  const [master, setMaster] = useState("");
  const [confirm, setConfirm] = useState("");
  const [skipped, setSkipped] = useState(false);
  const [created, setCreated] = useState(masterExists);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const Forward = dir === "rtl" ? ArrowLeft : ArrowRight;

  const mismatch = confirm.length > 0 && confirm !== master;
  const tooShort = master.length > 0 && [...master].length < MIN_MASTER_CHARS;
  const canCreate = [...master].length >= MIN_MASTER_CHARS && master === confirm;

  const run = async (fn: () => Promise<void>): Promise<boolean> => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      return true;
    } catch (e) {
      setError(e);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const createMaster = async (): Promise<void> => {
    if (created) {
      setStep(2);
      return;
    }
    const ok = await run(() => api.app.createMaster(master));
    // The secret must not outlive the step that needed it.
    setMaster("");
    setConfirm("");
    if (ok) {
      setCreated(true);
      setSkipped(false);
      setStep(2);
    }
  };

  const skipMaster = (): void => {
    setMaster("");
    setConfirm("");
    setError(null);
    setSkipped(true);
    setStep(2);
  };

  const finish = async (): Promise<void> => {
    const ok = await run(async () => {
      await api.app.completeOnboarding(!created);
      await refresh();
    });
    if (!ok) return;
  };

  if (!settings) return null;

  const stepIcons = [ShieldCheck, KeyRound, SlidersHorizontal, CheckCircle2] as const;

  return (
    <main className="flex h-full items-center justify-center overflow-y-auto bg-bg px-6 py-10">
      <div className="flex w-full max-w-lg flex-col gap-6 rounded-2xl border border-line bg-surface-1 p-8 animate-rise-in">
        <ol className="flex items-center justify-center gap-2" aria-label={t("onboarding.progress")}>
          {stepIcons.map((Icon, i) => (
            <li
              key={i}
              aria-current={i === step ? "step" : undefined}
              className={clsx(
                "flex h-8 w-8 items-center justify-center rounded-full border text-fg-faint transition-colors",
                i === step && "border-accent bg-accent-soft text-accent",
                i < step && "border-transparent bg-accent text-accent-fg",
                i > step && "border-line",
              )}
            >
              <Icon className="h-4 w-4" aria-hidden="true" />
            </li>
          ))}
        </ol>

        {step === 0 && (
          <section className="flex flex-col gap-4 text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-fg">
              {t("onboarding.welcome.title")}
            </h1>
            <p className="text-sm leading-relaxed text-fg-muted">
              {t("onboarding.welcome.body", { app: branding.appName })}
            </p>
            <ul className="mx-auto flex max-w-sm flex-col gap-2 text-start text-sm text-fg-muted">
              <li className="flex gap-2">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" aria-hidden="true" />
                {t("onboarding.welcome.point1")}
              </li>
              <li className="flex gap-2">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" aria-hidden="true" />
                {t("onboarding.welcome.point2")}
              </li>
              <li className="flex gap-2">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-ok" aria-hidden="true" />
                {t("onboarding.welcome.point3")}
              </li>
            </ul>
          </section>
        )}

        {step === 1 && (
          <section className="flex flex-col gap-4">
            <div className="text-center">
              <h1 className="text-xl font-semibold text-fg">{t("onboarding.security.title")}</h1>
              <p className="mt-2 text-sm leading-relaxed text-fg-muted">
                {t("onboarding.security.body")}
              </p>
            </div>
            {created ? (
              <p className="rounded-xl border border-line bg-surface-2 p-4 text-sm text-fg-muted">
                {t("onboarding.security.created")}
              </p>
            ) : (
              <>
                <PasswordField
                  label={t("onboarding.security.master")}
                  value={master}
                  onChange={(e) => setMaster(e.target.value)}
                  error={tooShort ? t("onboarding.security.tooShort", { n: MIN_MASTER_CHARS }) : undefined}
                  disabled={busy}
                  autoFocus
                />
                <StrengthMeter password={master} />
                <PasswordField
                  label={t("onboarding.security.confirm")}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  error={mismatch ? t("onboarding.security.mismatch") : undefined}
                  disabled={busy}
                />
                <p className="text-xs leading-relaxed text-fg-faint">
                  {t("onboarding.security.unrecoverable")}
                </p>
              </>
            )}
            {error ? <ErrorNotice error={error} /> : null}
          </section>
        )}

        {step === 2 && (
          <section className="flex flex-col gap-4">
            <div className="text-center">
              <h1 className="text-xl font-semibold text-fg">{t("onboarding.prefs.title")}</h1>
              <p className="mt-2 text-sm text-fg-muted">{t("onboarding.prefs.body")}</p>
            </div>
            <Select<Language>
              label={t("settings.language")}
              value={settings.language}
              options={[
                { value: "en", label: "English" },
                { value: "ar", label: "العربية" },
              ]}
              onChange={(language) => void patchSettings((s) => ({ ...s, language }))}
            />
            <Select<ThemeSetting>
              label={t("settings.theme")}
              value={settings.theme}
              options={[
                { value: "system", label: t("theme.system") },
                { value: "dark", label: t("theme.dark") },
                { value: "light", label: t("theme.light") },
              ]}
              onChange={(theme) => void patchSettings((s) => ({ ...s, theme }))}
            />
            <Select<string>
              label={t("settings.autoLock")}
              value={secsToChoice(AUTO_LOCK_CHOICES, settings.security.autoLockSecs)}
              options={AUTO_LOCK_CHOICES.map((c) => ({ value: c.value, label: t(c.key) }))}
              onChange={(v) =>
                void patchSettings((s) => ({
                  ...s,
                  security: { ...s.security, autoLockSecs: choiceToSecs(AUTO_LOCK_CHOICES, v) },
                }))
              }
              disabled={!created}
            />
            {!created ? <p className="text-xs text-fg-faint">{t("onboarding.prefs.noMaster")}</p> : null}
          </section>
        )}

        {step === 3 && (
          <section className="flex flex-col gap-4 text-center">
            <h1 className="text-xl font-semibold text-fg">{t("onboarding.ready.title")}</h1>
            <p className="text-sm leading-relaxed text-fg-muted">
              {created || !skipped ? t("onboarding.ready.withMaster") : t("onboarding.ready.noMaster")}
            </p>
            <p className="text-xs leading-relaxed text-fg-faint">{t("onboarding.ready.reminder")}</p>
            {error ? <ErrorNotice error={error} /> : null}
          </section>
        )}

        <div className="flex items-center justify-between gap-3">
          {step > 0 && step !== LAST && !(step === 2 && created) ? (
            <Button variant="ghost" onClick={() => setStep((step - 1) as Step)} disabled={busy}>
              {t("common.back")}
            </Button>
          ) : (
            <span />
          )}

          <div className="flex items-center gap-2">
            {step === 1 && !created ? (
              <Button variant="ghost" onClick={skipMaster} disabled={busy}>
                {t("onboarding.security.skip")}
              </Button>
            ) : null}
            {step === 0 && (
              <Button variant="primary" icon={<Forward className="h-4 w-4" />} onClick={() => setStep(1)}>
                {t("onboarding.start")}
              </Button>
            )}
            {step === 1 && (
              <Button
                variant="primary"
                busy={busy}
                disabled={created ? false : !canCreate}
                onClick={() => void createMaster()}
              >
                {created ? t("common.continue") : t("onboarding.security.create")}
              </Button>
            )}
            {step === 2 && (
              <Button variant="primary" onClick={() => setStep(3)}>
                {t("common.continue")}
              </Button>
            )}
            {step === 3 && (
              <Button variant="primary" busy={busy} onClick={() => void finish()}>
                {t("onboarding.finish")}
              </Button>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}
