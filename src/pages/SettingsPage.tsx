import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import clsx from "clsx";
import {
  Info,
  KeyRound,
  Languages,
  Lock,
  MonitorCog,
  Palette,
  Settings as SettingsIcon,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
} from "lucide-react";
import branding from "@branding";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { pickDirectory } from "@/services/dialogs";
import { useApp } from "@/stores/app";
import { useNav } from "@/stores/nav";
import { useToasts } from "@/stores/toasts";
import { acceleratorFromEvent } from "@/features/settings/shortcut";
import {
  AUTO_LOCK_CHOICES,
  BACKGROUND_LOCK_CHOICES,
  CLIPBOARD_CHOICES,
  choiceToSecs,
  secsToChoice,
} from "@/features/settings/options";
import { Button } from "@/components/ui/Button";
import { Card, PageHeader } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import { PasswordField } from "@/components/ui/Field";
import { Select } from "@/components/ui/Select";
import { Switch } from "@/components/ui/Switch";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { useMasterGate } from "@/components/shared/useMasterGate";
import type {
  DefaultPasswordMode,
  IntegrationStatus,
  Language,
  PostEncrypt,
  Settings,
  ThemeSetting,
} from "@/types/api";

type CategoryId =
  | "general"
  | "security"
  | "encryption"
  | "passwords"
  | "appearance"
  | "language"
  | "windows"
  | "privacy"
  | "about";

const CATEGORIES: ReadonlyArray<{ id: CategoryId; icon: typeof SettingsIcon }> = [
  { id: "general", icon: SlidersHorizontal },
  { id: "security", icon: ShieldCheck },
  { id: "encryption", icon: Lock },
  { id: "passwords", icon: KeyRound },
  { id: "appearance", icon: Palette },
  { id: "language", icon: Languages },
  { id: "windows", icon: MonitorCog },
  { id: "privacy", icon: Trash2 },
  { id: "about", icon: Info },
];

/** A label/description on one side and a control on the other. */
function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 py-2.5">
      <div className="min-w-0 flex-1 basis-60">
        <p className="text-sm text-fg">{label}</p>
        {hint ? <p className="mt-0.5 text-xs text-fg-faint">{hint}</p> : null}
      </div>
      <div className="w-full sm:w-56">{children}</div>
    </div>
  );
}

function Section({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <Card className="divide-y divide-line">
      {title ? <h3 className="pb-3 text-sm font-semibold text-fg">{title}</h3> : null}
      <div className="divide-y divide-line">{children}</div>
    </Card>
  );
}

// ---------------------------------------------------------------- Master password

function MasterDialog({ open, exists, onClose }: { open: boolean; exists: boolean; onClose: () => void }) {
  const { t } = useT();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (!open) {
      setCurrent("");
      setNext("");
      setConfirm("");
      setError(null);
    }
  }, [open]);

  const mismatch = confirm.length > 0 && confirm !== next;
  const ready = next.length > 0 && confirm === next && (!exists || current.length > 0) && !busy;

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      if (exists) await api.app.changeMaster(current, next);
      else await api.app.createMaster(next);
      await useApp.getState().refresh();
      useToasts.getState().push("success", t(exists ? "settings.master.changed" : "settings.master.created"));
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
      setCurrent("");
      setNext("");
      setConfirm("");
    }
  };

  return (
    <Dialog
      open={open}
      title={t(exists ? "settings.master.change" : "settings.master.create")}
      description={t("settings.master.warning")}
      onClose={onClose}
      dismissible={!busy}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button variant="primary" busy={busy} disabled={!ready} onClick={() => void submit()}>
            {t(exists ? "settings.master.change" : "settings.master.create")}
          </Button>
        </>
      }
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) void submit();
        }}
      >
        {exists ? (
          <PasswordField
            label={t("settings.master.current")}
            value={current}
            autoFocus
            disabled={busy}
            onChange={(e) => setCurrent(e.target.value)}
          />
        ) : null}
        <PasswordField
          label={t("settings.master.new")}
          value={next}
          autoFocus={!exists}
          disabled={busy}
          onChange={(e) => setNext(e.target.value)}
        />
        <PasswordField
          label={t("settings.master.confirm")}
          value={confirm}
          disabled={busy}
          error={mismatch ? t("picker.mismatch") : null}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {error ? <ErrorNotice error={error} /> : null}
      </form>
    </Dialog>
  );
}

// ---------------------------------------------------------------- Panic shortcut capture

function ShortcutCapture({
  value,
  onCommit,
  onReset,
  isDefault,
}: {
  value: string;
  onCommit: (accelerator: string) => void;
  onReset: () => void;
  isDefault: boolean;
}) {
  const { t } = useT();
  const [capturing, setCapturing] = useState(false);
  const ref = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (capturing) ref.current?.focus();
  }, [capturing]);

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        ref={ref}
        type="button"
        aria-label={t("settings.panic.title")}
        onClick={() => setCapturing(true)}
        onBlur={() => setCapturing(false)}
        onKeyDown={(e) => {
          if (!capturing) return;
          e.preventDefault();
          e.stopPropagation();
          if (e.key === "Escape" && !e.ctrlKey && !e.altKey && !e.metaKey) {
            setCapturing(false);
            return;
          }
          const accel = acceleratorFromEvent(e);
          if (accel) {
            setCapturing(false);
            onCommit(accel);
          }
        }}
        className={clsx(
          "ltr-text h-10 min-w-[11rem] rounded-xl border px-3 text-sm",
          capturing ? "border-accent bg-surface-3 text-fg-muted" : "border-line bg-surface-2 text-fg hover:border-fg-faint",
        )}
      >
        {capturing ? t("settings.panic.capture") : value}
      </button>
      {!isDefault ? (
        <Button size="sm" variant="ghost" onClick={onReset}>
          {t("settings.panic.reset")}
        </Button>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------- Page

export function SettingsPage() {
  const { t, number } = useT();
  const status = useApp((s) => s.status);
  const patchSettings = useApp((s) => s.patchSettings);
  const go = useNav((s) => s.go);
  const gate = useMasterGate();
  const tabsId = useId();

  const [category, setCategory] = useState<CategoryId>("general");
  const [error, setError] = useState<unknown>(null);
  const [masterOpen, setMasterOpen] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);

  const [integration, setIntegration] = useState<IntegrationStatus | null>(null);
  const [integrationBusy, setIntegrationBusy] = useState(false);

  useEffect(() => {
    let live = true;
    api.integration
      .status()
      .then((s) => {
        if (live) setIntegration(s);
      })
      .catch((e: unknown) => {
        if (live) setError(e);
      });
    return () => {
      live = false;
    };
  }, []);

  if (!status) return null;
  const s = status.settings;

  const update = async (fn: (cur: Settings) => Settings): Promise<void> => {
    setError(null);
    try {
      await patchSettings(fn);
    } catch (e) {
      setError(e);
      // The backend may have refused (for example a shortcut owned by another app): resync.
      await useApp.getState().refresh().catch(() => undefined);
    }
  };

  const toggleIntegration = async (kind: "autostart" | "contextMenu", enabled: boolean): Promise<void> => {
    setError(null);
    setIntegrationBusy(true);
    try {
      setIntegration(
        kind === "autostart" ? await api.integration.setAutostart(enabled) : await api.integration.setContextMenu(enabled),
      );
    } catch (e) {
      setError(e);
    } finally {
      setIntegrationBusy(false);
    }
  };

  const chooseDir = async (): Promise<void> => {
    setError(null);
    try {
      const dir = await pickDirectory();
      if (dir) await update((c) => ({ ...c, encryption: { ...c.encryption, defaultOutputDir: dir } }));
    } catch (e) {
      setError(e);
    }
  };

  const resetApp = async (): Promise<void> => {
    const master = await gate.ask("always");
    if (master === null) return;
    await api.app.reset(master);
    setConfirmReset(false);
    await useApp.getState().load();
    go({ name: "home" });
  };

  const autoLockOptions = AUTO_LOCK_CHOICES.map((c) => ({ value: c.value, label: t(c.key) }));
  const clipboardOptions = CLIPBOARD_CHOICES.map((c) => ({ value: c.value, label: t(c.key) }));
  const backgroundOptions = BACKGROUND_LOCK_CHOICES.map((c) => ({ value: c.value, label: t(c.key) }));
  const backgroundValue =
    BACKGROUND_LOCK_CHOICES.find((c) => c.minutes === s.security.backgroundLockMinutes)?.value ?? "never";

  const panel = ((): ReactNode => {
    switch (category) {
      case "general":
        return (
          <Section>
            <Switch
              checked={s.general.startMinimized}
              onChange={(v) => void update((c) => ({ ...c, general: { ...c.general, startMinimized: v } }))}
              label={t("settings.general.startMinimized")}
              description={t("settings.general.startMinimizedHint")}
            />
            <Switch
              checked={s.general.lockOnMinimize}
              onChange={(v) => void update((c) => ({ ...c, general: { ...c.general, lockOnMinimize: v } }))}
              label={t("settings.general.lockOnMinimize")}
              description={t("settings.general.lockOnMinimizeHint")}
            />
            <Switch
              checked={s.general.rememberWindowSize}
              onChange={(v) => void update((c) => ({ ...c, general: { ...c.general, rememberWindowSize: v } }))}
              label={t("settings.general.rememberWindowSize")}
              description={t("settings.general.rememberWindowSizeHint")}
            />
          </Section>
        );

      case "security":
        return (
          <>
            <Section title={t("settings.security.locking")}>
              <Row label={t("settings.autoLock")} hint={t("settings.autoLockHint")}>
                <Select
                  label={t("settings.autoLock")}
                  value={secsToChoice(AUTO_LOCK_CHOICES, s.security.autoLockSecs)}
                  options={autoLockOptions}
                  onChange={(v) =>
                    void update((c) => ({
                      ...c,
                      security: { ...c.security, autoLockSecs: choiceToSecs(AUTO_LOCK_CHOICES, v) },
                    }))
                  }
                />
              </Row>
              <Row label={t("settings.backgroundLock")} hint={t("settings.backgroundLockHint")}>
                <Select
                  label={t("settings.backgroundLock")}
                  value={backgroundValue}
                  options={backgroundOptions}
                  onChange={(v) =>
                    void update((c) => ({
                      ...c,
                      security: {
                        ...c.security,
                        backgroundLockMinutes: BACKGROUND_LOCK_CHOICES.find((x) => x.value === v)?.minutes ?? null,
                      },
                    }))
                  }
                />
              </Row>
              <Switch
                checked={s.security.lockOnSessionLock}
                onChange={(v) => void update((c) => ({ ...c, security: { ...c.security, lockOnSessionLock: v } }))}
                label={t("settings.lockOnSessionLock")}
                description={t("settings.lockOnSessionLockHint")}
              />
              <Switch
                checked={s.security.lockOnSleep}
                onChange={(v) => void update((c) => ({ ...c, security: { ...c.security, lockOnSleep: v } }))}
                label={t("settings.lockOnSleep")}
                description={t("settings.lockOnSleepHint")}
              />
              <div className="py-2.5">
                <p className="text-sm text-fg">{t("settings.panic.title")}</p>
                <p className="mb-2 mt-0.5 text-xs text-fg-faint">{t("settings.panic.hint")}</p>
                <ShortcutCapture
                  value={s.security.panicShortcut}
                  isDefault={s.security.panicShortcut === branding.defaultPanicShortcut}
                  onCommit={(accel) => void update((c) => ({ ...c, security: { ...c.security, panicShortcut: accel } }))}
                  onReset={() =>
                    void update((c) => ({
                      ...c,
                      security: { ...c.security, panicShortcut: branding.defaultPanicShortcut },
                    }))
                  }
                />
              </div>
            </Section>

            <Section title={t("settings.security.reauth")}>
              <Switch
                checked={s.security.requireMasterForSensitive}
                onChange={(v) =>
                  void update((c) => ({ ...c, security: { ...c.security, requireMasterForSensitive: v } }))
                }
                disabled={!status.masterExists}
                label={t("settings.requireMasterSensitive")}
                description={t("settings.requireMasterSensitiveHint")}
              />
              <Switch
                checked={s.security.requireMasterToReveal}
                onChange={(v) => void update((c) => ({ ...c, security: { ...c.security, requireMasterToReveal: v } }))}
                disabled={!status.masterExists}
                label={t("settings.requireMasterReveal")}
                description={t("settings.requireMasterRevealHint")}
              />
            </Section>

            <Section title={t("settings.master.title")}>
              <div className="flex flex-wrap items-center justify-between gap-3 py-2.5">
                <p className="min-w-0 flex-1 basis-60 text-sm text-fg-muted">
                  {t(status.masterExists ? "settings.master.hint" : "settings.master.none")}
                </p>
                <Button variant="secondary" onClick={() => setMasterOpen(true)}>
                  {t(status.masterExists ? "settings.master.change" : "settings.master.create")}
                </Button>
              </div>
            </Section>
          </>
        );

      case "encryption":
        return (
          <Section>
            <div className="flex flex-wrap items-center justify-between gap-3 py-2.5">
              <div className="min-w-0 flex-1 basis-60">
                <p className="text-sm text-fg">{t("settings.outDir")}</p>
                <p className="ltr-text mt-0.5 truncate text-xs text-fg-faint" title={s.encryption.defaultOutputDir ?? ""}>
                  {s.encryption.defaultOutputDir ?? t("settings.outDirSource")}
                </p>
              </div>
              <div className="flex gap-2">
                <Button size="sm" variant="secondary" onClick={() => void chooseDir()}>
                  {t("common.choose")}
                </Button>
                {s.encryption.defaultOutputDir ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => void update((c) => ({ ...c, encryption: { ...c.encryption, defaultOutputDir: null } }))}
                  >
                    {t("common.reset")}
                  </Button>
                ) : null}
              </div>
            </div>
            <Row label={t("settings.postEncrypt")} hint={t("settings.postEncryptHint")}>
              <Select<PostEncrypt>
                label={t("settings.postEncrypt")}
                value={s.encryption.postEncrypt}
                options={[
                  { value: "keep_original", label: t("settings.postEncrypt.keep_original") },
                  { value: "remove_original", label: t("settings.postEncrypt.remove_original") },
                ]}
                onChange={(v) => void update((c) => ({ ...c, encryption: { ...c.encryption, postEncrypt: v } }))}
              />
            </Row>
            <Row label={t("settings.defaultMode")} hint={t("settings.defaultModeHint")}>
              <Select<DefaultPasswordMode>
                label={t("settings.defaultMode")}
                value={s.encryption.defaultPasswordMode}
                options={[
                  { value: "auto", label: t("settings.defaultMode.auto") },
                  { value: "ask", label: t("settings.defaultMode.ask") },
                  { value: "require_master", label: t("settings.defaultMode.require_master") },
                ]}
                onChange={(v) => void update((c) => ({ ...c, encryption: { ...c.encryption, defaultPasswordMode: v } }))}
              />
            </Row>
          </Section>
        );

      case "passwords":
        return (
          <>
            <Section title={t("settings.generator.title")}>
              <div className="py-2.5">
                <label htmlFor={`${tabsId}-len`} className="flex items-center justify-between text-sm text-fg">
                  <span>{t("settings.generator.length")}</span>
                  <span className="text-fg-muted">{number(s.passwords.generatorLength)}</span>
                </label>
                <input
                  id={`${tabsId}-len`}
                  type="range"
                  min={8}
                  max={64}
                  step={1}
                  value={s.passwords.generatorLength}
                  onChange={(e) => {
                    const n = Number(e.target.value);
                    void update((c) => ({ ...c, passwords: { ...c.passwords, generatorLength: n } }));
                  }}
                  className="mt-2 w-full accent-[var(--accent,currentColor)]"
                />
              </div>
              {(
                [
                  ["generatorUpper", "settings.generator.upper"],
                  ["generatorLower", "settings.generator.lower"],
                  ["generatorDigits", "settings.generator.digits"],
                  ["generatorSymbols", "settings.generator.symbols"],
                  ["generatorAvoidAmbiguous", "settings.generator.avoidAmbiguous"],
                ] as const
              ).map(([field, key]) => (
                <Switch
                  key={field}
                  checked={s.passwords[field]}
                  onChange={(v) => void update((c) => ({ ...c, passwords: { ...c.passwords, [field]: v } }))}
                  label={t(key)}
                />
              ))}
            </Section>
            <Section>
              <Row label={t("settings.clipboard")} hint={t("settings.clipboardHint")}>
                <Select
                  label={t("settings.clipboard")}
                  value={secsToChoice(CLIPBOARD_CHOICES, s.passwords.clipboardClearSecs)}
                  options={clipboardOptions}
                  onChange={(v) =>
                    void update((c) => ({
                      ...c,
                      passwords: { ...c.passwords, clipboardClearSecs: choiceToSecs(CLIPBOARD_CHOICES, v) },
                    }))
                  }
                />
              </Row>
            </Section>
          </>
        );

      case "appearance":
        return (
          <Section>
            <Row label={t("settings.theme")} hint={t("settings.themeHint")}>
              <Select<ThemeSetting>
                label={t("settings.theme")}
                value={s.theme}
                options={[
                  { value: "system", label: t("theme.system") },
                  { value: "dark", label: t("theme.dark") },
                  { value: "light", label: t("theme.light") },
                ]}
                onChange={(v) => void update((c) => ({ ...c, theme: v }))}
              />
            </Row>
          </Section>
        );

      case "language":
        return (
          <Section>
            <Row label={t("settings.language")} hint={t("settings.languageHint")}>
              <Select<Language>
                label={t("settings.language")}
                value={s.language}
                options={[
                  { value: "en", label: t("settings.lang.en") },
                  { value: "ar", label: t("settings.lang.ar") },
                ]}
                onChange={(v) => void update((c) => ({ ...c, language: v }))}
              />
            </Row>
          </Section>
        );

      case "windows":
        return (
          <Section>
            {integration && !integration.supported ? (
              <p className="py-3 text-sm text-fg-muted">{t("settings.win.unsupported")}</p>
            ) : (
              <>
                <Switch
                  checked={integration?.autostart ?? false}
                  disabled={!integration || integrationBusy}
                  onChange={(v) => void toggleIntegration("autostart", v)}
                  label={t("settings.win.autostart", { app: branding.appName })}
                  description={t("settings.win.autostartHint")}
                />
                <Switch
                  checked={integration?.contextMenu ?? false}
                  disabled={!integration || integrationBusy}
                  onChange={(v) => void toggleIntegration("contextMenu", v)}
                  label={t("settings.win.contextMenu")}
                  description={t("settings.win.contextMenuHint")}
                />
                <Row
                  label={t("settings.win.fileAssoc", { ext: `.${branding.fileExtension}` })}
                  hint={t("settings.win.fileAssocHint")}
                >
                  <p className="text-sm text-fg-muted sm:text-end">
                    {t(integration?.fileAssociation ? "settings.win.registered" : "settings.win.notRegistered")}
                  </p>
                </Row>
                <p className="py-3 text-xs text-fg-faint">{t("settings.win.uninstallNote")}</p>
              </>
            )}
          </Section>
        );

      case "privacy":
        return (
          <>
            <Section>
              <Switch
                checked={s.historyEnabled}
                onChange={(v) => void update((c) => ({ ...c, historyEnabled: v }))}
                label={t("activity.enabled")}
                description={t("activity.enabledHint")}
              />
              <div className="flex flex-wrap items-center justify-between gap-3 py-2.5">
                <p className="min-w-0 flex-1 basis-60 text-sm text-fg">{t("settings.privacy.clearHistory")}</p>
                <Button variant="secondary" onClick={() => setConfirmClear(true)}>
                  {t("activity.clear")}
                </Button>
              </div>
              <p className="py-3 text-xs text-fg-faint">{t("settings.privacy.local")}</p>
            </Section>
            <Section title={t("settings.privacy.reset.title")}>
              <div className="flex flex-wrap items-center justify-between gap-3 py-2.5">
                <p className="min-w-0 flex-1 basis-60 text-sm text-fg-muted">{t("settings.privacy.reset.body")}</p>
                <Button variant="danger" onClick={() => setConfirmReset(true)}>
                  {t("settings.privacy.reset.action")}
                </Button>
              </div>
            </Section>
          </>
        );

      case "about":
        return (
          <Section>
            <div className="py-3">
              <p className="text-base font-semibold text-fg">{branding.appName}</p>
              <p className="mt-0.5 text-sm text-fg-muted">{t("settings.about.version", { v: status.version })}</p>
              <p className="mt-2 text-sm text-fg-muted">{t("settings.about.tagline")}</p>
            </div>
            <ul className="flex flex-col gap-2 py-3 text-sm text-fg-muted">
              <li>{t("settings.about.crypto")}</li>
              <li>{t("settings.about.offline")}</li>
              <li>{t("settings.about.noRecovery")}</li>
              <li>{t("settings.about.ssd")}</li>
            </ul>
          </Section>
        );
    }
  })();

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={t("settings.title")} subtitle={t("settings.subtitle")} />

      <div className="flex flex-col gap-6 md:flex-row">
        <div
          role="tablist"
          aria-orientation="vertical"
          aria-label={t("settings.title")}
          className="flex shrink-0 flex-row flex-wrap gap-1 md:w-52 md:flex-col"
        >
          {CATEGORIES.map(({ id, icon: Icon }) => (
            <button
              key={id}
              id={`${tabsId}-tab-${id}`}
              type="button"
              role="tab"
              aria-selected={category === id}
              aria-controls={`${tabsId}-panel`}
              onClick={() => setCategory(id)}
              className={clsx(
                "flex items-center gap-2 rounded-xl px-3 py-2 text-start text-sm transition-colors",
                category === id ? "bg-surface-3 text-fg" : "text-fg-muted hover:bg-surface-2 hover:text-fg",
              )}
            >
              <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
              {t(`settings.cat.${id}`)}
            </button>
          ))}
        </div>

        <div
          id={`${tabsId}-panel`}
          role="tabpanel"
          aria-labelledby={`${tabsId}-tab-${category}`}
          className="flex min-w-0 flex-1 flex-col gap-4"
        >
          {error ? <ErrorNotice error={error} /> : null}
          {panel}
        </div>
      </div>

      <MasterDialog open={masterOpen} exists={status.masterExists} onClose={() => setMasterOpen(false)} />

      <ConfirmDialog
        open={confirmClear}
        danger
        title={t("activity.clear")}
        body={t("activity.clearBody")}
        confirmLabel={t("activity.clear")}
        onClose={() => setConfirmClear(false)}
        onConfirm={async () => {
          await api.activity.clear();
          setConfirmClear(false);
          useToasts.getState().push("success", t("settings.privacy.cleared"));
        }}
      />

      <ConfirmDialog
        open={confirmReset}
        danger
        title={t("settings.privacy.reset.title")}
        body={t("settings.privacy.reset.confirmBody")}
        confirmLabel={t("settings.privacy.reset.action")}
        onClose={() => setConfirmReset(false)}
        onConfirm={resetApp}
      />

      {gate.dialog}
    </div>
  );
}
