import { useEffect } from "react";
import { AlertTriangle } from "lucide-react";
import { useT } from "@/i18n";
import { selectIsGated, useApp } from "@/stores/app";
import { useGlobalEvents } from "@/hooks/useGlobalEvents";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { Toasts } from "@/components/ui/Toasts";
import { AppShell } from "@/components/layout/AppShell";
import { DropOverlay } from "@/components/layout/DropOverlay";
import { LockScreen } from "@/features/lock/LockScreen";
import { Onboarding } from "@/features/onboarding/Onboarding";

function Splash() {
  return (
    <div className="flex h-full items-center justify-center bg-bg">
      <Spinner className="h-6 w-6 text-fg-faint" />
    </div>
  );
}

function LoadFailed({ onRetry }: { onRetry: () => void }) {
  const { t } = useT();
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 bg-bg px-6 text-center">
      <AlertTriangle className="h-8 w-8 text-warn" aria-hidden="true" />
      <p className="max-w-sm text-sm text-fg-muted">{t("app.loadFailed")}</p>
      <Button variant="primary" onClick={onRetry}>
        {t("common.retry")}
      </Button>
    </div>
  );
}

export function App() {
  const { t } = useT();
  const status = useApp((s) => s.status);
  const ready = useApp((s) => s.ready);
  const loadError = useApp((s) => s.loadError);
  const epoch = useApp((s) => s.epoch);
  const load = useApp((s) => s.load);
  const hovering = useGlobalEvents(t);

  useEffect(() => {
    void load();
  }, [load]);

  let body;
  if (!ready) body = <Splash />;
  else if (loadError || !status) body = <LoadFailed onRetry={() => void load()} />;
  else if (!status.settings.onboarded) body = <Onboarding key={epoch} />;
  else if (selectIsGated(status)) body = <LockScreen key={epoch} />;
  else body = <AppShell key={epoch} />;

  return (
    <>
      {body}
      <DropOverlay visible={hovering && ready && !loadError} />
      <Toasts />
    </>
  );
}
