import { UploadCloud } from "lucide-react";
import { useT } from "@/i18n";

/** Shown while the OS reports a drag over the window. The actual drop is handled by the webview
 * bridge in `useGlobalEvents`, so this is purely visual and never intercepts pointer events. */
export function DropOverlay({ visible }: { visible: boolean }) {
  const { t } = useT();
  if (!visible) return null;
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-40 flex items-center justify-center bg-black/70 backdrop-blur-sm"
    >
      <div className="flex flex-col items-center gap-3 rounded-3xl border-2 border-dashed border-accent bg-surface-1 px-12 py-10 text-center">
        <UploadCloud className="h-10 w-10 text-accent" />
        <p className="text-base font-medium text-fg">{t("drop.title")}</p>
      </div>
    </div>
  );
}
