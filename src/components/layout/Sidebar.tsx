import type { ComponentType } from "react";
import clsx from "clsx";
import {
  Activity,
  FolderLock,
  Home,
  KeyRound,
  Languages,
  Lock,
  Monitor,
  Moon,
  OctagonAlert,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Settings as SettingsIcon,
  ShieldCheck,
  Star,
  Sun,
  Clock,
} from "lucide-react";
import branding from "@branding";
import { useT } from "@/i18n";
import { useNav, topLevelOf, type TopLevel } from "@/stores/nav";
import { useApp } from "@/stores/app";
import { useToasts } from "@/stores/toasts";
import { useSearch } from "@/stores/search";
import { toAppError } from "@/services/errors";
import * as api from "@/services/api";
import type { ThemeSetting } from "@/types/api";

interface NavEntry {
  id: TopLevel;
  icon: ComponentType<{ className?: string }>;
}

const ENTRIES: readonly NavEntry[] = [
  { id: "home", icon: Home },
  { id: "protect", icon: ShieldCheck },
  { id: "vaults", icon: FolderLock },
  { id: "passwords", icon: KeyRound },
  { id: "recent", icon: Clock },
  { id: "favorites", icon: Star },
  { id: "activity", icon: Activity },
  { id: "settings", icon: SettingsIcon },
];

const THEME_ORDER: readonly ThemeSetting[] = ["system", "dark", "light"];
const THEME_ICON: Record<ThemeSetting, ComponentType<{ className?: string }>> = {
  system: Monitor,
  dark: Moon,
  light: Sun,
};

interface RailButtonProps {
  icon: ComponentType<{ className?: string }>;
  label: string;
  collapsed: boolean;
  onClick: () => void;
  active?: boolean;
  current?: boolean;
  trailing?: string;
}

function RailButton({ icon: Icon, label, collapsed, onClick, active, current, trailing }: RailButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={current ? "page" : undefined}
      aria-label={collapsed ? label : undefined}
      title={collapsed ? label : undefined}
      className={clsx(
        "flex h-10 w-full items-center gap-3 rounded-xl px-3 text-sm font-medium transition-colors",
        active ? "bg-accent-soft text-accent" : "text-fg-muted hover:bg-surface-3 hover:text-fg",
        collapsed && "justify-center px-0",
      )}
    >
      <Icon className="h-[18px] w-[18px] shrink-0" />
      {collapsed ? null : <span className="min-w-0 flex-1 truncate text-start">{label}</span>}
      {collapsed || !trailing ? null : <span className="text-xs text-fg-faint">{trailing}</span>}
    </button>
  );
}

export function Sidebar() {
  const { t, lang } = useT();
  const page = useNav((s) => s.page);
  const go = useNav((s) => s.go);
  const collapsed = useNav((s) => s.sidebarCollapsed);
  const toggle = useNav((s) => s.toggleSidebar);
  const settings = useApp((s) => s.status?.settings);
  const patchSettings = useApp((s) => s.patchSettings);
  const handleLocked = useApp((s) => s.handleLocked);
  const current = topLevelOf(page);

  const theme: ThemeSetting = settings?.theme ?? "system";
  const ThemeIcon = THEME_ICON[theme];

  const cycleTheme = (): void => {
    const next = THEME_ORDER[(THEME_ORDER.indexOf(theme) + 1) % THEME_ORDER.length] ?? "system";
    void patchSettings((s) => ({ ...s, theme: next })).catch((e: unknown) =>
      useToasts.getState().push("error", t(`error.${toAppError(e).code}`)),
    );
  };

  const toggleLanguage = (): void => {
    const next = lang === "en" ? "ar" : "en";
    void patchSettings((s) => ({ ...s, language: next })).catch((e: unknown) =>
      useToasts.getState().push("error", t(`error.${toAppError(e).code}`)),
    );
  };

  const lock = (): void => {
    void api.app
      .lock()
      .catch(() => undefined)
      .then(() => handleLocked());
  };

  const panic = (): void => {
    void api.app
      .panicLock()
      .catch(() => undefined)
      .then(() => handleLocked());
  };

  return (
    <nav
      aria-label={t("nav.label")}
      className={clsx(
        "flex shrink-0 flex-col border-e border-line bg-surface-1 transition-[width] duration-150",
        collapsed ? "w-[68px]" : "w-60",
      )}
    >
      <div className={clsx("flex h-14 items-center gap-2.5 px-4", collapsed && "justify-center px-0")}>
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-accent text-accent-fg">
          <ShieldCheck className="h-[18px] w-[18px]" aria-hidden="true" />
        </span>
        {collapsed ? null : (
          <span className="truncate text-[15px] font-semibold tracking-tight text-fg">{branding.appName}</span>
        )}
      </div>

      <div className="px-3 pb-1">
        <RailButton
          icon={Search}
          label={t("nav.search")}
          trailing="Ctrl K"
          collapsed={collapsed}
          onClick={() => useSearch.getState().show()}
        />
      </div>

      <ul className="flex flex-1 flex-col gap-1 overflow-y-auto px-3 py-2">
        {ENTRIES.map(({ id, icon }) => (
          <li key={id}>
            <RailButton
              icon={icon}
              label={t(`nav.${id}`)}
              collapsed={collapsed}
              active={current === id}
              current={current === id}
              onClick={() => go({ name: id })}
            />
          </li>
        ))}
      </ul>

      <div className="flex flex-col gap-1 border-t border-line px-3 py-3">
        <RailButton
          icon={Languages}
          label={t("nav.language")}
          trailing={lang === "en" ? "العربية" : "English"}
          collapsed={collapsed}
          onClick={toggleLanguage}
        />
        <RailButton
          icon={ThemeIcon}
          label={t("nav.theme")}
          trailing={t(`theme.${theme}`)}
          collapsed={collapsed}
          onClick={cycleTheme}
        />
        <RailButton icon={Lock} label={t("nav.lock")} collapsed={collapsed} onClick={lock} />
        <RailButton
          icon={OctagonAlert}
          label={t("nav.panic")}
          trailing={settings?.security.panicShortcut}
          collapsed={collapsed}
          onClick={panic}
        />
        <RailButton
          icon={collapsed ? PanelLeftOpen : PanelLeftClose}
          label={collapsed ? t("nav.expand") : t("nav.collapse")}
          collapsed={collapsed}
          onClick={toggle}
        />
      </div>
    </nav>
  );
}
