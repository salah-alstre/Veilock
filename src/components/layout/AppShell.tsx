import { useEffect } from "react";
import { useNav } from "@/stores/nav";
import { useSearch } from "@/stores/search";
import { Sidebar } from "@/components/layout/Sidebar";
import { GlobalSearch } from "@/features/search/GlobalSearch";
import { HomePage } from "@/pages/HomePage";
import { ProtectPage } from "@/pages/ProtectPage";
import { UnlockPage } from "@/pages/UnlockPage";
import { VaultsPage } from "@/pages/VaultsPage";
import { VaultDetailPage } from "@/pages/VaultDetailPage";
import { PasswordsPage } from "@/pages/PasswordsPage";
import { RecentPage } from "@/pages/RecentPage";
import { FavoritesPage } from "@/pages/FavoritesPage";
import { ActivityPage } from "@/pages/ActivityPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { ItemDetailsPage } from "@/pages/ItemDetailsPage";

function CurrentPage() {
  const page = useNav((s) => s.page);
  switch (page.name) {
    case "home":
      return <HomePage />;
    case "protect":
      return <ProtectPage />;
    case "unlock":
      return <UnlockPage />;
    case "vaults":
      return <VaultsPage />;
    case "vault":
      return <VaultDetailPage key={page.id} id={page.id} />;
    case "passwords":
      return <PasswordsPage />;
    case "recent":
      return <RecentPage />;
    case "favorites":
      return <FavoritesPage />;
    case "activity":
      return <ActivityPage />;
    case "settings":
      return <SettingsPage />;
    case "item":
      return <ItemDetailsPage key={page.id} id={page.id} />;
  }
}

/** The unlocked application frame. Global events are wired once in `App`, not here. */
export function AppShell() {
  const page = useNav((s) => s.page);

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        const s = useSearch.getState();
        if (s.open) s.hide();
        else s.show();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="flex h-full min-h-0 w-full bg-bg text-fg">
      <Sidebar />
      <main id="main" tabIndex={-1} className="min-w-0 flex-1 overflow-y-auto outline-none">
        <div key={page.name} className="mx-auto w-full max-w-5xl animate-fade-in px-8 py-8">
          <CurrentPage />
        </div>
      </main>
      <GlobalSearch />
    </div>
  );
}
