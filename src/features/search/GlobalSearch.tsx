import { useEffect, useRef, useState } from "react";
import type { ComponentType, KeyboardEvent } from "react";
import { Archive, FileLock2, FolderLock, KeyRound, Search } from "lucide-react";
import { useT } from "@/i18n";
import * as api from "@/services/api";
import { useNav } from "@/stores/nav";
import { useSearch } from "@/stores/search";
import { Dialog } from "@/components/ui/Dialog";
import { Spinner } from "@/components/ui/Spinner";
import { ErrorNotice } from "@/components/ui/ErrorNotice";
import type { SearchHit } from "@/types/api";

const ICONS: Record<SearchHit["kind"], ComponentType<{ className?: string }>> = {
  item: FileLock2,
  vault: FolderLock,
  vaultItem: Archive,
  password: KeyRound,
};

const DEBOUNCE_MS = 150;

/**
 * Searches names only. Rust decides what is searchable: locked vaults and a locked credential
 * vault contribute nothing, so this component cannot leak their contents.
 */
export function GlobalSearch() {
  const { t } = useT();
  const open = useSearch((s) => s.open);
  const hide = useSearch((s) => s.hide);
  const go = useNav((s) => s.go);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [active, setActive] = useState(0);
  const seq = useRef(0);

  useEffect(() => {
    if (!open) {
      setQuery("");
      setHits([]);
      setError(null);
      setActive(0);
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const q = query.trim();
    if (q === "") {
      setHits([]);
      setBusy(false);
      return;
    }
    const mine = ++seq.current;
    setBusy(true);
    const timer = setTimeout(() => {
      api.search
        .all(q)
        .then((res) => {
          if (mine !== seq.current) return;
          setHits(res);
          setActive(0);
          setError(null);
        })
        .catch((e: unknown) => {
          if (mine === seq.current) setError(e);
        })
        .finally(() => {
          if (mine === seq.current) setBusy(false);
        });
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [query, open]);

  const choose = (hit: SearchHit): void => {
    hide();
    switch (hit.kind) {
      case "item":
        go({ name: "item", id: hit.id });
        break;
      case "vault":
        go({ name: "vault", id: hit.id });
        break;
      case "vaultItem":
        go({ name: "vault", id: hit.vaultId ?? hit.id });
        break;
      case "password":
        go({ name: "passwords" });
        break;
    }
  };

  const onKeyDown = (e: KeyboardEvent): void => {
    if (hits.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => (a + 1) % hits.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => (a - 1 + hits.length) % hits.length);
    } else if (e.key === "Enter") {
      const hit = hits[active];
      if (hit) {
        e.preventDefault();
        choose(hit);
      }
    }
  };

  const trimmed = query.trim();

  return (
    <Dialog open={open} title={t("search.title")} onClose={hide} wide>
      <div className="flex flex-col gap-3" onKeyDown={onKeyDown}>
        <div className="flex items-center gap-2 rounded-xl border border-line bg-surface-1 px-3 focus-within:border-accent">
          <Search className="h-4 w-4 shrink-0 text-fg-faint" aria-hidden="true" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value.slice(0, 100))}
            placeholder={t("search.placeholder")}
            aria-label={t("search.placeholder")}
            autoComplete="off"
            spellCheck={false}
            className="h-11 min-w-0 flex-1 bg-transparent text-sm text-fg outline-none placeholder:text-fg-faint"
          />
          {busy ? <Spinner className="h-4 w-4 text-fg-faint" /> : null}
        </div>

        {error ? <ErrorNotice error={error} /> : null}

        {trimmed === "" ? (
          <p className="py-6 text-center text-sm text-fg-muted">{t("search.hint")}</p>
        ) : hits.length === 0 && !busy && !error ? (
          <p className="py-6 text-center text-sm text-fg-muted">{t("search.none", { q: trimmed })}</p>
        ) : (
          <ul role="listbox" aria-label={t("search.title")} className="flex flex-col gap-1">
            {hits.map((hit, i) => {
              const Icon = ICONS[hit.kind];
              return (
                <li key={`${hit.kind}:${hit.id}`} role="option" aria-selected={i === active}>
                  <button
                    type="button"
                    onClick={() => choose(hit)}
                    onMouseEnter={() => setActive(i)}
                    className={
                      "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-start transition-colors " +
                      (i === active ? "bg-surface-3 text-fg" : "text-fg-muted hover:bg-surface-3")
                    }
                  >
                    <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-sm">{hit.title}</span>
                    <span className="shrink-0 text-xs text-fg-faint">{t(`search.kind.${hit.kind}`)}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Dialog>
  );
}
