import { useCallback, useEffect, useRef, useState } from "react";

export interface Loaded<T> {
  data: T | null;
  error: unknown;
  loading: boolean;
  reload: () => Promise<void>;
  /** Replace the cached value locally (e.g. after an optimistic toggle). */
  set: (next: T | null) => void;
}

/**
 * Runs `fn` on mount and whenever `deps` change; ignores results from superseded runs.
 * `reload` re-runs without flashing the loading state.
 */
export function useLoad<T>(fn: () => Promise<T>, deps: readonly unknown[]): Loaded<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const seq = useRef(0);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async (silent: boolean): Promise<void> => {
    const mine = ++seq.current;
    if (!silent) setLoading(true);
    try {
      const value = await fnRef.current();
      if (mounted.current && mine === seq.current) {
        setData(value);
        setError(null);
      }
    } catch (e) {
      if (mounted.current && mine === seq.current) setError(e);
    } finally {
      if (mounted.current && mine === seq.current) setLoading(false);
    }
  }, []);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => void run(false), deps);

  const reload = useCallback(() => run(true), [run]);
  return { data, error, loading, reload, set: setData };
}
