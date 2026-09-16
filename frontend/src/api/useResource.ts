import { useEffect, useState } from "react";

import { ApiError } from "./client";

export interface Resource<T> {
  data: T | null;
  error: string | null;
  /** HTTP status when the failure came from the API — lets a caller treat a
   * 404 ("this scan never stored one") as an empty state rather than a fault. */
  status: number | null;
  loading: boolean;
}

/**
 * Runs `fetcher` whenever `deps` change, with the cancellation guard every
 * one of these needs so a fast tab-switch can't land a stale response on top
 * of a newer one.
 */
export function useResource<T>(fetcher: () => Promise<T>, deps: unknown[]): Resource<T> {
  const [state, setState] = useState<Resource<T>>({
    data: null,
    error: null,
    status: null,
    loading: true,
  });

  useEffect(() => {
    let cancelled = false;
    setState({ data: null, error: null, status: null, loading: true });

    fetcher()
      .then((data) => {
        if (!cancelled) setState({ data, error: null, status: 200, loading: false });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setState({
          data: null,
          error: err instanceof Error ? err.message : String(err),
          status: err instanceof ApiError ? err.status : null,
          loading: false,
        });
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return state;
}
