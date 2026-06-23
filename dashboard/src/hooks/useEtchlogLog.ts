import { useCallback, useEffect, useState } from 'react';
import { getSth, getEntry, type Entry } from '../api/etchlog';
import { buildTreeModel, type TreeNode } from '../verifier/merkle';
import type { Sth } from '../verifier/sth';

/** Snapshot of the log the dashboard renders from. */
export interface LogState {
  sth: Sth | null;
  entries: Entry[];
  treeModel: TreeNode | null;
  loading: boolean;
  error: string | null;
}

const EMPTY: LogState = { sth: null, entries: [], treeModel: null, loading: true, error: null };

/**
 * Loads the current STH and every entry, then rebuilds the client-side Merkle tree model from the
 * leaf hashes the server returned. The tree therefore reflects exactly what the server stores — so
 * after a tamper, the visualization shows the mutated leaf while the (still-signed) STH root does
 * not match, which is the point of the demo.
 */
export function useEtchlogLog(): LogState & { refresh: () => void } {
  const [state, setState] = useState<LogState>(EMPTY);

  const refresh = useCallback(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));
    (async () => {
      try {
        const sth = await getSth();
        const size = sth.treeSize;
        const indices = Array.from({ length: size }, (_, i) => i);
        const entries = await Promise.all(indices.map((i) => getEntry(i)));
        const treeModel = await buildTreeModel(entries.map((e) => e.leafHash));
        if (!cancelled) setState({ sth, entries, treeModel, loading: false, error: null });
      } catch (e) {
        if (!cancelled) {
          setState({
            sth: null,
            entries: [],
            treeModel: null,
            loading: false,
            error: (e as Error).message,
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => refresh(), [refresh]);

  return { ...state, refresh };
}
