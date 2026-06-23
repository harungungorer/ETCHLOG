import type { Verdict } from '../verify/flow';
import { VerdictBanner } from './VerdictBanner';

/**
 * In-browser verification controls (presentational). The actual verification runs in the parent,
 * which recomputes the root client-side; this panel only triggers it and shows the verdict.
 */
export function VerifyPanel({
  selectedLeaf,
  busy,
  inclusionVerdict,
  consistencyVerdict,
  pinnedSize,
  currentSize,
  onVerifyInclusion,
  onPinSth,
  onVerifyConsistency,
}: {
  selectedLeaf: number | null;
  busy: boolean;
  inclusionVerdict: Verdict | null;
  consistencyVerdict: Verdict | null;
  pinnedSize: number | null;
  currentSize: number | null;
  onVerifyInclusion: () => void;
  onPinSth: () => void;
  onVerifyConsistency: () => void;
}): JSX.Element {
  const btn =
    'rounded px-3 py-2 text-sm font-medium focus:outline-none focus:ring-2 disabled:cursor-not-allowed disabled:bg-gray-700 disabled:text-gray-400';
  return (
    <section className="rounded border border-gray-800 bg-gray-900 p-4" aria-labelledby="verify-h">
      <h2 id="verify-h" className="mb-3 text-sm font-semibold text-gray-200">
        Verify in your browser
      </h2>

      <div className="space-y-1">
        <p className="text-xs text-gray-400">
          {selectedLeaf === null
            ? 'Select a leaf in the tree, then verify its inclusion.'
            : `Selected leaf #${selectedLeaf}.`}
        </p>
        <button
          type="button"
          onClick={onVerifyInclusion}
          disabled={busy || selectedLeaf === null}
          className={`${btn} w-full bg-sky-600 text-white hover:bg-sky-500 focus:ring-sky-400`}
        >
          Verify inclusion
        </button>
        <VerdictBanner verdict={inclusionVerdict} />
      </div>

      <hr className="my-4 border-gray-800" />

      <div className="space-y-1">
        <p className="text-xs text-gray-400">
          Pin the current signed tree head, append more, then check the log is still an append-only
          extension of it.
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onPinSth}
            disabled={busy || currentSize === null}
            className={`${btn} flex-1 bg-gray-700 text-gray-100 hover:bg-gray-600 focus:ring-gray-400`}
          >
            {pinnedSize === null ? 'Pin current STH' : `Pinned @ size ${pinnedSize}`}
          </button>
          <button
            type="button"
            onClick={onVerifyConsistency}
            disabled={busy || pinnedSize === null}
            className={`${btn} flex-1 bg-sky-600 text-white hover:bg-sky-500 focus:ring-sky-400`}
          >
            Check consistency
          </button>
        </div>
        <VerdictBanner verdict={consistencyVerdict} />
      </div>
    </section>
  );
}
