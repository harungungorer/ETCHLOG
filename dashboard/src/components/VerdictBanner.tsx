import type { Verdict } from '../verify/flow';

/**
 * Accessible verdict display. The result is conveyed by icon (✅/❌) AND text AND color — never
 * color alone — and announced to assistive tech via `role="status"` / `aria-live`.
 */
export function VerdictBanner({ verdict }: { verdict: Verdict | null }): JSX.Element | null {
  if (verdict === null) return null;
  const ok = verdict.ok;
  return (
    <div
      role="status"
      aria-live="polite"
      className={`mt-2 flex items-start gap-2 rounded border px-3 py-2 text-sm ${
        ok
          ? 'border-emerald-700 bg-emerald-950/50 text-emerald-200'
          : 'border-red-700 bg-red-950/50 text-red-200'
      }`}
    >
      <span aria-hidden="true" className="text-base leading-5">
        {ok ? '✅' : '❌'}
      </span>
      <span>
        <span className="font-semibold">{ok ? 'VERIFIED' : 'FAILED'}</span>
        {!verdict.signatureChecked && (
          <span className="ml-1 text-xs text-gray-400">(STH signature not checked)</span>
        )}
        <br />
        {verdict.reason}
      </span>
    </div>
  );
}
