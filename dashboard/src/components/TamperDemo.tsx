import { useState } from 'react';
import { tamperLeaf } from '../api/etchlog';

/**
 * DEMO ONLY. Asks the server (demo profile) to rewrite the selected leaf in its database, then tells
 * the parent to refresh so the user can re-verify and watch detection fire.
 */
export function TamperDemo({
  selectedLeaf,
  busy,
  onTampered,
}: {
  selectedLeaf: number | null;
  busy: boolean;
  onTampered: () => void;
}): JSX.Element {
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function onTamper(): Promise<void> {
    if (selectedLeaf === null) return;
    setError(null);
    setNote(null);
    try {
      const r = await tamperLeaf(selectedLeaf);
      setNote(`Leaf #${r.leafIndex} was mutated in the database. Re-verify to see detection.`);
      onTampered();
    } catch (err) {
      setError(
        `Tamper endpoint unavailable (${(err as Error).message}). The server must run with the ` +
          'demo profile to enable it.',
      );
    }
  }

  return (
    <section className="rounded border border-amber-900/60 bg-amber-950/20 p-4" aria-labelledby="tamper-h">
      <h2 id="tamper-h" className="mb-1 text-sm font-semibold text-amber-300">
        ⚠ Tamper demo (dev only)
      </h2>
      <p className="mb-3 text-xs text-gray-400">
        Simulate a malicious operator editing a stored record directly in the database. The signed
        tree head is left untouched — so the next verification catches the change.
      </p>
      <button
        type="button"
        onClick={onTamper}
        disabled={busy || selectedLeaf === null}
        className="w-full rounded bg-amber-600 px-3 py-2 text-sm font-medium text-white hover:bg-amber-500 focus:outline-none focus:ring-2 focus:ring-amber-400 disabled:cursor-not-allowed disabled:bg-gray-700 disabled:text-gray-400"
      >
        {selectedLeaf === null ? 'Select a leaf to tamper' : `Tamper leaf #${selectedLeaf}`}
      </button>
      {note !== null && (
        <p role="status" aria-live="polite" className="mt-2 text-xs text-amber-300">
          {note}
        </p>
      )}
      {error !== null && (
        <p role="alert" className="mt-2 text-xs text-red-400">
          {error}
        </p>
      )}
    </section>
  );
}
