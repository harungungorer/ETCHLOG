import { useState, type FormEvent } from 'react';
import { appendEntry } from '../api/etchlog';
import { utf8ToBytes } from '../verifier/encoding';

/**
 * Append form. POSTs the typed text (UTF-8) to the log using the configured appender key. In the
 * local demo the public demo key is fine; production apps append server-side via the starter.
 */
export function AppendPanel({
  apiKey,
  onAppended,
}: {
  apiKey: string;
  onAppended: () => void;
}): JSX.Element {
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (text.trim() === '') return;
    setBusy(true);
    setError(null);
    try {
      await appendEntry(utf8ToBytes(text), apiKey);
      setText('');
      onAppended();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded border border-gray-800 bg-gray-900 p-4" aria-labelledby="append-h">
      <h2 id="append-h" className="mb-3 text-sm font-semibold text-gray-200">
        Append a record
      </h2>
      <form onSubmit={submit} className="flex flex-col gap-2">
        <label htmlFor="append-input" className="sr-only">
          Record to append
        </label>
        <input
          id="append-input"
          type="text"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Type a record to etch in…"
          className="rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
          disabled={busy}
        />
        <button
          type="submit"
          disabled={busy || text.trim() === ''}
          className="rounded bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-400 disabled:cursor-not-allowed disabled:bg-gray-700 disabled:text-gray-400"
        >
          {busy ? 'Appending…' : 'Append'}
        </button>
      </form>
      {error !== null && (
        <p role="alert" className="mt-2 text-xs text-red-400">
          Append failed: {error}
        </p>
      )}
    </section>
  );
}
