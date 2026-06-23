import { useCallback, useEffect, useState } from 'react';
import { MerkleTreeView } from './components/MerkleTreeView';
import { AppendPanel } from './components/AppendPanel';
import { VerifyPanel } from './components/VerifyPanel';
import { TamperDemo } from './components/TamperDemo';
import { useEtchlogLog } from './hooks/useEtchlogLog';
import {
  inclusionHighlight,
  verifyInclusionInBrowser,
  verifyConsistencyInBrowser,
  type Verdict,
} from './verify/flow';
import { bytesToHex } from './verifier/encoding';
import type { Sth } from './verifier/sth';

const API_KEY = import.meta.env.VITE_ETCHLOG_API_KEY ?? 'etchlog-demo-key-change-me';

function App(): JSX.Element {
  const log = useEtchlogLog();
  const [selectedLeaf, setSelectedLeaf] = useState<number | null>(null);
  const [highlightPath, setHighlightPath] = useState<Set<string>>(new Set());
  const [inclusionVerdict, setInclusionVerdict] = useState<Verdict | null>(null);
  const [consistencyVerdict, setConsistencyVerdict] = useState<Verdict | null>(null);
  const [pinnedSth, setPinnedSth] = useState<Sth | null>(null);
  const [busy, setBusy] = useState(false);
  const [pubKeyPem, setPubKeyPem] = useState<string>(import.meta.env.VITE_ETCHLOG_PUBLIC_KEY ?? '');

  // Keep the highlighted audit path in sync with the current tree model and selection.
  useEffect(() => {
    setHighlightPath(selectedLeaf === null ? new Set() : inclusionHighlight(log.treeModel, selectedLeaf));
  }, [log.treeModel, selectedLeaf]);

  const handleSelect = useCallback((leafIndex: number) => {
    setSelectedLeaf(leafIndex);
    setInclusionVerdict(null);
  }, []);

  const onAppended = useCallback(() => {
    setInclusionVerdict(null);
    setConsistencyVerdict(null);
    log.refresh();
  }, [log]);

  const onVerifyInclusion = useCallback(async () => {
    if (selectedLeaf === null) return;
    setBusy(true);
    try {
      setInclusionVerdict(await verifyInclusionInBrowser(selectedLeaf, pubKeyPem));
    } catch (e) {
      setInclusionVerdict({ ok: false, reason: (e as Error).message, signatureChecked: false });
    } finally {
      setBusy(false);
    }
  }, [selectedLeaf, pubKeyPem]);

  const onPinSth = useCallback(() => {
    if (log.sth) setPinnedSth(log.sth);
    setConsistencyVerdict(null);
  }, [log.sth]);

  const onVerifyConsistency = useCallback(async () => {
    if (pinnedSth === null) return;
    setBusy(true);
    try {
      setConsistencyVerdict(await verifyConsistencyInBrowser(pinnedSth, pubKeyPem));
    } catch (e) {
      setConsistencyVerdict({ ok: false, reason: (e as Error).message, signatureChecked: false });
    } finally {
      setBusy(false);
    }
  }, [pinnedSth, pubKeyPem]);

  const onTampered = useCallback(() => {
    setInclusionVerdict(null);
    setConsistencyVerdict(null);
    log.refresh();
  }, [log]);

  const sth = log.sth;

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800 px-6 py-4">
        <h1 className="text-xl font-semibold tracking-tight text-white">
          Etchlog Verification Dashboard
        </h1>
        <p className="text-xs text-gray-500">
          Append, then verify inclusion &amp; consistency <em>in your browser</em> — the server is
          never trusted for the verdict.
        </p>
      </header>

      <main className="mx-auto grid max-w-6xl gap-4 px-6 py-6 lg:grid-cols-3">
        {/* Tree + STH (spans two columns on wide screens). */}
        <div className="space-y-4 lg:col-span-2">
          <section className="rounded border border-gray-800 bg-gray-900 p-4" aria-labelledby="tree-h">
            <div className="mb-3 flex items-baseline justify-between">
              <h2 id="tree-h" className="text-sm font-semibold text-gray-200">
                Merkle tree
              </h2>
              <span className="font-mono text-xs text-gray-500">
                {log.loading ? 'loading…' : `tree_size = ${sth?.treeSize ?? 0}`}
              </span>
            </div>
            {log.error !== null ? (
              <p role="alert" className="text-sm text-red-400">
                Could not reach the log: {log.error}
              </p>
            ) : (
              <MerkleTreeView
                root={log.treeModel}
                treeSize={sth?.treeSize ?? 0}
                highlightPath={highlightPath}
                selectedLeaf={selectedLeaf}
                onSelectLeaf={handleSelect}
              />
            )}
            {sth !== null && sth.treeSize > 0 && (
              <dl className="mt-3 grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 font-mono text-xs text-gray-400">
                <dt className="text-gray-500">root</dt>
                <dd className="truncate">{bytesToHex(sth.rootHash)}</dd>
                <dt className="text-gray-500">signed</dt>
                <dd>Ed25519 · {sth.signature.length} bytes</dd>
              </dl>
            )}
          </section>

          <AppendPanel apiKey={API_KEY} onAppended={onAppended} />
        </div>

        {/* Verify / tamper / settings. */}
        <div className="space-y-4">
          <VerifyPanel
            selectedLeaf={selectedLeaf}
            busy={busy}
            inclusionVerdict={inclusionVerdict}
            consistencyVerdict={consistencyVerdict}
            pinnedSize={pinnedSth?.treeSize ?? null}
            currentSize={sth?.treeSize ?? null}
            onVerifyInclusion={onVerifyInclusion}
            onPinSth={onPinSth}
            onVerifyConsistency={onVerifyConsistency}
          />

          <TamperDemo selectedLeaf={selectedLeaf} busy={busy} onTampered={onTampered} />

          <section className="rounded border border-gray-800 bg-gray-900 p-4" aria-labelledby="settings-h">
            <h2 id="settings-h" className="mb-2 text-sm font-semibold text-gray-200">
              Log public key (PEM)
            </h2>
            <label htmlFor="pubkey" className="sr-only">
              Log Ed25519 public key in PEM format
            </label>
            <textarea
              id="pubkey"
              value={pubKeyPem}
              onChange={(e) => setPubKeyPem(e.target.value)}
              rows={4}
              placeholder="-----BEGIN PUBLIC KEY-----&#10;… paste to also verify the STH signature …&#10;-----END PUBLIC KEY-----"
              className="w-full rounded border border-gray-700 bg-gray-950 px-2 py-1 font-mono text-[10px] text-gray-200 placeholder-gray-600 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
            <p className="mt-1 text-xs text-gray-500">
              Optional. With a key, verification also checks the STH Ed25519 signature — the
              verifier&apos;s only root of trust.
            </p>
          </section>
        </div>
      </main>
    </div>
  );
}

export default App;
