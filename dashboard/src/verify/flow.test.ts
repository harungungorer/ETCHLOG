// @vitest-environment node
//
// Drives the real verifier through the in-browser flow with the API mocked to return data derived
// from the shared etchlog-core fixture. Runs under Node for Web Crypto (SHA-256 + Ed25519).

import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import vectors from '../verifier/__fixtures__/core-vectors.json';
import { base64ToBytes } from '../verifier/encoding';
import { buildTreeModel } from '../verifier/merkle';
import type { Sth } from '../verifier/sth';

vi.mock('../api/etchlog');
import * as api from '../api/etchlog';
import { verifyInclusionInBrowser, verifyConsistencyInBrowser, inclusionHighlight } from './flow';

const b = (s: string) => base64ToBytes(s);
const CURRENT_SIZE = vectors.sth.treeSize; // 9

function currentSth(): Sth {
  return {
    treeSize: CURRENT_SIZE,
    rootHash: b(vectors.sth.rootHash),
    timestamp: vectors.sth.timestamp,
    signature: b(vectors.sth.signature),
  };
}

beforeEach(() => {
  vi.resetAllMocks();
  (api.getSth as Mock).mockResolvedValue(currentSth());
});

describe('verifyInclusionInBrowser', () => {
  it('returns ok for a leaf that is genuinely included', async () => {
    const leafIndex = 3;
    const inc = vectors.inclusion.find((x) => x.treeSize === CURRENT_SIZE && x.leafIndex === leafIndex)!;
    (api.getEntry as Mock).mockResolvedValue({
      leafIndex,
      leafData: b(vectors.leaves[leafIndex].leafData),
      leafHash: b(vectors.leaves[leafIndex].leafHash),
    });
    (api.getInclusionProof as Mock).mockResolvedValue({
      leafIndex,
      treeSize: CURRENT_SIZE,
      auditPath: inc.auditPath.map(b),
    });

    const v = await verifyInclusionInBrowser(leafIndex);
    expect(v.ok).toBe(true);
    expect(v.signatureChecked).toBe(false); // no public key supplied
  });

  it('returns NOT ok when the served leaf bytes were tampered', async () => {
    const leafIndex = 3;
    const inc = vectors.inclusion.find((x) => x.treeSize === CURRENT_SIZE && x.leafIndex === leafIndex)!;
    const tampered = b(vectors.leaves[leafIndex].leafData);
    tampered[0] ^= 0x01; // operator silently rewrote the record
    (api.getEntry as Mock).mockResolvedValue({ leafIndex, leafData: tampered, leafHash: new Uint8Array(32) });
    (api.getInclusionProof as Mock).mockResolvedValue({
      leafIndex,
      treeSize: CURRENT_SIZE,
      auditPath: inc.auditPath.map(b),
    });

    const v = await verifyInclusionInBrowser(leafIndex);
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/tampered|not in the log/i);
  });

  it('checks the STH signature when a public key is supplied', async () => {
    const leafIndex = 0;
    const inc = vectors.inclusion.find((x) => x.treeSize === CURRENT_SIZE && x.leafIndex === leafIndex)!;
    (api.getEntry as Mock).mockResolvedValue({
      leafIndex,
      leafData: b(vectors.leaves[leafIndex].leafData),
      leafHash: b(vectors.leaves[leafIndex].leafHash),
    });
    (api.getInclusionProof as Mock).mockResolvedValue({
      leafIndex,
      treeSize: CURRENT_SIZE,
      auditPath: inc.auditPath.map(b),
    });

    const v = await verifyInclusionInBrowser(leafIndex, vectors.sth.publicKeyPem);
    expect(v.signatureChecked).toBe(true);
    expect(v.ok).toBe(true);
  });
});

describe('verifyConsistencyInBrowser', () => {
  it('returns ok for a genuine append-only prefix', async () => {
    const first = 4;
    const con = vectors.consistency.find((x) => x.first === first && x.second === CURRENT_SIZE)!;
    const pinned: Sth = {
      treeSize: first,
      rootHash: b(con.oldRoot),
      timestamp: 1,
      signature: new Uint8Array(64),
    };
    (api.getConsistencyProof as Mock).mockResolvedValue({
      first,
      second: CURRENT_SIZE,
      proof: con.proof.map(b),
    });

    const v = await verifyConsistencyInBrowser(pinned);
    expect(v.ok).toBe(true);
  });

  it('returns NOT ok when the current root was rewritten', async () => {
    const first = 4;
    const con = vectors.consistency.find((x) => x.first === first && x.second === CURRENT_SIZE)!;
    const badCurrent = currentSth();
    badCurrent.rootHash = b(con.newRoot);
    badCurrent.rootHash[0] ^= 0x01;
    (api.getSth as Mock).mockResolvedValue(badCurrent);
    const pinned: Sth = {
      treeSize: first,
      rootHash: b(con.oldRoot),
      timestamp: 1,
      signature: new Uint8Array(64),
    };
    (api.getConsistencyProof as Mock).mockResolvedValue({
      first,
      second: CURRENT_SIZE,
      proof: con.proof.map(b),
    });

    const v = await verifyConsistencyInBrowser(pinned);
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/rewritten|FAILED/i);
  });
});

describe('inclusionHighlight', () => {
  it('includes the selected leaf, its ancestors, and sibling subtree roots', async () => {
    const leafHashes = vectors.leaves.slice(0, CURRENT_SIZE).map((l) => b(l.leafHash));
    const root = await buildTreeModel(leafHashes);
    const { bytesToHex } = await import('../verifier/encoding');

    const set = inclusionHighlight(root, 3);
    // The selected leaf is highlighted.
    expect(set.has(bytesToHex(leafHashes[3]))).toBe(true);
    // The root is on the recomputed path.
    expect(set.has(root!.hashHex)).toBe(true);
    // Leaf 2 is the immediate sibling of leaf 3 -> its hash is on the audit path.
    expect(set.has(bytesToHex(leafHashes[2]))).toBe(true);
    // A far-away leaf that is neither the target nor a direct sibling subtree boundary.
    expect(set.size).toBeGreaterThan(2);
  });

  it('returns an empty set for a null tree', () => {
    expect(inclusionHighlight(null, 0).size).toBe(0);
  });
});
