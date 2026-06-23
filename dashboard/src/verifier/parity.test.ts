// @vitest-environment node
//
// Runs under the Node environment (not jsdom) because the in-browser verifier relies on the
// Web Crypto SubtleCrypto API — including native Ed25519 — which jsdom does not implement but
// Node's `globalThis.crypto.subtle` does.
//
// PARITY CONTRACT: every vector in core-vectors.json is generated and self-checked by
// `etchlog-core`'s CoreVectorGenerator. These tests assert the TypeScript verifier agrees with
// etchlog-core on all of them — the dashboard's "don't trust us, verify" claim is only as good as
// this parity holding.

import { describe, it, expect } from 'vitest';
import vectors from './__fixtures__/core-vectors.json';
import {
  hashLeaf,
  hashChildren,
  emptyTreeHash,
  merkleTreeHash,
  verifyInclusion,
  verifyConsistency,
} from './merkle';
import { importLogPublicKey, verifySth, type Sth } from './sth';
import { base64ToBytes, bytesToBase64 } from './encoding';

const b = (s: string) => base64ToBytes(s);

describe('encoding round-trips', () => {
  it('base64 decode/encode is stable for every vector hash', () => {
    for (const leaf of vectors.leaves) {
      expect(bytesToBase64(b(leaf.leafHash))).toBe(leaf.leafHash);
    }
  });
});

describe('RFC 6962 hashing parity with etchlog-core', () => {
  it('empty tree hash = SHA-256("")', async () => {
    expect(bytesToBase64(await emptyTreeHash())).toBe(vectors.emptyTreeRoot);
  });

  it('leaf hash = SHA-256(0x00 || leaf_data) for every leaf', async () => {
    for (const leaf of vectors.leaves) {
      const got = await hashLeaf(b(leaf.leafData));
      expect(bytesToBase64(got)).toBe(leaf.leafHash);
    }
  });

  it('hashChildren composes the documented two-leaf root', async () => {
    const left = b(vectors.leaves[0].leafHash);
    const right = b(vectors.leaves[1].leafHash);
    const root = await hashChildren(left, right);
    const size2 = vectors.roots.find((r) => r.treeSize === 2)!;
    expect(bytesToBase64(root)).toBe(size2.root);
  });

  it('Merkle tree hash (MTH) matches the core root for every tree size', async () => {
    const leafHashes = vectors.leaves.map((l) => b(l.leafHash));
    for (const { treeSize, root } of vectors.roots) {
      const got = await merkleTreeHash(leafHashes.slice(0, treeSize));
      expect(bytesToBase64(got)).toBe(root);
    }
  });
});

describe('inclusion-proof verification parity', () => {
  it('every core-generated inclusion proof verifies in the browser verifier', async () => {
    for (const v of vectors.inclusion) {
      const leafHash = b(vectors.leaves[v.leafIndex].leafHash);
      const ok = await verifyInclusion(
        leafHash,
        v.leafIndex,
        v.treeSize,
        v.auditPath.map(b),
        b(v.root),
      );
      expect(ok, `inclusion leafIndex=${v.leafIndex} treeSize=${v.treeSize}`).toBe(true);
    }
  });

  it('tampering with the leaf hash breaks verification', async () => {
    const v = vectors.inclusion.find((x) => x.treeSize >= 5 && x.leafIndex === 1)!;
    const tampered = b(vectors.leaves[v.leafIndex].leafHash);
    tampered[0] ^= 0x01; // flip one bit
    const ok = await verifyInclusion(tampered, v.leafIndex, v.treeSize, v.auditPath.map(b), b(v.root));
    expect(ok).toBe(false);
  });

  it('a corrupted audit-path node breaks verification', async () => {
    const v = vectors.inclusion.find((x) => x.auditPath.length >= 2)!;
    const path = v.auditPath.map(b);
    path[0][0] ^= 0x80;
    const leafHash = b(vectors.leaves[v.leafIndex].leafHash);
    const ok = await verifyInclusion(leafHash, v.leafIndex, v.treeSize, path, b(v.root));
    expect(ok).toBe(false);
  });

  it('a wrong expected root breaks verification', async () => {
    const v = vectors.inclusion.find((x) => x.treeSize >= 4)!;
    const wrongRoot = b(v.root);
    wrongRoot[31] ^= 0x01;
    const leafHash = b(vectors.leaves[v.leafIndex].leafHash);
    const ok = await verifyInclusion(leafHash, v.leafIndex, v.treeSize, v.auditPath.map(b), wrongRoot);
    expect(ok).toBe(false);
  });
});

describe('consistency-proof verification parity', () => {
  it('every core-generated consistency proof verifies in the browser verifier', async () => {
    for (const v of vectors.consistency) {
      const ok = await verifyConsistency(v.first, v.second, b(v.oldRoot), b(v.newRoot), v.proof.map(b));
      expect(ok, `consistency m=${v.first} n=${v.second}`).toBe(true);
    }
  });

  it('a rewritten new root fails the consistency check (the tamper alarm)', async () => {
    const v = vectors.consistency.find((x) => x.first < x.second)!;
    const badNewRoot = b(v.newRoot);
    badNewRoot[0] ^= 0x01;
    const ok = await verifyConsistency(v.first, v.second, b(v.oldRoot), badNewRoot, v.proof.map(b));
    expect(ok).toBe(false);
  });

  it('a corrupted proof node fails the consistency check', async () => {
    const v = vectors.consistency.find((x) => x.proof.length >= 1 && x.first < x.second)!;
    const proof = v.proof.map(b);
    proof[0][0] ^= 0x40;
    const ok = await verifyConsistency(v.first, v.second, b(v.oldRoot), b(v.newRoot), proof);
    expect(ok).toBe(false);
  });
});

describe('STH Ed25519 signature verification parity', () => {
  it('verifies the core-signed STH against the published public key', async () => {
    const key = await importLogPublicKey(vectors.sth.publicKeyPem);
    const sth: Sth = {
      treeSize: vectors.sth.treeSize,
      rootHash: b(vectors.sth.rootHash),
      timestamp: vectors.sth.timestamp,
      signature: b(vectors.sth.signature),
    };
    expect(await verifySth(key, sth)).toBe(true);
  });

  it('rejects a tampered tree size (signature no longer covers the bytes)', async () => {
    const key = await importLogPublicKey(vectors.sth.publicKeyPem);
    const sth: Sth = {
      treeSize: vectors.sth.treeSize + 1,
      rootHash: b(vectors.sth.rootHash),
      timestamp: vectors.sth.timestamp,
      signature: b(vectors.sth.signature),
    };
    expect(await verifySth(key, sth)).toBe(false);
  });

  it('rejects a tampered root hash', async () => {
    const key = await importLogPublicKey(vectors.sth.publicKeyPem);
    const badRoot = b(vectors.sth.rootHash);
    badRoot[0] ^= 0x01;
    const sth: Sth = {
      treeSize: vectors.sth.treeSize,
      rootHash: badRoot,
      timestamp: vectors.sth.timestamp,
      signature: b(vectors.sth.signature),
    };
    expect(await verifySth(key, sth)).toBe(false);
  });
});
