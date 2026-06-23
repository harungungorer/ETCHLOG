/**
 * Standalone TypeScript re-implementation of the RFC 6962 §2.1 Merkle algorithms.
 *
 * This is a deliberate **second, independent implementation** of `etchlog-core`'s verifier
 * (`dev.hg.etchlog.core.hash.MerkleHash`, `proof.InclusionVerifier`, `proof.ConsistencyVerifier`,
 * `tree.MerkleTreeHash`). The browser computes the verdict itself, using only data the server hands
 * over plus the log's public key — the operator's server is never trusted for the result.
 *
 * Correctness invariants (asserted in `merkle.test.ts` against shared `etchlog-core` vectors):
 *   leaf hash      = SHA-256( 0x00 || leaf_data )
 *   interior node  = SHA-256( 0x01 || left || right )
 *   empty tree     = SHA-256( "" )            (no domain-separation prefix)
 *
 * ⚠️ The audit-path walk uses `bigint` for the node/last indices, NOT `number`. JavaScript's
 * bitwise operators coerce operands to **signed 32-bit ints**, which would silently corrupt the
 * left/right-child decision for trees of size ≥ 2³¹. `etchlog-core` uses `long`; `bigint` mirrors
 * that exactly.
 */

import { bytesToHex } from './encoding';

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;

/** Length, in bytes, of a SHA-256 digest. */
export const HASH_LENGTH = 32;

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(digest);
}

/** Leaf hash: `SHA-256(0x00 || leafData)`. */
export async function hashLeaf(leafData: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(1 + leafData.length);
  buf[0] = LEAF_PREFIX;
  buf.set(leafData, 1);
  return sha256(buf);
}

/** Interior node hash: `SHA-256(0x01 || left || right)`. */
export async function hashChildren(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = NODE_PREFIX;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256(buf);
}

/**
 * RFC 6962 empty-tree head: `MTH({}) = SHA-256("")`. Deliberately NOT `hashLeaf(new Uint8Array(0))`
 * — the empty tree has no leaf, so the `0x00` leaf prefix must not be applied.
 */
export function emptyTreeHash(): Promise<Uint8Array> {
  return sha256(new Uint8Array(0));
}

/** Largest power of two strictly less than `n` (requires `n >= 2`). */
function largestPowerOfTwoLessThan(n: number): number {
  // Highest set bit of (n-1). For n up to 2^31 this stays within safe integer range.
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}

/**
 * Reference RFC 6962 Merkle Tree Hash over an ordered list of **leaf hashes** — a direct
 * transcription of the spec recursion. Used by the visualization (so what you see is what gets
 * verified) and by the parity tests.
 *
 *   MTH({})      = SHA-256("")
 *   MTH({d0})    = d0
 *   MTH(d[0..n)) = hashChildren( MTH(d[0..k)), MTH(d[k..n)) ),  k = largest 2^x < n
 */
export async function merkleTreeHash(leafHashes: Uint8Array[]): Promise<Uint8Array> {
  return mth(leafHashes, 0, leafHashes.length);
}

async function mth(leaves: Uint8Array[], lo: number, hi: number): Promise<Uint8Array> {
  const n = hi - lo;
  if (n === 0) return emptyTreeHash();
  if (n === 1) return leaves[lo];
  const k = largestPowerOfTwoLessThan(n);
  const [left, right] = await Promise.all([mth(leaves, lo, lo + k), mth(leaves, lo + k, hi)]);
  return hashChildren(left, right);
}

/** Constant-time byte-array comparison (length-checked first). */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * RFC 6962 §2.1.1 inclusion-proof verification — mirrors `InclusionVerifier.verify`.
 *
 * Recomputes the tree root from `leafHash` plus its `auditPath` and compares it (constant-time) to
 * `expectedRoot` (the STH root). Returns `true` only on an exact match.
 */
export async function verifyInclusion(
  leafHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  auditPath: Uint8Array[],
  expectedRoot: Uint8Array,
): Promise<boolean> {
  if (!leafHash || !auditPath || !expectedRoot) return false;
  if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) return false;

  let fn = BigInt(leafIndex); // node position within its current level
  let sn = BigInt(treeSize) - 1n; // last index within its current level
  let r = leafHash; // running hash, starts at the leaf

  for (const sibling of auditPath) {
    if (sn === 0n) return false; // ran out of tree before the path was exhausted
    if ((fn & 1n) === 1n || fn === sn) {
      // running node is a RIGHT child
      r = await hashChildren(sibling, r);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      // running node is a LEFT child
      r = await hashChildren(r, sibling);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && constantTimeEqual(r, expectedRoot);
}

/**
 * RFC 6962 §2.1.2 consistency-proof verification — mirrors `ConsistencyVerifier.verify`.
 *
 * Reconstructs BOTH the size-`m` root and the size-`n` root from `proof` and checks each against its
 * signed counterpart (`oldRoot`, `newRoot`). If either reconstruction fails, the size-`m` log was
 * not an unmodified prefix of the size-`n` log — history was rewritten — and the proof is rejected.
 */
export async function verifyConsistency(
  m: number,
  n: number,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  proof: Uint8Array[],
): Promise<boolean> {
  if (!oldRoot || !newRoot || !proof) return false;
  if (m <= 0 || m > n) return false;
  if (m === n) {
    // Degenerate: nothing appended. Proof must be empty and roots equal.
    return proof.length === 0 && constantTimeEqual(oldRoot, newRoot);
  }

  const nodes = [...proof];
  const bm = BigInt(m);
  const mIsPowerOfTwo = (bm & (bm - 1n)) === 0n;
  if (!mIsPowerOfTwo && nodes.length === 0) return false; // malformed: needs a seed node

  let node1 = mIsPowerOfTwo ? oldRoot : nodes.shift()!; // rebuilds the OLD root
  let node2 = node1; // rebuilds the NEW root

  let fn = BigInt(m) - 1n;
  let sn = BigInt(n) - 1n;
  // Shift past the part of the path shared by both subtrees (the common right spine).
  while ((fn & 1n) === 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }

  for (const c of nodes) {
    if (sn === 0n) return false; // ran out of tree before the proof was exhausted
    if ((fn & 1n) === 1n || fn === sn) {
      // right child: both reconstructions absorb this node as a LEFT sibling
      node1 = await hashChildren(c, node1);
      node2 = await hashChildren(c, node2);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      // left child: only the NEW root grows here
      node2 = await hashChildren(node2, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }

  return constantTimeEqual(node1, oldRoot) && constantTimeEqual(node2, newRoot);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tree model for the SVG visualization. Recomputed from leaf hashes client-side
// with the SAME hashing as the verifier, so the displayed tree IS the verified one.
// ─────────────────────────────────────────────────────────────────────────────

export interface TreeNode {
  hash: Uint8Array;
  hashHex: string;
  isLeaf: boolean;
  /** Leaf index for leaves; -1 for interior nodes. */
  leafIndex: number;
  /** Inclusive [lo, hi) leaf range this subtree covers. */
  lo: number;
  hi: number;
  left?: TreeNode;
  right?: TreeNode;
}

/**
 * Build the left-balanced RFC 6962 tree model over `leafHashes` for rendering. Mirrors the MTH
 * split (largest power of two < n) so the shape matches the cryptographic tree exactly.
 */
export async function buildTreeModel(leafHashes: Uint8Array[]): Promise<TreeNode | null> {
  if (leafHashes.length === 0) return null;
  return buildSubtree(leafHashes, 0, leafHashes.length);
}

async function buildSubtree(leaves: Uint8Array[], lo: number, hi: number): Promise<TreeNode> {
  const n = hi - lo;
  if (n === 1) {
    const hash = leaves[lo];
    return { hash, hashHex: bytesToHex(hash), isLeaf: true, leafIndex: lo, lo, hi };
  }
  const k = largestPowerOfTwoLessThan(n);
  const [left, right] = await Promise.all([
    buildSubtree(leaves, lo, lo + k),
    buildSubtree(leaves, lo + k, hi),
  ]);
  const hash = await hashChildren(left.hash, right.hash);
  return { hash, hashHex: bytesToHex(hash), isLeaf: false, leafIndex: -1, lo, hi, left, right };
}
