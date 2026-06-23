/**
 * In-browser verification flows: glue that pulls data from the public API and runs the standalone
 * verifier to produce a verdict. The server hands over DATA; these functions decide whether it is
 * valid — entirely client-side, the dashboard's "don't trust us, verify" property.
 */

import { hashLeaf, verifyInclusion, verifyConsistency, type TreeNode } from '../verifier/merkle';
import { importLogPublicKey, verifySth, type Sth } from '../verifier/sth';
import {
  getSth,
  getEntry,
  getInclusionProof,
  getConsistencyProof,
} from '../api/etchlog';

/** The outcome of an in-browser verification, suitable for direct display. */
export interface Verdict {
  ok: boolean;
  reason: string;
  /** True only when the STH Ed25519 signature was actually checked (a public key was supplied). */
  signatureChecked: boolean;
}

async function checkSthSignature(sth: Sth, logPublicKeyPem?: string): Promise<Verdict | null> {
  if (!logPublicKeyPem || logPublicKeyPem.trim() === '') {
    return null; // no key configured — signature not checked (caller notes this)
  }
  try {
    const key = await importLogPublicKey(logPublicKeyPem);
    if (!(await verifySth(key, sth))) {
      return {
        ok: false,
        reason: 'STH signature invalid — the tree head was forged or altered.',
        signatureChecked: true,
      };
    }
    return null; // signature good; continue
  } catch (e) {
    return {
      ok: false,
      reason: `Could not verify STH signature: ${(e as Error).message}`,
      signatureChecked: true,
    };
  }
}

/**
 * Verify that the leaf at {@code leafIndex} is provably included in the current signed tree head —
 * recomputing the leaf hash from the bytes the server returns and the root from the audit path.
 */
export async function verifyInclusionInBrowser(
  leafIndex: number,
  logPublicKeyPem?: string,
): Promise<Verdict> {
  const sth = await getSth();
  const sigFailure = await checkSthSignature(sth, logPublicKeyPem);
  if (sigFailure) return sigFailure;
  const signatureChecked = Boolean(logPublicKeyPem && logPublicKeyPem.trim() !== '');

  const entry = await getEntry(leafIndex);
  const leafHash = await hashLeaf(entry.leafData);
  const proof = await getInclusionProof(leafIndex, sth.treeSize);
  const ok = await verifyInclusion(leafHash, leafIndex, sth.treeSize, proof.auditPath, sth.rootHash);

  return ok
    ? {
        ok: true,
        reason: `Leaf #${leafIndex} is provably in the log (root recomputed in your browser).`,
        signatureChecked,
      }
    : {
        ok: false,
        reason:
          'Recomputed root ≠ signed root — this record is not in the log as signed (tampered).',
        signatureChecked,
      };
}

/**
 * Verify that a previously-pinned (older) STH is an append-only prefix of the current log. A failure
 * is the tamper alarm: the operator rewrote history.
 */
export async function verifyConsistencyInBrowser(
  pinned: Sth,
  logPublicKeyPem?: string,
): Promise<Verdict> {
  const current = await getSth();
  const sigFailure = await checkSthSignature(current, logPublicKeyPem);
  if (sigFailure) return sigFailure;
  const signatureChecked = Boolean(logPublicKeyPem && logPublicKeyPem.trim() !== '');

  if (pinned.treeSize > current.treeSize) {
    return {
      ok: false,
      reason: `Pinned size ${pinned.treeSize} exceeds current size ${current.treeSize}.`,
      signatureChecked,
    };
  }

  const proof = await getConsistencyProof(pinned.treeSize, current.treeSize);
  const ok = await verifyConsistency(
    pinned.treeSize,
    current.treeSize,
    pinned.rootHash,
    current.rootHash,
    proof.proof,
  );

  return ok
    ? {
        ok: true,
        reason: `Size ${pinned.treeSize} is an append-only prefix of size ${current.treeSize} — history intact.`,
        signatureChecked,
      }
    : {
        ok: false,
        reason: `Consistency FAILED — size ${pinned.treeSize} is not a clean prefix of size ${current.treeSize}. History was rewritten.`,
        signatureChecked,
      };
}

/**
 * Pure helper: the set of node `hashHex` values on the inclusion audit path for `leafIndex` — the
 * leaf, its ancestors up to the root, and the sibling subtree roots combined at each step. Used to
 * highlight the path in the tree visualization. Returns an empty set if the leaf is not found.
 */
export function inclusionHighlight(root: TreeNode | null, leafIndex: number): Set<string> {
  const out = new Set<string>();
  if (!root) return out;
  let node: TreeNode | undefined = root;
  while (node && !node.isLeaf) {
    out.add(node.hashHex); // ancestor on the recomputed path
    const left: TreeNode | undefined = node.left;
    const right: TreeNode | undefined = node.right;
    if (left && leafIndex >= left.lo && leafIndex < left.hi) {
      if (right) out.add(right.hashHex); // right sibling is on the audit path
      node = left;
    } else if (right) {
      if (left) out.add(left.hashHex); // left sibling is on the audit path
      node = right;
    } else {
      break;
    }
  }
  if (node && node.isLeaf && node.leafIndex === leafIndex) {
    out.add(node.hashHex);
  }
  return out;
}
