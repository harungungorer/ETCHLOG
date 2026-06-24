/**
 * Signed Tree Head: canonical encoding + Ed25519 signature verification in the browser.
 *
 * Mirrors `etchlog-core`'s `sth.SthEncoding` and `sth.SthVerifier`. The signed payload is a fixed,
 * version-tagged byte layout (never the JSON rendering, whose whitespace/key order is not
 * canonical):
 *
 *   to_be_signed =  0x00                 (STH version/structure byte)
 *                || uint64_be(tree_size) (8 bytes, big-endian)
 *                || uint64_be(timestamp) (8 bytes, big-endian)
 *                || root_hash            (32 bytes)
 *
 * The log's Ed25519 **public key** is the verifier's only root of trust. Verification uses the
 * native Web Crypto `Ed25519` algorithm — no heavy crypto bundle.
 */

import { HASH_LENGTH } from './merkle';
import { pemToDer } from './encoding';

/** Structure/version tag prefixed to every signed STH payload (matches `SthEncoding.STH_VERSION`). */
const STH_VERSION = 0x00;

/** Fixed signed-payload width: 1 version + 8 tree_size + 8 timestamp + 32 root. */
const SIGNED_LENGTH = 1 + 8 + 8 + HASH_LENGTH;

/** Parsed STH with binary fields already decoded from their Base64 wire form. */
export interface Sth {
  treeSize: number;
  rootHash: Uint8Array;
  timestamp: number;
  signature: Uint8Array;
}

/** Produces the exact bytes an Ed25519 signature covers for the given STH fields. */
export function bytesToSign(treeSize: number, timestampMs: number, rootHash: Uint8Array): Uint8Array {
  if (rootHash.length !== HASH_LENGTH) {
    throw new Error(`root must be ${HASH_LENGTH} bytes`);
  }
  const buf = new Uint8Array(SIGNED_LENGTH);
  const view = new DataView(buf.buffer);
  buf[0] = STH_VERSION;
  view.setBigUint64(1, BigInt(treeSize), false); // big-endian
  view.setBigUint64(9, BigInt(timestampMs), false); // big-endian
  buf.set(rootHash, 17);
  return buf;
}

/**
 * Import the log's Ed25519 public key from PEM (SPKI). The resulting `CryptoKey` is reusable across
 * many `verifySth` calls.
 */
export async function importLogPublicKey(pem: string): Promise<CryptoKey> {
  const der = pemToDer(pem);
  // `as BufferSource` is required (not redundant): a `Uint8Array<ArrayBufferLike>` is not
  // assignable to the DOM lib's `BufferSource` because its buffer may be a `SharedArrayBuffer`.
  return crypto.subtle.importKey('spki', der as BufferSource, { name: 'Ed25519' }, false, [
    'verify',
  ]);
}

/**
 * Verify an STH's Ed25519 signature against the log's public key. Returns `true` only if the
 * signature covers exactly the canonical `(version, tree_size, timestamp, root_hash)` bytes.
 */
export async function verifySth(publicKey: CryptoKey, sth: Sth): Promise<boolean> {
  if (sth.rootHash.length !== HASH_LENGTH) return false;
  const message = bytesToSign(sth.treeSize, sth.timestamp, sth.rootHash);
  try {
    // `as BufferSource` casts are required for the same reason as in `importLogPublicKey`.
    return await crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      sth.signature as BufferSource,
      message as BufferSource,
    );
  } catch {
    return false;
  }
}
