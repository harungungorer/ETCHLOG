/**
 * Thin client over the Etchlog **public** REST read endpoints (plus the demo append/tamper calls
 * used by the dashboard demo). It only ever decodes data — every verification verdict is computed
 * by `src/verifier/*`, never trusted from the server.
 *
 * Wire encoding (see docs/api/API_DOCUMENTATION.md): hashes and signatures are **standard Base64**
 * in JSON bodies; the `?hash=` lookup parameter is **Base64URL**. This module decodes those to
 * `Uint8Array` at the boundary so callers and the verifier work in bytes.
 */

import { base64ToBytes, bytesToBase64, bytesToBase64Url } from '../verifier/encoding';
import type { Sth } from '../verifier/sth';

/** Base API URL: `${VITE_ETCHLOG_BASE_URL}/api/v1`, falling back to a same-origin relative path. */
const API_BASE = `${(import.meta.env.VITE_ETCHLOG_BASE_URL ?? '').replace(/\/+$/, '')}/api/v1`;

/** A stored log entry with its raw payload and RFC 6962 leaf hash decoded to bytes. */
export interface Entry {
  leafIndex: number;
  leafData: Uint8Array;
  leafHash: Uint8Array;
}

/** Inclusion proof with the audit path decoded to bytes. */
export interface InclusionProofResult {
  leafIndex: number;
  treeSize: number;
  auditPath: Uint8Array[];
}

/** Consistency proof with the proof nodes decoded to bytes. */
export interface ConsistencyProofResult {
  first: number;
  second: number;
  proof: Uint8Array[];
}

/** Result of the demo tamper call: the leaf and its new (mutated) bytes. */
export interface TamperResult {
  leafIndex: number;
  tamperedLeafData: Uint8Array;
  tamperedLeafHash: Uint8Array;
}

/** Result of an append: the assigned index and the resulting STH. */
export interface AppendResult {
  leafIndex: number;
  sth: Sth;
}

/** Error carrying the HTTP status and (when present) the RFC 7807 problem detail from the server. */
export class EtchlogApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`Etchlog API ${status}: ${detail}`);
    this.name = 'EtchlogApiError';
  }
}

/**
 * Thrown when a 2xx response does not match the documented wire shape (e.g. a proof with a missing
 * or non-array `audit_path`). Distinct from {@link EtchlogApiError} (an HTTP-level failure): this is
 * a protocol mismatch on an otherwise-successful request. Surfacing it explicitly — rather than
 * letting an `undefined.map(...)` throw an opaque `TypeError` — keeps the failure legible and means
 * a malformed proof can never be silently coerced into a VERIFIED verdict downstream.
 */
export class EtchlogProtocolError extends Error {
  constructor(message: string) {
    super(`Etchlog malformed response: ${message}`);
    this.name = 'EtchlogProtocolError';
  }
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const res = await fetch(`${API_BASE}${path}`, init);
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const detail =
      (body && typeof body === 'object' && 'detail' in body && String(body.detail)) ||
      res.statusText ||
      'request failed';
    throw new EtchlogApiError(res.status, detail);
  }
  return body;
}

// --- Wire-shape validators: narrow `unknown` at the decode boundary so every byte we feed the
// verifier is known-typed. Each throws EtchlogProtocolError on a shape mismatch. ---

function asObject(v: unknown, ctx: string): Record<string, unknown> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) {
    throw new EtchlogProtocolError(`${ctx}: expected a JSON object`);
  }
  return v as Record<string, unknown>;
}

/**
 * Reads a JSON **integer** field — a count, leaf index, tree size, or epoch-millis timestamp, each
 * of which the Etchlog wire encodes as a JSON number whose Java counterpart is a 64-bit `long`. We
 * require a SAFE integer (`|v| < 2^53`): JavaScript represents integers exactly only below that
 * bound, so a larger `tree_size`/`leaf_index` would already have been silently rounded by
 * `JSON.parse` before this validator ever sees it. Feeding such an imprecise coordinate to the
 * verifier could flip an inclusion/consistency verdict, or shift the reconstructed STH bytes so a
 * genuine signature no longer matches — so we reject it loudly here rather than coerce it, the same
 * fail-closed stance {@link EtchlogProtocolError} takes for a malformed shape. Every value that
 * passes is then promoted to `bigint` for the exact proof/STH arithmetic (see `merkle.ts` and
 * `sth.ts`), so the whole pipeline is precise for any size this guard admits. A single-sequencer log
 * cannot approach 2^53 leaves in any realistic deployment; this just makes the boundary explicit and
 * safe regardless.
 */
function num(o: Record<string, unknown>, field: string, ctx: string): number {
  const v = o[field];
  if (typeof v !== 'number' || !Number.isSafeInteger(v)) {
    throw new EtchlogProtocolError(`${ctx}.${field}: expected a safe integer (< 2^53)`);
  }
  return v;
}

function str(o: Record<string, unknown>, field: string, ctx: string): string {
  const v = o[field];
  if (typeof v !== 'string') {
    throw new EtchlogProtocolError(`${ctx}.${field}: expected a base64 string`);
  }
  return v;
}

function strArray(o: Record<string, unknown>, field: string, ctx: string): string[] {
  const v = o[field];
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) {
    throw new EtchlogProtocolError(`${ctx}.${field}: expected an array of base64 strings`);
  }
  return v as string[];
}

// Raw wire shapes (snake_case as documented) are validated field-by-field by the decoders below,
// so the byte-typed interfaces above are only ever built from known-good data.

function decodeSth(v: unknown): Sth {
  const o = asObject(v, 'sth');
  return {
    treeSize: num(o, 'tree_size', 'sth'),
    rootHash: base64ToBytes(str(o, 'root_hash', 'sth')),
    timestamp: num(o, 'timestamp', 'sth'),
    signature: base64ToBytes(str(o, 'ed25519_signature', 'sth')),
  };
}

function decodeEntry(v: unknown): Entry {
  const o = asObject(v, 'entry');
  return {
    leafIndex: num(o, 'leaf_index', 'entry'),
    leafData: base64ToBytes(str(o, 'leaf_data', 'entry')),
    leafHash: base64ToBytes(str(o, 'leaf_hash', 'entry')),
  };
}

/** `GET /log/sth` — the log's latest Signed Tree Head. Public. */
export async function getSth(): Promise<Sth> {
  return decodeSth(await request('/log/sth'));
}

/** `GET /log/entries/{index}` — fetch the stored leaf at an index. Public. */
export async function getEntry(index: number): Promise<Entry> {
  return decodeEntry(await request(`/log/entries/${index}`));
}

/** `GET /log/entries?hash=<base64url>` — look up a leaf by its RFC 6962 leaf hash. Public. */
export async function getEntryByHash(leafHash: Uint8Array): Promise<Entry> {
  const q = encodeURIComponent(bytesToBase64Url(leafHash));
  return decodeEntry(await request(`/log/entries?hash=${q}`));
}

/** `GET /log/proofs/inclusion?leaf_index=I&tree_size=N` — inclusion (audit) path. Public. */
export async function getInclusionProof(
  leafIndex: number,
  treeSize: number,
): Promise<InclusionProofResult> {
  const o = asObject(
    await request(`/log/proofs/inclusion?leaf_index=${leafIndex}&tree_size=${treeSize}`),
    'inclusion proof',
  );
  return {
    leafIndex: num(o, 'leaf_index', 'inclusion proof'),
    treeSize: num(o, 'tree_size', 'inclusion proof'),
    auditPath: strArray(o, 'audit_path', 'inclusion proof').map(base64ToBytes),
  };
}

/** `GET /log/proofs/consistency?first=M&second=N` — consistency proof between two sizes. Public. */
export async function getConsistencyProof(
  first: number,
  second: number,
): Promise<ConsistencyProofResult> {
  const o = asObject(
    await request(`/log/proofs/consistency?first=${first}&second=${second}`),
    'consistency proof',
  );
  return {
    first: num(o, 'first', 'consistency proof'),
    second: num(o, 'second', 'consistency proof'),
    proof: strArray(o, 'proof', 'consistency proof').map(base64ToBytes),
  };
}

/**
 * `POST /log/entries` — append a record. Requires the appender `X-Api-Key`.
 *
 * In production an app appends server-side via the Spring starter; the dashboard only does this for
 * the local demo, where the (public, well-known) demo key is acceptable. No key is persisted in the
 * browser beyond this call's configured value.
 */
export async function appendEntry(leafData: Uint8Array, apiKey: string): Promise<AppendResult> {
  const o = asObject(
    await request('/log/entries', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey },
      body: JSON.stringify({ leaf_data: bytesToBase64(leafData) }),
    }),
    'append',
  );
  return { leafIndex: num(o, 'leaf_index', 'append'), sth: decodeSth(o.sth) };
}

/**
 * `POST /_demo/tamper/{index}` — DEMO ONLY. Asks the server (running with the `demo` profile) to
 * rewrite a stored leaf in its database, simulating a malicious operator. Re-verifying the entry
 * afterwards detects the tampering. Not part of the production API.
 */
export async function tamperLeaf(index: number): Promise<TamperResult> {
  const o = asObject(await request(`/_demo/tamper/${index}`, { method: 'POST' }), 'tamper');
  return {
    leafIndex: num(o, 'leaf_index', 'tamper'),
    tamperedLeafData: base64ToBytes(str(o, 'tampered_leaf_data', 'tamper')),
    tamperedLeafHash: base64ToBytes(str(o, 'tampered_leaf_hash', 'tamper')),
  };
}
