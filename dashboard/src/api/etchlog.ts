/**
 * Thin client over the Etchlog **public** REST read endpoints (plus the demo append/tamper calls
 * used by the dashboard demo). It only ever decodes data — every verification verdict is computed
 * by `src/verifier/*`, never trusted from the server.
 *
 * Wire encoding (see docs/api/API_DOCUMENTATION.md): hashes and signatures are **standard Base64**
 * in JSON bodies; the `?hash=` lookup parameter is **Base64URL**. This module decodes those to
 * `Uint8Array` at the boundary so callers and the verifier work in bytes.
 */

import { base64ToBytes, bytesToBase64Url } from '../verifier/encoding';
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

// Raw wire shapes (snake_case as documented). Decoded into the byte-typed interfaces above.
interface SthWire {
  tree_size: number;
  root_hash: string;
  timestamp: number;
  ed25519_signature: string;
}
interface EntryWire {
  leaf_index: number;
  leaf_data: string;
  leaf_hash: string;
}

function decodeSth(w: SthWire): Sth {
  return {
    treeSize: w.tree_size,
    rootHash: base64ToBytes(w.root_hash),
    timestamp: w.timestamp,
    signature: base64ToBytes(w.ed25519_signature),
  };
}

function decodeEntry(w: EntryWire): Entry {
  return {
    leafIndex: w.leaf_index,
    leafData: base64ToBytes(w.leaf_data),
    leafHash: base64ToBytes(w.leaf_hash),
  };
}

/** `GET /log/sth` — the log's latest Signed Tree Head. Public. */
export async function getSth(): Promise<Sth> {
  return decodeSth((await request('/log/sth')) as SthWire);
}

/** `GET /log/entries/{index}` — fetch the stored leaf at an index. Public. */
export async function getEntry(index: number): Promise<Entry> {
  return decodeEntry((await request(`/log/entries/${index}`)) as EntryWire);
}

/** `GET /log/entries?hash=<base64url>` — look up a leaf by its RFC 6962 leaf hash. Public. */
export async function getEntryByHash(leafHash: Uint8Array): Promise<Entry> {
  const q = encodeURIComponent(bytesToBase64Url(leafHash));
  return decodeEntry((await request(`/log/entries?hash=${q}`)) as EntryWire);
}

/** `GET /log/proofs/inclusion?leaf_index=I&tree_size=N` — inclusion (audit) path. Public. */
export async function getInclusionProof(
  leafIndex: number,
  treeSize: number,
): Promise<InclusionProofResult> {
  const w = (await request(
    `/log/proofs/inclusion?leaf_index=${leafIndex}&tree_size=${treeSize}`,
  )) as { leaf_index: number; tree_size: number; audit_path: string[] };
  return {
    leafIndex: w.leaf_index,
    treeSize: w.tree_size,
    auditPath: w.audit_path.map(base64ToBytes),
  };
}

/** `GET /log/proofs/consistency?first=M&second=N` — consistency proof between two sizes. Public. */
export async function getConsistencyProof(
  first: number,
  second: number,
): Promise<ConsistencyProofResult> {
  const w = (await request(`/log/proofs/consistency?first=${first}&second=${second}`)) as {
    first: number;
    second: number;
    proof: string[];
  };
  return { first: w.first, second: w.second, proof: w.proof.map(base64ToBytes) };
}
