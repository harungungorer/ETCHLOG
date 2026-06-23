import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  getSth,
  getEntry,
  getEntryByHash,
  getInclusionProof,
  getConsistencyProof,
  EtchlogApiError,
} from './etchlog';
import { bytesToBase64 } from '../verifier/encoding';

function mockFetch(status: number, body: unknown): { calls: string[] } {
  const calls: string[] = [];
  vi.stubGlobal('fetch', (url: string) => {
    calls.push(url);
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      statusText: 'mock',
      text: () => Promise.resolve(body === null ? '' : JSON.stringify(body)),
    } as Response);
  });
  return { calls };
}

const b64 = (n: number) => bytesToBase64(new Uint8Array(32).fill(n));

afterEach(() => vi.unstubAllGlobals());

describe('etchlog API client', () => {
  it('decodes STH snake_case fields into byte-typed Sth', async () => {
    mockFetch(200, {
      tree_size: 5,
      root_hash: b64(0xab),
      timestamp: 1750000000000,
      ed25519_signature: bytesToBase64(new Uint8Array(64).fill(7)),
    });
    const sth = await getSth();
    expect(sth.treeSize).toBe(5);
    expect(sth.timestamp).toBe(1750000000000);
    expect(sth.rootHash).toEqual(new Uint8Array(32).fill(0xab));
    expect(sth.signature.length).toBe(64);
  });

  it('decodes an entry by index', async () => {
    const { calls } = mockFetch(200, {
      leaf_index: 3,
      leaf_data: bytesToBase64(new Uint8Array([1, 2, 3])),
      leaf_hash: b64(0x10),
    });
    const e = await getEntry(3);
    expect(calls[0]).toContain('/api/v1/log/entries/3');
    expect(e.leafIndex).toBe(3);
    expect(e.leafData).toEqual(new Uint8Array([1, 2, 3]));
    expect(e.leafHash.length).toBe(32);
  });

  it('encodes the leaf hash as base64url in the lookup query', async () => {
    const { calls } = mockFetch(200, { leaf_index: 0, leaf_data: '', leaf_hash: b64(1) });
    // 0xfb 0xff 0xbf is "+/+/" in standard base64 -> must become "-_-_" (base64url, unpadded).
    await getEntryByHash(new Uint8Array([0xfb, 0xff, 0xbf]));
    const hashParam = new URL(calls[0], 'http://x').searchParams.get('hash')!;
    expect(hashParam).toBe('-_-_');
    expect(hashParam).not.toMatch(/[+/=]/);
  });

  it('maps inclusion proof audit_path to bytes', async () => {
    mockFetch(200, { leaf_index: 1, tree_size: 5, audit_path: [b64(2), b64(3)] });
    const p = await getInclusionProof(1, 5);
    expect(p.leafIndex).toBe(1);
    expect(p.treeSize).toBe(5);
    expect(p.auditPath).toHaveLength(2);
    expect(p.auditPath[0]).toEqual(new Uint8Array(32).fill(2));
  });

  it('maps consistency proof nodes to bytes', async () => {
    mockFetch(200, { first: 2, second: 5, proof: [b64(9)] });
    const p = await getConsistencyProof(2, 5);
    expect(p.first).toBe(2);
    expect(p.second).toBe(5);
    expect(p.proof[0]).toEqual(new Uint8Array(32).fill(9));
  });

  it('throws EtchlogApiError carrying status and problem detail on 404', async () => {
    mockFetch(404, { detail: 'No leaf exists at index 9999', status: 404 });
    await expect(getEntry(9999)).rejects.toBeInstanceOf(EtchlogApiError);
    await expect(getEntry(9999)).rejects.toMatchObject({ status: 404 });
  });
});
