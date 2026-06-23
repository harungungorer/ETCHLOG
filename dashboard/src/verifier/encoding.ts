/**
 * Byte/string encoding helpers for the in-browser verifier.
 *
 * The Etchlog REST API encodes hashes and signatures as **standard Base64** in JSON bodies, and the
 * `hash` query parameter as **Base64URL** (no padding). These helpers are the single place those
 * conventions live so the verifier and API client agree byte-for-byte with `etchlog-core`.
 */

/** Decode a standard Base64 string (RFC 4648 §4, with `+`/`/` and `=` padding) to bytes. */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/** Encode bytes as standard Base64 (with padding). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Decode a Base64URL string (`-`/`_`, padding optional) to bytes. */
export function base64UrlToBytes(b64url: string): Uint8Array {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  if (pad === 2) b64 += '==';
  else if (pad === 3) b64 += '=';
  else if (pad === 1) throw new Error('invalid base64url length');
  return base64ToBytes(b64);
}

/** Encode bytes as unpadded Base64URL (used for the `?hash=` lookup query parameter). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Lowercase hex of a byte array — used as a stable node identity in the tree visualization. */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/** UTF-8 encode a string to bytes (leaf payloads typed in the dashboard append form). */
export function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * Extract the DER (SPKI) body from a PEM-wrapped public key. Tolerates CRLF, surrounding
 * whitespace, and any `-----BEGIN ...-----` label so a user can paste either a generic
 * `PUBLIC KEY` block or a provider-specific one.
 */
export function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
  if (body.length === 0) {
    throw new Error('PEM contains no key material');
  }
  return base64ToBytes(body);
}
