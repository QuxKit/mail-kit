// Small primitives shared across modules: hashing, sealing, ids.

import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const sha256Hex = (value: string | Uint8Array): string => createHash('sha256').update(value).digest('hex');

export const hmacSha256 = (key: string | Uint8Array, value: string | Uint8Array): Buffer =>
  createHmac('sha256', key).update(value).digest();

export const safeEqual = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && timingSafeEqual(a, b);

/** Parse a 64-hex-char key or explain what was expected. */
export function keyFromHex(hex: string | undefined, what: string): Buffer {
  if (!hex || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`mail-kit: ${what} must be 32 bytes as 64 hex chars (openssl rand -hex 32)`);
  }
  return Buffer.from(hex, 'hex');
}

/** AES-256-GCM. `iv:tag:cipher`, all base64 — one column, self-describing. */
export function seal(key: Buffer, plaintext: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const cipher = Buffer.concat([c.update(plaintext, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), cipher].map((b) => b.toString('base64')).join(':');
}

export function unseal(key: Buffer, sealed: string): string {
  const [iv, tag, cipher] = sealed.split(':').map((s) => Buffer.from(s, 'base64'));
  const d = createDecipheriv('aes-256-gcm', key, iv!);
  d.setAuthTag(tag!);
  return Buffer.concat([d.update(cipher!), d.final()]).toString('utf8');
}

export const randomToken = (bytes = 24): string => randomBytes(bytes).toString('base64url');
