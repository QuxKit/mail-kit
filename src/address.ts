// Addresses: normalise, validate, render.
//
// Validation is deliberately structural rather than a full RFC 5322 grammar —
// one `@`, a non-empty local part without control characters or spaces, a
// domain that is a plausible hostname. Anything stricter rejects real
// addresses; anything looser lets a header injection or an empty domain
// through to the transport, where the error message is far less useful.

import { domainToASCII } from 'node:url';
import { MailError } from './errors.ts';
import type { Address } from './types.ts';

export interface ParsedAddress {
  /** Lower-cased domain, local part as given (local parts are case-sensitive
   *  by RFC and case-insensitive by every real mailbox; we don't fold). */
  email: string;
  name: string | null;
  domain: string;
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point of this check
const CONTROL = /[\u0000-\u001f\u007f]/;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** Lower-cases and IDNA-encodes a domain. Throws `invalid_address`-shaped
 *  reasons via the caller; returns null when it is not a hostname. */
export function normaliseDomain(input: string): string | null {
  const trimmed = input.trim().replace(/\.$/, '');
  if (!trimmed) return null;
  const ascii = domainToASCII(trimmed.toLowerCase());
  if (!ascii || !HOSTNAME.test(ascii)) return null;
  return ascii;
}

/** `Name <addr>` / `"Name" <addr>` / `<addr>` as one string. */
const NAME_ADDR = /^\s*(?:"([^"]*)"|([^<]*?))\s*<([^<>]+)>\s*$/;

export function parseAddress(input: Address): ParsedAddress {
  let raw = typeof input === 'string' ? input : input.email;
  let name = typeof input === 'string' ? null : input.name?.trim() || null;
  if (typeof input === 'string') {
    const m = NAME_ADDR.exec(input);
    if (m) {
      raw = m[3] ?? '';
      name = (m[1] ?? m[2] ?? '').trim() || null;
    }
  }
  const email = (raw ?? '').trim();

  const fail = (reason: string): never => {
    throw new MailError({ code: 'invalid_address', address: email, reason });
  };

  if (!email) fail('empty');
  if (CONTROL.test(email) || /\s/.test(email)) fail('contains whitespace or control characters');
  if (name && CONTROL.test(name)) fail('display name contains control characters');
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) fail('must be local@domain');
  const local = email.slice(0, at);
  if (local.length > 64) fail('local part longer than 64 characters');
  const domain = normaliseDomain(email.slice(at + 1));
  if (!domain) return fail('domain is not a valid hostname');
  return { email: `${local}@${domain}`, name, domain };
}

export function parseAddressList(input: Address | readonly Address[] | undefined): ParsedAddress[] {
  if (input === undefined) return [];
  const list = Array.isArray(input) ? (input as readonly Address[]) : [input as Address];
  return list.map(parseAddress);
}

const NEEDS_QUOTING = /[()<>[\]:;@\\,."]/;

/** `Name <addr>` for the header, or the bare address. Non-ASCII names are
 *  RFC 2047 encoded so the header stays 7-bit clean. */
export function renderAddress(a: ParsedAddress): string {
  if (!a.name) return a.email;
  const name = /[^\u0020-\u007e]/.test(a.name)
    ? encodeWord(a.name)
    : NEEDS_QUOTING.test(a.name)
      ? `"${a.name.replace(/(["\\])/g, '\\$1')}"`
      : a.name;
  return `${name} <${a.email}>`;
}

/** RFC 2047 encoded-word, B encoding, split so no word exceeds 75 chars. */
export function encodeWord(value: string): string {
  const bytes = Buffer.from(value, 'utf8');
  // 75 - "=?UTF-8?B?" (10) - "?=" (2) = 63 base64 chars → 45 bytes per word,
  // and don't split a UTF-8 sequence.
  const chunks: string[] = [];
  let i = 0;
  while (i < bytes.length) {
    let end = Math.min(i + 45, bytes.length);
    while (end < bytes.length && ((bytes[end] ?? 0) & 0xc0) === 0x80) end -= 1;
    chunks.push(`=?UTF-8?B?${bytes.subarray(i, end).toString('base64')}?=`);
    i = end;
  }
  return chunks.join(' ');
}
