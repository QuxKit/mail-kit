// The outbound-URL guard for webhook endpoints.
//
// A webhook URL is attacker-chosen by definition — a tenant types it in — and
// the worker that posts to it sits inside your network. Without this, a
// subscription for `http://169.254.169.254/latest/meta-data/` or
// `http://10.0.0.5:5432/` turns the webhook worker into a port scanner or a
// credential reader. So: https only unless told otherwise, and the hostname is
// resolved and every address checked against the ranges that mean "inside"
// — at `create` and again at delivery, because DNS answers change.
//
// What this cannot do: pin the address the HTTP client then connects to. The
// injected `fetch` resolves the name again, so a resolver that answers a
// public address to us and a private one to the client (rebinding) gets
// through. A host whose threat model includes that should hand in a fetch
// whose agent connects to the checked address (undici's `connect.lookup`).

import { isIP } from 'node:net';
import { MailError } from './errors.ts';

/** Resolve a hostname to its addresses (A and AAAA). `node:dns` `lookup` with
 *  `all: true` is one; tests hand in a map. */
export type HostResolver = (hostname: string) => Promise<string[]>;

/** Parse an IPv6 literal into 16 bytes, or null. Handles `::` and an embedded
 *  dotted IPv4 tail. */
function parseIPv6(text: string): Uint8Array | null {
  let s = text;
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);
  const groups: number[] = [];
  let v4Tail: number[] | null = null;
  const lastColon = s.lastIndexOf(':');
  if (s.includes('.', lastColon)) {
    const v4 = parseIPv4(s.slice(lastColon + 1));
    if (!v4) return null;
    v4Tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = `${s.slice(0, lastColon)}:0:0`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (part: string): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    for (const g of part.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(Number.parseInt(g, 16));
    }
    return out;
  };
  const head = parse(halves[0] ?? '');
  const tail = halves.length === 2 ? parse(halves[1] ?? '') : [];
  if (!head || !tail) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  groups.push(...head, ...new Array<number>(halves.length === 2 ? missing : 0).fill(0), ...tail);
  if (v4Tail) {
    groups[6] = v4Tail[0] ?? 0;
    groups[7] = v4Tail[1] ?? 0;
  }
  const bytes = new Uint8Array(16);
  groups.forEach((g, i) => {
    bytes[i * 2] = g >> 8;
    bytes[i * 2 + 1] = g & 0xff;
  });
  return bytes;
}

function parseIPv4(text: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const parts = m.slice(1).map(Number) as [number, number, number, number];
  return parts.every((n) => n <= 255) ? parts : null;
}

/** Why an IPv4 address may not be a webhook target, or null if it may. */
function forbiddenIPv4([a, b]: readonly [number, number, number, number]): string | null {
  if (a === 0) return 'this-network (0.0.0.0/8)';
  if (a === 10) return 'private (10.0.0.0/8)';
  if (a === 127) return 'loopback (127.0.0.0/8)';
  if (a === 100 && b >= 64 && b <= 127) return 'shared address space (100.64.0.0/10)';
  if (a === 169 && b === 254) return 'link-local (169.254.0.0/16)';
  if (a === 172 && b >= 16 && b <= 31) return 'private (172.16.0.0/12)';
  if (a === 192 && b === 168) return 'private (192.168.0.0/16)';
  if (a >= 224 && a <= 239) return 'multicast (224.0.0.0/4)';
  if (a >= 240) return 'reserved (240.0.0.0/4)';
  return null;
}

/**
 * Why an address may not be a webhook target, or null if it may. Covers
 * loopback, RFC 1918, link-local (the cloud metadata address lives there),
 * shared address space, 0.0.0.0/8, multicast and reserved for IPv4; loopback,
 * unspecified, ULA, link-local, site-local, multicast, and IPv4-mapped /
 * NAT64-embedded addresses (checked as their IPv4) for IPv6.
 */
export function forbiddenAddressReason(address: string): string | null {
  const kind = isIP(address);
  if (kind === 4) {
    const v4 = parseIPv4(address);
    return v4 ? forbiddenIPv4(v4) : 'not an IP address';
  }
  if (kind !== 6) return 'not an IP address';
  const b = parseIPv6(address);
  if (!b) return 'not an IP address';
  const allZeroTo = (n: number) => b.subarray(0, n).every((x) => x === 0);
  if (allZeroTo(15) && b[15] === 1) return 'loopback (::1)';
  if (allZeroTo(16)) return 'unspecified (::)';
  const v4 = (offset: number): [number, number, number, number] => [
    b[offset] ?? 0,
    b[offset + 1] ?? 0,
    b[offset + 2] ?? 0,
    b[offset + 3] ?? 0,
  ];
  if (allZeroTo(10) && b[10] === 0xff && b[11] === 0xff) {
    return forbiddenIPv4(v4(12)) ?? null; // IPv4-mapped: judged as the IPv4
  }
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b.subarray(4, 12).every((x) => x === 0)) {
    return forbiddenIPv4(v4(12)) ?? null; // NAT64 well-known prefix 64:ff9b::/96
  }
  const first = b[0] ?? 0;
  const second = b[1] ?? 0;
  if ((first & 0xfe) === 0xfc) return 'unique-local (fc00::/7)';
  if (first === 0xfe && (second & 0xc0) === 0x80) return 'link-local (fe80::/10)';
  if (first === 0xfe && (second & 0xc0) === 0xc0) return 'site-local (fec0::/10)';
  if (first === 0xff) return 'multicast (ff00::/8)';
  return null;
}

export interface UrlGuardOptions {
  resolve: HostResolver;
  /** Permit `http:` (development only). Default false: https is required. */
  allowInsecureHttp?: boolean;
}

/**
 * Throw `MailError` (`webhook_url_forbidden`) unless `url` is an http(s) URL
 * whose host resolves only to addresses that are not loopback, private,
 * link-local, multicast or otherwise internal. Returns the checked addresses.
 */
export async function assertWebhookUrlAllowed(url: URL, opts: UrlGuardOptions): Promise<string[]> {
  const fail = (reason: string): never => {
    throw new MailError({ code: 'webhook_url_forbidden', url: url.toString(), reason });
  };
  if (url.protocol === 'http:') {
    if (!opts.allowInsecureHttp)
      return fail('http: is not allowed; use https: (or set allowInsecureHttp for development)');
  } else if (url.protocol !== 'https:') {
    return fail(`scheme ${url.protocol} is not http(s)`);
  }
  if (url.username || url.password) return fail('credentials in the URL are not allowed');
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === '') return fail('no host');
  if (host === 'localhost' || host.endsWith('.localhost')) return fail('localhost');
  if (isIP(host)) {
    const why = forbiddenAddressReason(host);
    if (why) return fail(`${host} is ${why}`);
    return [host];
  }
  const addresses = await opts.resolve(host);
  if (addresses.length === 0) return fail(`${host} did not resolve`);
  for (const a of addresses) {
    const why = forbiddenAddressReason(a);
    if (why) return fail(`${host} resolves to ${a}, which is ${why}`);
  }
  return addresses;
}
