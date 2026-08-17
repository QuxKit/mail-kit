// DKIM (RFC 6376): key generation, signing, and verification.
//
// mail-kit signs only when the transport does not — an SMTP relay, or a
// memory transport. SES signs itself (Easy DKIM) and then this file is not on
// the path. Relaxed/relaxed canonicalisation, rsa-sha256, 2048-bit keys: the
// combination every receiver accepts and every DNS provider can publish (a
// 2048-bit `p=` fits in two 255-byte TXT strings).
//
// The verifier is here so the signer can be tested against something other
// than itself, and because inbound is a plausible later chapter for the kit.

import { createHash, createSign, createVerify, generateKeyPairSync } from 'node:crypto';

export interface DkimKeyPair {
  /** PKCS#8 PEM. Sealed before it reaches the database. */
  privateKeyPem: string;
  /** SubjectPublicKeyInfo DER, base64 — the `p=` value. */
  publicKeyBase64: string;
}

export function generateDkimKey(modulusLength = 2048): DkimKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyBase64: (publicKey as Buffer).toString('base64') };
}

/** The TXT record value for `<selector>._domainkey.<domain>`. */
export function dkimTxtRecord(publicKeyBase64: string): string {
  return `v=DKIM1; k=rsa; p=${publicKeyBase64}`;
}

/** Headers signed when present, in this order. `from` is mandatory by RFC. */
export const DEFAULT_SIGNED_HEADERS = [
  'from', 'to', 'cc', 'reply-to', 'subject', 'date', 'message-id', 'mime-version',
  'content-type', 'content-transfer-encoding', 'list-unsubscribe', 'list-unsubscribe-post',
];

export interface DkimSignOptions {
  domain: string;
  selector: string;
  privateKeyPem: string;
  headers?: readonly string[];
  /** Signature timestamp; injected for tests. */
  now?: Date;
}

const CRLF = '\r\n';

/** Split raw bytes into header block and body at the first empty line. */
function splitMessage(raw: Uint8Array): { headers: string; body: string } {
  const text = Buffer.from(raw).toString('latin1');
  const idx = text.indexOf(`${CRLF}${CRLF}`);
  if (idx === -1) return { headers: text, body: '' };
  return { headers: text.slice(0, idx), body: text.slice(idx + 4) };
}

/** Unfold and list header fields as [name, rawValueWithName] pairs, in order. */
function headerFields(block: string): Array<{ name: string; raw: string }> {
  const fields: Array<{ name: string; raw: string }> = [];
  for (const line of block.split(CRLF)) {
    if (/^[ \t]/.test(line) && fields.length) {
      fields[fields.length - 1]!.raw += `${CRLF}${line}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    fields.push({ name: line.slice(0, colon).trim().toLowerCase(), raw: line });
  }
  return fields;
}

/** Relaxed header canonicalisation (RFC 6376 §3.4.2). */
function relaxHeader(raw: string): string {
  const colon = raw.indexOf(':');
  const name = raw.slice(0, colon).trim().toLowerCase();
  const value = raw
    .slice(colon + 1)
    .replace(/\r\n[ \t]+/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim();
  return `${name}:${value}`;
}

/** Relaxed body canonicalisation (RFC 6376 §3.4.4). */
export function relaxBody(body: string): string {
  const lines = body.split(CRLF).map((l) => l.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines.length ? lines.join(CRLF) + CRLF : '';
}

const b64 = (s: string | Buffer) => Buffer.from(s).toString('base64');

/** Prepend a DKIM-Signature header to the message. */
export function dkimSign(raw: Uint8Array, opts: DkimSignOptions): Uint8Array {
  const { headers: block, body } = splitMessage(raw);
  const fields = headerFields(block);
  const wanted = opts.headers ?? DEFAULT_SIGNED_HEADERS;

  // Sign each wanted header that is present, once (bottom-up per RFC — with a
  // builder that emits each header exactly once this is just presence).
  const present = new Set(fields.map((f) => f.name));
  const signed = wanted.filter((h) => present.has(h));
  if (!signed.includes('from')) throw new Error('dkim: message has no From header');

  const bh = createHash('sha256').update(relaxBody(body), 'latin1').digest('base64');
  const t = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const tagList =
    `v=1; a=rsa-sha256; c=relaxed/relaxed; d=${opts.domain}; s=${opts.selector}; t=${t}; ` +
    `h=${signed.join(':')}; bh=${bh}; b=`;
  // Fold the header BEFORE signing, so what is signed is the relaxed form of
  // the bytes that go on the wire. Folding only ever happens after a `; ` —
  // which relaxed canonicalisation collapses back to one space either way —
  // and inside the b= value, which is excluded from the hash. Never inside h=
  // or bh=, where an inserted space would change the canonical form.
  const headerNoB = foldTags(`DKIM-Signature: ${tagList}`);

  const signer = createSign('RSA-SHA256');
  for (const name of signed) {
    // last instance of each header name, per RFC (bottom-up)
    const field = [...fields].reverse().find((f) => f.name === name)!;
    signer.update(`${relaxHeader(field.raw)}${CRLF}`, 'latin1');
  }
  signer.update(relaxHeader(headerNoB), 'latin1');
  const signature = signer.sign(opts.privateKeyPem, 'base64');

  const header = headerNoB + foldValue(signature);
  return Buffer.from(`${header}${CRLF}${block}${CRLF}${CRLF}${body}`, 'latin1');
}

/** Fold on `; ` boundaries at ~72 chars — never inside a tag value. */
function foldTags(header: string): string {
  const out: string[] = [];
  let cur = '';
  for (const tag of header.split('; ')) {
    const piece = cur ? `; ${tag}` : tag;
    if (cur.length + piece.length > 72 && cur) {
      out.push(cur + ';');
      cur = ` ${tag}`;
    } else cur += piece;
  }
  out.push(cur);
  return out.join(CRLF);
}

/** Hard-fold a long opaque value (b=) at 72 chars. */
function foldValue(value: string): string {
  const chunks: string[] = [];
  for (let i = 0; i < value.length; i += 72) chunks.push(value.slice(i, i + 72));
  return chunks.join(`${CRLF} `);
}

export interface DkimVerifyResult {
  ok: boolean;
  domain?: string;
  selector?: string;
  reason?: string;
}

/**
 * Verify the first DKIM-Signature on a message. `publicKeyFor` returns the
 * base64 `p=` for `<selector>._domainkey.<domain>` — a DNS lookup in life, a
 * map in tests.
 */
export async function dkimVerify(
  raw: Uint8Array,
  publicKeyFor: (selector: string, domain: string) => Promise<string | null>,
): Promise<DkimVerifyResult> {
  const { headers: block, body } = splitMessage(raw);
  const fields = headerFields(block);
  const sigField = fields.find((f) => f.name === 'dkim-signature');
  if (!sigField) return { ok: false, reason: 'no DKIM-Signature' };

  const unfolded = sigField.raw.slice(sigField.raw.indexOf(':') + 1).replace(/\r\n[ \t]+/g, ' ');
  const tags = new Map<string, string>();
  for (const part of unfolded.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    tags.set(part.slice(0, eq).trim(), part.slice(eq + 1).replace(/\s+/g, ''));
  }
  const domain = tags.get('d');
  const selector = tags.get('s');
  const h = tags.get('h');
  const bh = tags.get('bh');
  const b = tags.get('b');
  if (!domain || !selector || !h || !bh || !b) return { ok: false, reason: 'missing tags' };
  if (tags.get('a') !== 'rsa-sha256') return { ok: false, domain, selector, reason: `unsupported a=${tags.get('a')}` };
  if ((tags.get('c') ?? 'simple/simple') !== 'relaxed/relaxed') return { ok: false, domain, selector, reason: 'only relaxed/relaxed is verified here' };

  const computedBh = createHash('sha256').update(relaxBody(body), 'latin1').digest('base64');
  if (computedBh !== bh) return { ok: false, domain, selector, reason: 'body hash mismatch' };

  const p = await publicKeyFor(selector, domain);
  if (!p) return { ok: false, domain, selector, reason: 'no public key' };
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${p.match(/.{1,64}/g)!.join('\n')}\n-----END PUBLIC KEY-----\n`;

  const verifier = createVerify('RSA-SHA256');
  const used = new Map<string, number>();
  for (const name of h.split(':').map((s) => s.trim().toLowerCase())) {
    const instances = fields.filter((f) => f.name === name);
    const n = used.get(name) ?? 0;
    const field = instances[instances.length - 1 - n];
    used.set(name, n + 1);
    if (!field) continue; // signed a header that is absent — legal, contributes nothing
    verifier.update(`${relaxHeader(field.raw)}${CRLF}`, 'latin1');
  }
  // the signature header itself, with b= emptied, no trailing CRLF
  const sigNoB = sigField.raw.replace(/([;\s]b=)[^;]*/i, '$1');
  verifier.update(relaxHeader(sigNoB), 'latin1');
  const ok = verifier.verify(publicKeyPem, b, 'base64');
  return ok ? { ok: true, domain, selector } : { ok: false, domain, selector, reason: 'signature mismatch' };
}
