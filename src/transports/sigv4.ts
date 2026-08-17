// AWS Signature Version 4, for the SES transport.
//
// Written out (about eighty lines) rather than pulling in the AWS SDK, for the
// same reason billing-kit talks to Stripe over raw HTTP: the SDK is tens of
// megabytes and a moving target, and the signature is a fixed, documented
// algorithm with a public test suite. Only what SES needs is here — a single
// request, no chunked signing, no presigned URLs.

import { createHash, createHmac } from 'node:crypto';

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface SignInput {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  service: string;
  region: string;
  credentials: AwsCredentials;
  now: Date;
}

const sha256 = (s: string | Buffer): string => createHash('sha256').update(s).digest('hex');
const hmac = (key: string | Buffer, s: string): Buffer => createHmac('sha256', key).update(s, 'utf8').digest();

/** RFC 3986 encoding — SigV4 wants `!*'()` escaped too, which encodeURIComponent leaves. */
const enc = (s: string): string =>
  encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

const amzDate = (d: Date): string => d.toISOString().replace(/[:-]|\.\d{3}/g, '');

/** Returns the headers to send: the input headers plus host, x-amz-date,
 *  optionally x-amz-security-token, and Authorization. (No
 *  x-amz-content-sha256 — SES does not require it, and leaving it out keeps
 *  the output byte-identical to AWS's published test vectors.) */
export function signV4(input: SignInput): Record<string, string> {
  const url = new URL(input.url);
  const date = amzDate(input.now);
  const day = date.slice(0, 8);
  const payloadHash = sha256(input.body);

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers)) headers[k.toLowerCase()] = v.trim().replace(/\s+/g, ' ');
  headers.host = url.host;
  headers['x-amz-date'] = date;
  if (input.credentials.sessionToken) headers['x-amz-security-token'] = input.credentials.sessionToken;

  const signedHeaderNames = Object.keys(headers).sort();
  const canonicalHeaders = signedHeaderNames.map((k) => `${k}:${headers[k]}\n`).join('');
  const signedHeaders = signedHeaderNames.join(';');

  // Path: encode each segment once (SES paths carry identities like domains,
  // which are already safe, but be correct anyway).
  const canonicalPath =
    url.pathname
      .split('/')
      .map((seg) => enc(decodeURIComponent(seg)))
      .join('/') || '/';
  const canonicalQuery = [...url.searchParams.entries()]
    .map(([k, v]) => [enc(k), enc(v)] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');

  const canonicalRequest = [input.method.toUpperCase(), canonicalPath, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${day}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', date, scope, sha256(canonicalRequest)].join('\n');

  const kDate = hmac(`AWS4${input.credentials.secretAccessKey}`, day);
  const kRegion = hmac(kDate, input.region);
  const kService = hmac(kRegion, input.service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = hmac(kSigning, stringToSign).toString('hex');

  headers.authorization =
    `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return headers;
}
