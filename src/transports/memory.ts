// The in-memory transport: for tests, local development, and dry runs.
//
// It keeps every envelope it was handed, can be told to fail (once, or with a
// given retryability), and can optionally pretend to manage domains — so a
// host's tests can exercise both signing paths without SES or DNS.

import { MailError } from '../errors.ts';
import type { DnsRecord, DomainRegistration, MailTransport, OutboundEnvelope, TransportResult } from '../types.ts';

export interface MemoryTransportOptions {
  /** Pretend to be a transport that manages identities (SES-like). Domain
   *  records are fake CNAMEs; `verified` controls what `checkDomain` says. */
  manageDomains?: boolean;
  spfInclude?: string;
  /** Called per send; throw or return a failure to simulate the provider. */
  onSend?: (envelope: OutboundEnvelope) => void | Promise<void>;
}

export interface MemorySend {
  envelope: OutboundEnvelope;
  providerMessageId: string;
  /** The raw message as text, for asserting on headers. */
  text: string;
  at: Date;
}

export interface MemoryTransport extends MailTransport {
  readonly sent: MemorySend[];
  /** Fail the next `n` sends. */
  failNext(n: number, opts?: { retryable?: boolean; status?: number }): void;
  /** What `checkDomain` returns; default true. */
  domainVerified: boolean;
  registeredDomains: string[];
  clear(): void;
  /** Sends addressed to `address` (any envelope recipient). */
  to(address: string): MemorySend[];
}

export function memoryTransport(opts: MemoryTransportOptions = {}): MemoryTransport {
  const sent: MemorySend[] = [];
  const registered: string[] = [];
  let failures = 0;
  let failOpts: { retryable?: boolean; status?: number } = {};
  let counter = 0;

  const t: MemoryTransport = {
    name: 'memory',
    spfInclude: opts.spfInclude,
    sent,
    domainVerified: true,
    registeredDomains: registered,

    async send(envelope): Promise<TransportResult> {
      await opts.onSend?.(envelope);
      if (failures > 0) {
        failures -= 1;
        throw new MailError({
          code: 'transport',
          transport: 'memory',
          retryable: failOpts.retryable ?? true,
          status: failOpts.status,
          detail: 'simulated failure',
        });
      }
      counter += 1;
      const providerMessageId = `mem-${counter}`;
      sent.push({ envelope, providerMessageId, text: Buffer.from(envelope.raw).toString('utf8'), at: new Date() });
      return { providerMessageId };
    },

    failNext(n, o) {
      failures = n;
      failOpts = o ?? {};
    },
    clear() {
      sent.length = 0;
      registered.length = 0;
      failures = 0;
    },
    to(address) {
      const a = address.toLowerCase();
      return sent.filter((s) => s.envelope.recipients.some((r) => r.toLowerCase() === a));
    },
  };

  if (opts.manageDomains) {
    t.registerDomain = async (domain, { returnPathHost }): Promise<DomainRegistration> => {
      registered.push(domain);
      const records: DnsRecord[] = [
        { type: 'CNAME', name: `mem1._domainkey.${domain}`, value: 'mem1.dkim.memory.test', purpose: 'dkim', required: true },
        { type: 'CNAME', name: `mem2._domainkey.${domain}`, value: 'mem2.dkim.memory.test', purpose: 'dkim', required: true },
      ];
      if (returnPathHost) {
        records.push({ type: 'MX', name: returnPathHost, value: 'feedback.memory.test', priority: 10, purpose: 'return_path', required: true });
        records.push({ type: 'TXT', name: returnPathHost, value: 'v=spf1 include:memory.test ~all', purpose: 'spf', required: true });
      }
      return { records, providerRef: `mem:${domain}` };
    };
    t.checkDomain = async () => ({ verified: t.domainVerified });
    t.removeDomain = async (domain) => {
      const i = registered.indexOf(domain);
      if (i >= 0) registered.splice(i, 1);
    };
  }

  return t;
}
