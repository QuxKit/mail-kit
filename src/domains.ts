// Sending domains: the DNS checklist, verification, and who holds the DKIM key.
//
// Adding a domain produces the records the host must publish. Where they come
// from depends on the transport: one that manages sending identities (SES)
// hands them over and signs; one that does not (an SMTP relay, the memory
// transport) gets a DKIM key pair generated here, sealed under
// `config.dkimKey`, and mail-kit signs before `send`. Either way the host
// sees the same `DnsRecord[]` and the same `verify`.
//
// Verification asks DNS, not the transport's word alone. A transport can say
// "verified" while the SPF or DMARC record is still missing; the checklist is
// what the dashboard shows and what a customer fixes.

import { randomBytes } from 'node:crypto';
import { normaliseDomain } from './address.ts';
import { keyFromHex, seal, unseal } from './crypto.ts';
import { dkimTxtRecord, generateDkimKey } from './dkim.ts';
import { MailError } from './errors.ts';
import type {
  AddDomainInput,
  Clock,
  DnsRecord,
  DnsResolver,
  Logger,
  MailConfig,
  MailTransport,
  RecordCheck,
  SendingDomain,
  SqlExecutor,
  TenantId,
} from './types.ts';
import type { WebhooksApi } from './webhooks.ts';

export interface DomainsOptions {
  db: SqlExecutor;
  transport: MailTransport;
  dns: DnsResolver;
  config: MailConfig;
  webhooks: WebhooksApi;
  clock?: Clock;
  logger?: Logger;
}

/** What `messages` needs to sign for a domain, or null when the transport signs. */
export interface LocalSigner {
  domain: string;
  selector: string;
  privateKeyPem: string;
}

export interface DomainsApi {
  add(tenantId: TenantId, input: AddDomainInput): Promise<SendingDomain>;
  get(tenantId: TenantId, id: string): Promise<SendingDomain | null>;
  /** The tenant's domain by name, or null. What `send` uses to authorise a From. */
  find(tenantId: TenantId, name: string): Promise<SendingDomain | null>;
  list(tenantId: TenantId): Promise<SendingDomain[]>;
  /** Ask DNS (and the transport, if it has a view) and update status. */
  verify(tenantId: TenantId, id: string): Promise<SendingDomain>;
  /** For a poller: re-check every pending domain not checked in `olderThanMs`. */
  verifyPending(opts?: { limit?: number; olderThanMs?: number }): Promise<SendingDomain[]>;
  remove(tenantId: TenantId, id: string): Promise<boolean>;
  /** Internal to the kit; exported on the API for hosts that build their own send path. */
  signerFor(domain: SendingDomain): Promise<LocalSigner | null>;
}

interface Row {
  id: string;
  tenant_id: string;
  name: string;
  status: SendingDomain['status'];
  signing: SendingDomain['signing'];
  provider_ref: string | null;
  dkim_selector: string | null;
  dkim_public_key: string | null;
  dkim_private_key: string | null;
  return_path_host: string | null;
  records: DnsRecord[];
  last_check: RecordCheck[] | null;
  created_at: Date;
  verified_at: Date | null;
  last_checked_at: Date | null;
}

const COLUMNS =
  'id, tenant_id, name, status, signing, provider_ref, dkim_selector, dkim_public_key, dkim_private_key, ' +
  'return_path_host, records, last_check, created_at, verified_at, last_checked_at';

const toDomain = (r: Row): SendingDomain => ({
  id: r.id,
  tenantId: r.tenant_id,
  name: r.name,
  status: r.status,
  signing: r.signing,
  dkimSelector: r.dkim_selector,
  returnPathHost: r.return_path_host,
  records: r.records,
  lastCheck: r.last_check,
  createdAt: r.created_at,
  verifiedAt: r.verified_at,
  lastCheckedAt: r.last_checked_at,
});

const strip = (s: string) => s.replace(/\s+/g, '');
const noDot = (s: string) => s.toLowerCase().replace(/\.$/, '');

/** Compare what DNS returned to what a record asks for. */
export function recordSatisfied(record: DnsRecord, found: string[]): boolean {
  switch (record.type) {
    case 'CNAME':
      return found.some((f) => noDot(f) === noDot(record.value));
    case 'MX':
      return found.some((f) => noDot(f) === noDot(record.value));
    case 'TXT': {
      switch (record.purpose) {
        case 'dkim': {
          const p = /p=([^;]*)/.exec(strip(record.value))?.[1] ?? '';
          return found.some((f) => strip(f).includes(`p=${p}`));
        }
        case 'spf': {
          const include = /include:(\S+)/.exec(record.value)?.[1];
          return found.some((f) => /^v=spf1\b/i.test(f.trim()) && (!include || f.includes(`include:${include}`)));
        }
        case 'dmarc':
          return found.some((f) => /^v=DMARC1\b/i.test(f.trim()));
        default:
          return found.some((f) => f.trim() === record.value.trim());
      }
    }
  }
}

export function createDomains(opts: DomainsOptions): DomainsApi {
  const { db, transport, dns, config, webhooks } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const dkimKey = config.dkimKey ? keyFromHex(config.dkimKey, 'config.dkimKey') : null;

  const dmarcRecord = (name: string): DnsRecord => ({
    type: 'TXT',
    name: `_dmarc.${name}`,
    value: `v=DMARC1; p=none;${config.dmarcReportAddress ? ` rua=mailto:${config.dmarcReportAddress};` : ''}`,
    purpose: 'dmarc',
    required: false,
  });

  const check = async (
    domain: SendingDomain,
  ): Promise<{ checks: RecordCheck[]; transportOk: boolean; detail?: string }> => {
    const checks: RecordCheck[] = [];
    for (const record of domain.records) {
      let found: string[] = [];
      try {
        if (record.type === 'TXT') found = await dns.resolveTxt(record.name);
        else if (record.type === 'CNAME') found = await dns.resolveCname(record.name);
        else found = (await dns.resolveMx(record.name)).map((m) => m.exchange);
      } catch (error) {
        opts.logger?.warn('dns lookup failed', { name: record.name, type: record.type, error: String(error) });
      }
      checks.push({ record, ok: recordSatisfied(record, found), found });
    }
    let transportOk = true;
    let detail: string | undefined;
    if (transport.checkDomain) {
      const rows = await db.query<{ provider_ref: string | null }>(
        'SELECT provider_ref FROM mail.domains WHERE id = $1',
        [domain.id],
      );
      const verdict = await transport.checkDomain(domain.name, rows[0]?.provider_ref ?? null);
      transportOk = verdict.verified;
      detail = verdict.detail;
    }
    return { checks, transportOk, detail };
  };

  const applyCheck = async (domain: SendingDomain): Promise<SendingDomain> => {
    const now = clock();
    const { checks, transportOk } = await check(domain);
    const requiredOk = checks.filter((c) => c.record.required).every((c) => c.ok) && transportOk;
    let status = domain.status;
    if (requiredOk) status = 'verified';
    else if (domain.status === 'verified') status = 'failed';
    const rows = await db.query<Row>(
      `UPDATE mail.domains
          SET status = $2, last_check = $3::jsonb, last_checked_at = $4,
              verified_at = CASE WHEN $2 = 'verified' THEN COALESCE(verified_at, $4) ELSE verified_at END
        WHERE id = $1 RETURNING ${COLUMNS}`,
      [domain.id, status, JSON.stringify(checks), now],
    );
    // biome-ignore lint/style/noNonNullAssertion: UPDATE … RETURNING on a row we just read
    const updated = toDomain(rows[0]!);
    if (status !== domain.status) {
      const type = status === 'verified' ? 'domain.verified' : status === 'failed' ? 'domain.failed' : null;
      if (type)
        await webhooks.enqueue(domain.tenantId, type, { domain_id: updated.id, name: updated.name, status }, now);
    }
    return updated;
  };

  const api: DomainsApi = {
    async add(tenantId, input) {
      const name = normaliseDomain(input.name);
      if (!name)
        throw new MailError({ code: 'invalid_input', reason: `${JSON.stringify(input.name)} is not a domain name` });
      const rpSub = input.returnPathSubdomain === undefined ? 'bounce' : input.returnPathSubdomain;
      const returnPathHost = rpSub ? `${rpSub}.${name}` : null;

      const existing = await db.query<{ tenant_id: string }>('SELECT tenant_id FROM mail.domains WHERE name = $1', [
        name,
      ]);
      if (existing.length) {
        throw new MailError({
          code: 'invalid_input',
          reason:
            existing[0]?.tenant_id === tenantId
              ? `domain ${name} is already added`
              : `domain ${name} is claimed by another tenant`,
        });
      }

      let records: DnsRecord[];
      let signing: SendingDomain['signing'];
      let providerRef: string | null = null;
      let selector: string | null = null;
      let publicKey: string | null = null;
      let sealedPrivate: string | null = null;

      if (transport.registerDomain) {
        signing = 'transport';
        const reg = await transport.registerDomain(name, { returnPathHost });
        records = [...reg.records];
        providerRef = reg.providerRef ?? null;
      } else {
        signing = 'local';
        if (!dkimKey) throw new MailError({ code: 'dkim_key_required' });
        selector = `qk${randomBytes(4).toString('hex')}`;
        const pair = generateDkimKey();
        publicKey = pair.publicKeyBase64;
        sealedPrivate = seal(dkimKey, pair.privateKeyPem);
        records = [
          {
            type: 'TXT',
            name: `${selector}._domainkey.${name}`,
            value: dkimTxtRecord(publicKey),
            purpose: 'dkim',
            required: true,
          },
        ];
        if (transport.spfInclude) {
          records.push({
            type: 'TXT',
            name: returnPathHost ?? name,
            value: `v=spf1 include:${transport.spfInclude} ~all`,
            purpose: 'spf',
            required: true,
          });
        }
      }
      records.push(dmarcRecord(name));

      const rows = await db.query<Row>(
        `INSERT INTO mail.domains
           (tenant_id, name, signing, provider_ref, dkim_selector, dkim_public_key, dkim_private_key, return_path_host, records)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb) RETURNING ${COLUMNS}`,
        [
          tenantId,
          name,
          signing,
          providerRef,
          selector,
          publicKey,
          sealedPrivate,
          returnPathHost,
          JSON.stringify(records),
        ],
      );
      // biome-ignore lint/style/noNonNullAssertion: INSERT … RETURNING always yields one row
      return toDomain(rows[0]!);
    },

    async get(tenantId, id) {
      const rows = await db.query<Row>(`SELECT ${COLUMNS} FROM mail.domains WHERE tenant_id = $1 AND id = $2`, [
        tenantId,
        id,
      ]);
      return rows[0] ? toDomain(rows[0]) : null;
    },

    async find(tenantId, name) {
      const n = normaliseDomain(name);
      if (!n) return null;
      const rows = await db.query<Row>(`SELECT ${COLUMNS} FROM mail.domains WHERE tenant_id = $1 AND name = $2`, [
        tenantId,
        n,
      ]);
      return rows[0] ? toDomain(rows[0]) : null;
    },

    async list(tenantId) {
      const rows = await db.query<Row>(
        `SELECT ${COLUMNS} FROM mail.domains WHERE tenant_id = $1 ORDER BY created_at DESC`,
        [tenantId],
      );
      return rows.map(toDomain);
    },

    async verify(tenantId, id) {
      const domain = await api.get(tenantId, id);
      if (!domain) throw new MailError({ code: 'not_found', what: 'domain', id });
      return applyCheck(domain);
    },

    async verifyPending(o) {
      const cutoff = new Date(clock().getTime() - (o?.olderThanMs ?? 5 * 60_000));
      const rows = await db.query<Row>(
        `SELECT ${COLUMNS} FROM mail.domains
          WHERE status = 'pending' AND (last_checked_at IS NULL OR last_checked_at <= $1)
          ORDER BY last_checked_at NULLS FIRST LIMIT $2`,
        [cutoff, o?.limit ?? 50],
      );
      const out: SendingDomain[] = [];
      for (const r of rows) out.push(await applyCheck(toDomain(r)));
      return out;
    },

    async remove(tenantId, id) {
      const rows = await db.query<Row>(
        `DELETE FROM mail.domains WHERE tenant_id = $1 AND id = $2 RETURNING ${COLUMNS}`,
        [tenantId, id],
      );
      const row = rows[0];
      if (!row) return false;
      if (transport.removeDomain) {
        try {
          await transport.removeDomain(row.name, row.provider_ref);
        } catch (error) {
          opts.logger?.warn('transport removeDomain failed; row already deleted', {
            name: row.name,
            error: String(error),
          });
        }
      }
      return true;
    },

    async signerFor(domain) {
      if (domain.signing !== 'local') return null;
      if (!dkimKey) throw new MailError({ code: 'dkim_key_required' });
      const rows = await db.query<{ dkim_selector: string; dkim_private_key: string }>(
        'SELECT dkim_selector, dkim_private_key FROM mail.domains WHERE id = $1',
        [domain.id],
      );
      const row = rows[0];
      if (!row) throw new MailError({ code: 'not_found', what: 'domain', id: domain.id });
      return { domain: domain.name, selector: row.dkim_selector, privateKeyPem: unseal(dkimKey, row.dkim_private_key) };
    },
  };
  return api;
}
