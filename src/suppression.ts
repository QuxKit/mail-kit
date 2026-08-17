// Suppression: addresses a tenant (or everyone) must not send to.
//
// Two scopes. A tenant's list holds its own unsubscribes and the bounces of
// its own sends. The global list (tenant_id NULL) holds complaints — the
// mailbox provider that recorded the complaint does not care which of your
// tenants sent, so neither can you — and whatever the operator adds by hand.
// A send is checked against both. Bounces and complaints reach here from
// `recordEvents`, automatically; a host never has to remember.

import type { Clock, SqlExecutor, Suppression, SuppressionReason, TenantId } from './types.ts';

export interface SuppressionOptions {
  db: SqlExecutor;
  clock?: Clock;
}

export interface AddSuppressionInput {
  address: string;
  reason: SuppressionReason;
  detail?: string;
}

export interface SuppressionApi {
  /** Add to a tenant's list, or to the global list with `tenantId: null`.
   *  Idempotent: an address already present keeps its original reason. */
  add(tenantId: TenantId | null, input: AddSuppressionInput): Promise<Suppression>;
  remove(tenantId: TenantId | null, address: string): Promise<boolean>;
  list(tenantId: TenantId | null, opts?: { limit?: number }): Promise<Suppression[]>;
  /** Which of `addresses` may not be sent to by `tenantId` — its own list and
   *  the global list, in one query. */
  check(tenantId: TenantId, addresses: readonly string[]): Promise<Set<string>>;
}

interface Row {
  id: string;
  tenant_id: string | null;
  address: string;
  reason: SuppressionReason;
  detail: string | null;
  created_at: Date;
}

const toSuppression = (r: Row): Suppression => ({
  id: r.id,
  tenantId: r.tenant_id,
  address: r.address,
  reason: r.reason,
  detail: r.detail,
  createdAt: r.created_at,
});

export const normaliseForSuppression = (address: string): string => address.trim().toLowerCase();

export function createSuppression(opts: SuppressionOptions): SuppressionApi {
  const { db } = opts;
  return {
    async add(tenantId, input) {
      const address = normaliseForSuppression(input.address);
      const rows = await db.query<Row>(
        `INSERT INTO mail.suppressions (tenant_id, address, reason, detail)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (COALESCE(tenant_id, ''), address) DO UPDATE SET address = EXCLUDED.address
         RETURNING id, tenant_id, address, reason, detail, created_at`,
        [tenantId, address, input.reason, input.detail ?? null],
      );
      // biome-ignore lint/style/noNonNullAssertion: INSERT … ON CONFLICT DO UPDATE … RETURNING always yields one row
      return toSuppression(rows[0]!);
    },

    async remove(tenantId, address) {
      const rows = await db.query<{ id: string }>(
        `DELETE FROM mail.suppressions
          WHERE address = $2 AND ($1::text IS NULL AND tenant_id IS NULL OR tenant_id = $1)
          RETURNING id`,
        [tenantId, normaliseForSuppression(address)],
      );
      return rows.length > 0;
    },

    async list(tenantId, o) {
      const rows = await db.query<Row>(
        `SELECT id, tenant_id, address, reason, detail, created_at FROM mail.suppressions
          WHERE ($1::text IS NULL AND tenant_id IS NULL OR tenant_id = $1)
          ORDER BY created_at DESC LIMIT $2`,
        [tenantId, o?.limit ?? 100],
      );
      return rows.map(toSuppression);
    },

    async check(tenantId, addresses) {
      if (addresses.length === 0) return new Set();
      const wanted = [...new Set(addresses.map(normaliseForSuppression))];
      const rows = await db.query<{ address: string }>(
        `SELECT address FROM mail.suppressions
          WHERE address = ANY($2::text[]) AND (tenant_id IS NULL OR tenant_id = $1)`,
        [tenantId, wanted],
      );
      return new Set(rows.map((r) => r.address));
    },
  };
}
