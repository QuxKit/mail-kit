// Suppression: addresses a tenant (or everyone) must not send to.
//
// Two scopes, and a list within a tenant. A tenant's list holds its own
// unsubscribes and the bounces of its own sends. The global list (tenant_id
// NULL) holds complaints — the mailbox provider that recorded the complaint
// does not care which of your tenants sent, so neither can you — and whatever
// the operator adds by hand. An entry may further be scoped to a `listId`
// (a newsletter, a digest): it then applies only to sends that name that
// list, so unsubscribing from the newsletter does not stop the receipts. A
// send is checked against all of them in one query. Bounces and complaints
// reach here from `recordEvents`, automatically; unsubscribes from the
// one-click handler; a host never has to remember.

import { clampLimit, MAX_LIST_LIMIT } from './limits.ts';
import type { Clock, SqlExecutor, Suppression, SuppressionReason, TenantId } from './types.ts';

export interface SuppressionOptions {
  db: SqlExecutor;
  clock?: Clock;
}

export interface AddSuppressionInput {
  address: string;
  reason: SuppressionReason;
  detail?: string;
  /** Scope the entry to one list within the tenant. Absent: the whole tenant. */
  listId?: string;
}

export interface SuppressionScope {
  /** Only entries for this list (plus, for `check`, the unscoped ones). */
  listId?: string;
}

export interface SuppressionApi {
  /** Add to a tenant's list, or to the global list with `tenantId: null`.
   *  Idempotent: an address already present keeps its original reason. */
  add(tenantId: TenantId | null, input: AddSuppressionInput): Promise<Suppression>;
  /** Remove the address from the scope. Without `listId`, every entry for
   *  the address in that scope goes — tenant-wide and list-scoped alike;
   *  with one, only that list's. */
  remove(tenantId: TenantId | null, address: string, scope?: SuppressionScope): Promise<boolean>;
  /** Newest first; `limit` defaults to 100, capped at `MAX_LIST_LIMIT`.
   *  `listId` narrows to that list's entries. */
  list(tenantId: TenantId | null, opts?: { limit?: number } & SuppressionScope): Promise<Suppression[]>;
  /** Which of `addresses` may not be sent to by `tenantId` — its own list,
   *  the global list, and (when `listId` is given) that list's entries, in
   *  one query. */
  check(tenantId: TenantId, addresses: readonly string[], scope?: SuppressionScope): Promise<Set<string>>;
}

interface Row {
  id: string;
  tenant_id: string | null;
  list_id: string | null;
  address: string;
  reason: SuppressionReason;
  detail: string | null;
  created_at: Date;
}

const COLUMNS = 'id, tenant_id, list_id, address, reason, detail, created_at';

const toSuppression = (r: Row): Suppression => ({
  id: r.id,
  tenantId: r.tenant_id,
  listId: r.list_id,
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
        `INSERT INTO mail.suppressions (tenant_id, list_id, address, reason, detail)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (COALESCE(tenant_id, ''), COALESCE(list_id, ''), address) DO UPDATE SET address = EXCLUDED.address
         RETURNING ${COLUMNS}`,
        [tenantId, input.listId ?? null, address, input.reason, input.detail ?? null],
      );
      // biome-ignore lint/style/noNonNullAssertion: INSERT … ON CONFLICT DO UPDATE … RETURNING always yields one row
      return toSuppression(rows[0]!);
    },

    async remove(tenantId, address, scope) {
      const rows = await db.query<{ id: string }>(
        `DELETE FROM mail.suppressions
          WHERE address = $2 AND ($1::text IS NULL AND tenant_id IS NULL OR tenant_id = $1)
            AND ($3::text IS NULL OR list_id = $3)
          RETURNING id`,
        [tenantId, normaliseForSuppression(address), scope?.listId ?? null],
      );
      return rows.length > 0;
    },

    async list(tenantId, o) {
      const rows = await db.query<Row>(
        `SELECT ${COLUMNS} FROM mail.suppressions
          WHERE ($1::text IS NULL AND tenant_id IS NULL OR tenant_id = $1)
            AND ($3::text IS NULL OR list_id = $3)
          ORDER BY created_at DESC LIMIT $2`,
        [tenantId, clampLimit(o?.limit, 100, MAX_LIST_LIMIT), o?.listId ?? null],
      );
      return rows.map(toSuppression);
    },

    async check(tenantId, addresses, scope) {
      if (addresses.length === 0) return new Set();
      const wanted = [...new Set(addresses.map(normaliseForSuppression))];
      const rows = await db.query<{ address: string }>(
        `SELECT address FROM mail.suppressions
          WHERE address = ANY($2::text[]) AND (tenant_id IS NULL OR tenant_id = $1)
            AND (list_id IS NULL OR list_id = $3)`,
        [tenantId, wanted, scope?.listId ?? null],
      );
      return new Set(rows.map((r) => r.address));
    },
  };
}
