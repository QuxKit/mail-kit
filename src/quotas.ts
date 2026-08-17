// Per-tenant send quotas: a per-minute and a per-day token bucket.
//
// One tenant must not be able to spend the transport's rate or the account's
// daily allowance for everyone. Each tenant has two buckets that refill
// continuously up to their capacity (per_minute/60 tokens a second,
// per_day/86400), so a burst up to the limit is fine and a steady stream at
// the rate never blocks. `consume` runs under the tenant's row lock, so N
// parallel sends admit exactly the limit — the database serialises, not a
// mutex in one process. Refused sends carry `retryAfterMs`: how long until
// one token is back in the emptier bucket.
//
// Limits come from `config.quotas` unless `set` has given the tenant its own
// (`custom`); a `null` bucket is unlimited. Nothing is enforced for a tenant
// with no limit from either source, and no row is written for it.

import { MailError } from './errors.ts';
import type { Clock, MailConfig, SqlExecutor, TenantId } from './types.ts';

export interface QuotaLimits {
  /** Sends admitted per minute (a token bucket of that capacity). `null`: no limit. */
  perMinute: number | null;
  /** Sends admitted per day. `null`: no limit. */
  perDay: number | null;
}

export interface Quota extends QuotaLimits {
  tenantId: TenantId;
  /** True when `set` gave the tenant its own limits; false when the config default applies. */
  custom: boolean;
  /** Tokens left in each bucket right now (`null` where there is no limit). */
  remaining: { minute: number | null; day: number | null };
}

export type ConsumeResult = { ok: true } | { ok: false; window: 'minute' | 'day'; limit: number; retryAfterMs: number };

export interface QuotasOptions {
  db: SqlExecutor;
  config: MailConfig;
  clock?: Clock;
}

export interface QuotasApi {
  /** Give a tenant its own limits (`null` per bucket = unlimited), or pass
   *  `null` to drop them and fall back to `config.quotas`. */
  set(tenantId: TenantId, limits: QuotaLimits | null): Promise<Quota>;
  /** The effective limits and what is left, as of `now`. */
  get(tenantId: TenantId, now?: Date): Promise<Quota>;
  /** Take `n` tokens from both buckets, or neither. What `send` calls. */
  consume(tenantId: TenantId, n?: number, now?: Date): Promise<ConsumeResult>;
}

interface Row {
  tenant_id: string;
  custom: boolean;
  per_minute: number | null;
  per_day: number | null;
  minute_tokens: number;
  day_tokens: number;
  refilled_at: Date;
}

const COLUMNS = 'tenant_id, custom, per_minute, per_day, minute_tokens, day_tokens, refilled_at';
const MINUTE_S = 60;
const DAY_S = 86_400;

function assertLimit(value: number | null, what: string): void {
  if (value === null) return;
  if (!Number.isInteger(value) || value < 1 || value > 2_147_483_647) {
    throw new MailError({ code: 'invalid_input', reason: `${what} must be a positive integer or null` });
  }
}

/** Tokens in a bucket of `cap` that held `stored` at `since`, refilling at cap/window per second. */
const refilled = (stored: number, cap: number, windowS: number, since: Date, now: Date): number => {
  const elapsedS = Math.max(0, (now.getTime() - since.getTime()) / 1000);
  return Math.min(cap, stored + (elapsedS * cap) / windowS);
};

export function createQuotas(opts: QuotasOptions): QuotasApi {
  const { db } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const defaults = (): QuotaLimits => ({
    perMinute: opts.config.quotas?.perMinute ?? null,
    perDay: opts.config.quotas?.perDay ?? null,
  });
  assertLimit(defaults().perMinute, 'config.quotas.perMinute');
  assertLimit(defaults().perDay, 'config.quotas.perDay');

  const effective = (row: Row | null): QuotaLimits =>
    row?.custom ? { perMinute: row.per_minute, perDay: row.per_day } : defaults();

  const view = (tenantId: TenantId, row: Row | null, now: Date): Quota => {
    const lim = effective(row);
    const minute =
      lim.perMinute === null
        ? null
        : row
          ? refilled(row.minute_tokens, lim.perMinute, MINUTE_S, row.refilled_at, now)
          : lim.perMinute;
    const day =
      lim.perDay === null ? null : row ? refilled(row.day_tokens, lim.perDay, DAY_S, row.refilled_at, now) : lim.perDay;
    return { tenantId, ...lim, custom: row?.custom ?? false, remaining: { minute, day } };
  };

  /** The row, created full if absent. `forUpdate` locks it for the transaction. */
  const ensureRow = async (tx: SqlExecutor, tenantId: TenantId, now: Date, forUpdate: boolean): Promise<Row> => {
    const d = defaults();
    await tx.query(
      `INSERT INTO mail.quotas (tenant_id, minute_tokens, day_tokens, refilled_at)
       VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id) DO NOTHING`,
      [tenantId, d.perMinute ?? 0, d.perDay ?? 0, now],
    );
    const rows = await tx.query<Row>(
      `SELECT ${COLUMNS} FROM mail.quotas WHERE tenant_id = $1${forUpdate ? ' FOR UPDATE' : ''}`,
      [tenantId],
    );
    // biome-ignore lint/style/noNonNullAssertion: just inserted-or-present under the PK
    return rows[0]!;
  };

  return {
    async set(tenantId, limits) {
      const now = clock();
      if (limits) {
        assertLimit(limits.perMinute, 'perMinute');
        assertLimit(limits.perDay, 'perDay');
      }
      return db.transaction(async (tx) => {
        const row = await ensureRow(tx, tenantId, now, true);
        // Settle the buckets at their current level under the old limits
        // first, so a raised limit does not hand out tokens retroactively
        // and a lowered one clamps.
        const before = effective(row);
        const minuteNow =
          before.perMinute === null ? 0 : refilled(row.minute_tokens, before.perMinute, MINUTE_S, row.refilled_at, now);
        const dayNow =
          before.perDay === null ? 0 : refilled(row.day_tokens, before.perDay, DAY_S, row.refilled_at, now);
        const after: QuotaLimits = limits ?? defaults();
        // A bucket that had no limit starts full; one that had one keeps its level (clamped).
        const minuteTokens =
          after.perMinute === null
            ? 0
            : before.perMinute === null
              ? after.perMinute
              : Math.min(after.perMinute, minuteNow);
        const dayTokens =
          after.perDay === null ? 0 : before.perDay === null ? after.perDay : Math.min(after.perDay, dayNow);
        const rows = await tx.query<Row>(
          `UPDATE mail.quotas SET custom = $2, per_minute = $3, per_day = $4, minute_tokens = $5, day_tokens = $6, refilled_at = $7
            WHERE tenant_id = $1 RETURNING ${COLUMNS}`,
          [tenantId, limits !== null, limits?.perMinute ?? null, limits?.perDay ?? null, minuteTokens, dayTokens, now],
        );
        return view(tenantId, rows[0] ?? null, now);
      });
    },

    async get(tenantId, now = clock()) {
      const rows = await db.query<Row>(`SELECT ${COLUMNS} FROM mail.quotas WHERE tenant_id = $1`, [tenantId]);
      return view(tenantId, rows[0] ?? null, now);
    },

    async consume(tenantId, n = 1, now = clock()) {
      if (!Number.isInteger(n) || n < 1)
        throw new MailError({ code: 'invalid_input', reason: 'n must be a positive integer' });
      // Fast path: nothing to enforce and no row → no lock, no write.
      const existing = await db.query<Row>(`SELECT ${COLUMNS} FROM mail.quotas WHERE tenant_id = $1`, [tenantId]);
      const peek = effective(existing[0] ?? null);
      if (peek.perMinute === null && peek.perDay === null) return { ok: true };
      return db.transaction(async (tx) => {
        const row = await ensureRow(tx, tenantId, now, true);
        const lim = effective(row);
        const minute =
          lim.perMinute === null ? null : refilled(row.minute_tokens, lim.perMinute, MINUTE_S, row.refilled_at, now);
        const day = lim.perDay === null ? null : refilled(row.day_tokens, lim.perDay, DAY_S, row.refilled_at, now);
        const short = (have: number | null, cap: number | null, windowS: number): number | null =>
          have === null || cap === null || have >= n ? null : Math.ceil(((n - have) * windowS * 1000) / cap);
        const minuteWait = short(minute, lim.perMinute, MINUTE_S);
        const dayWait = short(day, lim.perDay, DAY_S);
        if (minuteWait !== null || dayWait !== null) {
          // Report the bucket that keeps the caller waiting longest.
          const useDay = (dayWait ?? -1) > (minuteWait ?? -1);
          return {
            ok: false,
            window: useDay ? 'day' : 'minute',
            limit: (useDay ? lim.perDay : lim.perMinute) as number,
            retryAfterMs: Math.max(1, useDay ? (dayWait as number) : (minuteWait as number)),
          };
        }
        await tx.query(
          `UPDATE mail.quotas SET minute_tokens = $2, day_tokens = $3, refilled_at = $4 WHERE tenant_id = $1`,
          [tenantId, minute === null ? 0 : minute - n, day === null ? 0 : day - n, now],
        );
        return { ok: true };
      });
    },
  };
}
