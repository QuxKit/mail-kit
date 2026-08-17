// Upper bounds on caller-supplied page sizes and worker batch sizes.
//
// A `limit` is a hint about a page, not a licence to pull the table; a
// worker batch that is too large holds leases on rows it will not reach
// for a long time. Both are clamped, not rejected — a dashboard asking for
// 1,000 gets 200, which is what it would have paginated anyway.

/** The most rows any `list` returns per call. */
export const MAX_LIST_LIMIT = 200;

/** The most rows one `deliverPending` / `verifyPending` call claims. */
export const MAX_BATCH = 500;

/** `value` as a positive integer no larger than `max`; `fallback` when absent or not a number. */
export function clampLimit(value: number | undefined, fallback: number, max: number): number {
  const n = typeof value === 'number' && Number.isFinite(value) ? Math.floor(value) : fallback;
  return Math.min(Math.max(1, n), max);
}
