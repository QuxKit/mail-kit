// A concurrency limiter in twenty lines, so `sendBatch` needs no dependency.
//
// `mapLimit` runs `fn` over `items` with at most `concurrency` in flight and
// resolves to the results in input order. Workers pull the next index from a
// shared counter; there is no queue to allocate and no promise per item
// beyond the one `fn` returns. A rejection from `fn` rejects the whole map
// (as `Promise.all` would) — callers that want per-item failures catch inside
// `fn`, which is what `sendBatch` does.

export async function mapLimit<T, R>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const width = Math.max(1, Math.min(Math.floor(concurrency) || 1, items.length));
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next;
      next += 1;
      out[i] = await fn(items[i] as T, i);
    }
  };
  await Promise.all(Array.from({ length: width }, worker));
  return out;
}
