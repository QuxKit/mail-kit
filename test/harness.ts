// The shipped pg adapter over a real pool, a schema rebuild, a fake resolver
// and a fetch that records webhook posts.
//
// The store-backed tests run against a real Postgres, because the behaviour
// worth testing — the idempotency conflict on a unique index, SKIP LOCKED
// claims, the suppression upsert — is in the database, not the TypeScript.

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { pgExecutor } from '../src/pg.ts';
import type { DnsResolver, Fetch, FetchInit, SqlExecutor } from '../src/types.ts';

/** The shipped adapter, re-exported under the harness's older name. */
export const fromPool = pgExecutor;

export const TEST_DATABASE_URL = process.env.MAIL_KIT_TEST_DATABASE_URL ?? 'postgres://localhost:5432/mail_kit_test';

/** A resolver over a map you fill in as the "customer publishes records". */
export class FakeDns implements DnsResolver {
  txt = new Map<string, string[]>();
  cname = new Map<string, string[]>();
  mx = new Map<string, Array<{ exchange: string; priority: number }>>();
  /** Hostname → addresses for the webhook URL guard. Unknown hosts resolve
   *  to a TEST-NET address so ordinary test URLs are allowed; set an entry to
   *  make a host resolve somewhere forbidden. */
  a = new Map<string, string[]>();
  async resolveTxt(name: string) {
    return this.txt.get(name.toLowerCase()) ?? [];
  }
  async resolveCname(name: string) {
    return this.cname.get(name.toLowerCase()) ?? [];
  }
  async resolveMx(name: string) {
    return this.mx.get(name.toLowerCase()) ?? [];
  }
  async lookup(hostname: string) {
    return this.a.get(hostname.toLowerCase()) ?? ['203.0.113.10'];
  }
  /** Publish every record in a domain's checklist, so verification passes. */
  publish(records: Array<{ type: string; name: string; value: string; priority?: number }>) {
    for (const r of records) {
      const n = r.name.toLowerCase();
      if (r.type === 'TXT') this.txt.set(n, [...(this.txt.get(n) ?? []), r.value]);
      if (r.type === 'CNAME') this.cname.set(n, [r.value]);
      if (r.type === 'MX') this.mx.set(n, [{ exchange: r.value, priority: r.priority ?? 10 }]);
    }
  }
}

export interface RecordedPost {
  url: string;
  init: FetchInit;
}

/** A fetch that records calls and answers with a scripted status. */
export class FakeFetch {
  calls: RecordedPost[] = [];
  private queue: number[] = [];
  status = 200;
  fetch: Fetch = async (url, init) => {
    this.calls.push({ url, init });
    const status = this.queue.length ? this.queue.shift()! : this.status;
    return { status, headers: { get: () => null }, text: async () => '' };
  };
  respondNext(...statuses: number[]) {
    this.queue.push(...statuses);
  }
}

export interface Harness {
  db: SqlExecutor;
  /** The underlying pool, for tests that need a second connection. */
  pool: pg.Pool;
  close(): Promise<void>;
}

export const testDkimKey = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

/**
 * Connect, rebuild the `mail` schema and hand back an executor. Returns null
 * when the database is unreachable so suites skip with `SKIP_REASON` — unless
 * `REQUIRE_DB` is set (CI), in which case an unreachable database is a failure,
 * not a silent skip.
 */
export async function setupDatabase(): Promise<Harness | null> {
  const pool = new pg.Pool({ connectionString: TEST_DATABASE_URL, max: 4 });
  try {
    await pool.query('SELECT 1');
  } catch (error) {
    await pool.end().catch(() => {});
    if (process.env.REQUIRE_DB) {
      throw new Error(
        `REQUIRE_DB is set but ${TEST_DATABASE_URL} is unreachable: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    return null;
  }
  await pool.query('DROP SCHEMA IF EXISTS mail CASCADE');
  const sqlDir = fileURLToPath(new URL('../sql/', import.meta.url));
  const files = (await readdir(sqlDir)).filter((f) => /^\d{3}_.*\.sql$/.test(f)).sort();
  for (const f of files) await pool.query(await readFile(join(sqlDir, f), 'utf8'));
  return { db: pgExecutor(pool), pool, close: () => pool.end() };
}

export const SKIP_REASON =
  `no database at ${TEST_DATABASE_URL} — set MAIL_KIT_TEST_DATABASE_URL or ` +
  'run `createdb mail_kit_test` to exercise the SQL paths';
