// A pg.Pool adapter for SqlExecutor, a schema rebuild, a fake resolver and a
// fetch that records webhook posts.
//
// The store-backed tests run against a real Postgres, because the behaviour
// worth testing — the idempotency conflict on a unique index, SKIP LOCKED
// claims, the suppression upsert — is in the database, not the TypeScript.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import type { DnsResolver, Fetch, FetchInit, SqlExecutor } from '../src/types.ts';

export function fromPool(pool: pg.Pool): SqlExecutor {
  return {
    async query<T>(text: string, params?: readonly unknown[]): Promise<T[]> {
      const result = await pool.query(text, params as unknown[]);
      return result.rows as T[];
    },
    async transaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      const bound: SqlExecutor = {
        async query<R>(text: string, params?: readonly unknown[]): Promise<R[]> {
          const result = await client.query(text, params as unknown[]);
          return result.rows as R[];
        },
        transaction: (inner) => inner(bound),
      };
      try {
        await client.query('BEGIN');
        const out = await fn(bound);
        await client.query('COMMIT');
        return out;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    },
  };
}

export const TEST_DATABASE_URL = process.env.MAIL_KIT_TEST_DATABASE_URL ?? 'postgres://localhost:5432/mail_kit_test';

/** A resolver over a map you fill in as the "customer publishes records". */
export class FakeDns implements DnsResolver {
  txt = new Map<string, string[]>();
  cname = new Map<string, string[]>();
  mx = new Map<string, Array<{ exchange: string; priority: number }>>();
  async resolveTxt(name: string) {
    return this.txt.get(name.toLowerCase()) ?? [];
  }
  async resolveCname(name: string) {
    return this.cname.get(name.toLowerCase()) ?? [];
  }
  async resolveMx(name: string) {
    return this.mx.get(name.toLowerCase()) ?? [];
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
  close(): Promise<void>;
}

export const testDkimKey = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

export async function setupDatabase(): Promise<Harness | null> {
  const pool = new pg.Pool({ connectionString: TEST_DATABASE_URL, max: 4 });
  try {
    await pool.query('SELECT 1');
  } catch {
    await pool.end().catch(() => {});
    return null;
  }
  await pool.query('DROP SCHEMA IF EXISTS mail CASCADE');
  await pool.query(await readFile(fileURLToPath(new URL('../sql/001_mail.sql', import.meta.url)), 'utf8'));
  return { db: fromPool(pool), close: () => pool.end() };
}

export const SKIP_REASON =
  `no database at ${TEST_DATABASE_URL} — set MAIL_KIT_TEST_DATABASE_URL or ` +
  'run `createdb mail_kit_test` to exercise the SQL paths';
