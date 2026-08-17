// The shipped node-postgres adapter: a `pg.Pool` as a `SqlExecutor`.
//
// `@quxkit/mail-kit/pg` is a separate entry point so the core never imports
// `pg` — it is an optional peer, present only in hosts that use it. Any other
// driver is welcome to implement `SqlExecutor` in the same ~30 lines.

import type { Pool, PoolClient } from 'pg';
import type { SqlExecutor } from './types.ts';

/** Wrap a pinned client. Nested `transaction` calls become savepoints, so a
 *  rollback inside a transaction undoes only the inner body. */
function bound(client: PoolClient, depth: number): SqlExecutor {
  const executor: SqlExecutor = {
    async query<T>(text: string, params?: readonly unknown[]): Promise<T[]> {
      const result = await client.query(text, params as unknown[]);
      return result.rows as T[];
    },
    async transaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T> {
      const sp = `mail_kit_sp_${depth}`;
      await client.query(`SAVEPOINT ${sp}`);
      try {
        const out = await fn(bound(client, depth + 1));
        await client.query(`RELEASE SAVEPOINT ${sp}`);
        return out;
      } catch (error) {
        await client.query(`ROLLBACK TO SAVEPOINT ${sp}`);
        throw error;
      }
    },
  };
  return executor;
}

/**
 * A `SqlExecutor` over a `pg.Pool`. Plain queries go to the pool;
 * `transaction` pins one connection for the body, commits on resolve and
 * rolls back on throw.
 */
export function pgExecutor(pool: Pool): SqlExecutor {
  return {
    async query<T>(text: string, params?: readonly unknown[]): Promise<T[]> {
      const result = await pool.query(text, params as unknown[]);
      return result.rows as T[];
    },
    async transaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const out = await fn(bound(client, 0));
        await client.query('COMMIT');
        return out;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    },
  };
}
