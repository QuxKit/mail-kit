// The default DnsResolver, over node:dns/promises.
//
// A separate file so the core never imports `node:dns` unless the host asks
// for the default — tests hand in a map, and a host behind a split-horizon
// resolver may hand in something that asks a public one.

import { promises as dns } from 'node:dns';
import type { DnsResolver } from './types.ts';

const notFound = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && 'code' in error &&
  ['ENOTFOUND', 'ENODATA', 'ESERVFAIL'].includes(String((error as { code: unknown }).code));

export function nodeDnsResolver(servers?: string[]): DnsResolver {
  const r = new dns.Resolver();
  if (servers?.length) r.setServers(servers);
  const swallow = async <T>(p: Promise<T>, empty: T): Promise<T> => {
    try {
      return await p;
    } catch (error) {
      if (notFound(error)) return empty;
      throw error;
    }
  };
  return {
    // node returns each TXT record as its chunks; a record is their concatenation
    resolveTxt: (name) => swallow(r.resolveTxt(name).then((rr) => rr.map((chunks) => chunks.join(''))), []),
    resolveCname: (name) => swallow(r.resolveCname(name), []),
    resolveMx: (name) => swallow(r.resolveMx(name), []),
  };
}
