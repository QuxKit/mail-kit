// The mail surface, bound to one executor, one transport and one config.
//
// `createMail` is a factory, not a singleton: config is an argument and never a
// module global, so two instances (a test and a worker, or two regions) can
// hold different transports and different databases in one process. The free
// `create*` functions each module exports are still the API; this binds the
// shared dependencies over them for the common case where an application has
// one of each.

import { createDomains, type DomainsApi } from './domains.ts';
import { createEvents, type EventsApi } from './events.ts';
import { createMessages, type MessagesApi } from './messages.ts';
import { createSuppression, type SuppressionApi } from './suppression.ts';
import type { Clock, DnsResolver, Fetch, Logger, MailConfig, MailTransport, SqlExecutor } from './types.ts';
import { createWebhooks, type WebhooksApi } from './webhooks.ts';

export interface MailOptions {
  db: SqlExecutor;
  transport: MailTransport;
  config?: MailConfig;
  /** For domain verification. Default: node's resolver (`nodeDnsResolver()`). */
  dns?: DnsResolver;
  /** For webhook delivery. Default: the global `fetch`. */
  fetch?: Fetch;
  clock?: Clock;
  logger?: Logger;
}

export interface Mail extends MessagesApi {
  domains: DomainsApi;
  suppression: SuppressionApi;
  webhooks: WebhooksApi;
  events: EventsApi;
  /** Everything a worker loop should do on a tick: due sends, due webhooks,
   *  pending domain checks. Call it every few seconds from one or more
   *  processes; each part claims its own rows. */
  tick(
    now?: Date,
  ): Promise<{ sent: number; failed: number; retried: number; webhooks: number; domainsChecked: number }>;
}

export function createMail(opts: MailOptions): Mail {
  const config = opts.config ?? {};
  const clock: Clock = opts.clock ?? (() => new Date());
  const fetchImpl: Fetch = opts.fetch ?? ((url, init) => globalThis.fetch(url, init) as unknown as ReturnType<Fetch>);
  const dns = opts.dns ?? lazyNodeDns();
  const dnsLookup = opts.dns?.lookup;

  const suppression = createSuppression({ db: opts.db, clock });
  const webhooks = createWebhooks({
    db: opts.db,
    fetch: fetchImpl,
    clock,
    logger: opts.logger,
    maxAttempts: config.webhookMaxAttempts,
    resolve: dnsLookup ? dnsLookup.bind(opts.dns) : undefined,
    allowInsecureHttp: config.allowInsecureHttp,
  });
  const events = createEvents({ db: opts.db, suppression, webhooks, clock, logger: opts.logger });
  const domains = createDomains({
    db: opts.db,
    transport: opts.transport,
    dns,
    config,
    webhooks,
    clock,
    logger: opts.logger,
  });
  const messages = createMessages({
    db: opts.db,
    transport: opts.transport,
    domains,
    suppression,
    events,
    webhooks,
    config,
    clock,
    logger: opts.logger,
  });

  return {
    ...messages,
    domains,
    suppression,
    webhooks,
    events,
    async tick(now = clock()) {
      const s = await messages.deliverPending(50, now);
      const w = await webhooks.deliverPending(50, now);
      const d = await domains.verifyPending({ limit: 20 });
      return { ...s, webhooks: w.delivered + w.retried + w.failed, domainsChecked: d.length };
    },
  };
}

/** Import node:dns only when the default resolver is actually used. */
function lazyNodeDns(): DnsResolver {
  let real: DnsResolver | null = null;
  const get = async (): Promise<DnsResolver> => {
    if (!real) real = (await import('./dns.ts')).nodeDnsResolver();
    return real;
  };
  return {
    resolveTxt: (n) => get().then((r) => r.resolveTxt(n)),
    resolveCname: (n) => get().then((r) => r.resolveCname(n)),
    resolveMx: (n) => get().then((r) => r.resolveMx(n)),
  };
}
