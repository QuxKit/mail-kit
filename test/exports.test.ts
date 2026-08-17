// The public surface: every entry point imports, and the names the README
// promises are there. Catches a dropped export before a consumer does.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { nodeDnsResolver, nodeLookup } from '../src/dns.ts';
import * as root from '../src/index.ts';
import * as memory from '../src/memory.ts';
import * as pgEntry from '../src/pg.ts';
import * as ses from '../src/ses.ts';
import * as smtp from '../src/smtp.ts';

describe('mail-kit/exports', () => {
  it('root entry exports the API, the errors and the helpers', () => {
    for (const name of [
      'createMail',
      'createMessages',
      'createDomains',
      'createEvents',
      'createSuppression',
      'createWebhooks',
      'enqueueWebhookDeliveries',
      'signWebhook',
      'verifyWebhookSignature',
      'buildMime',
      'buildMimeDetailed',
      'assertAttachmentSafe',
      'parseAddress',
      'dkimSign',
      'dkimVerify',
      'generateDkimKey',
      'nodeDnsResolver',
      'nodeLookup',
      'assertWebhookUrlAllowed',
      'forbiddenAddressReason',
      'clampLimit',
      'createUnsubscribe',
      'MailError',
    ]) {
      assert.equal(typeof (root as Record<string, unknown>)[name], 'function', name);
    }
    assert.equal(root.MAX_LIST_LIMIT, 200);
    assert.equal(root.MAX_BATCH, 500);
    assert.ok(Array.isArray(root.ALL_WEBHOOK_EVENTS));
    assert.ok(Array.isArray(root.WEBHOOK_RETRY_SCHEDULE_S));
    assert.ok(Array.isArray(root.SEND_RETRY_SCHEDULE_S));
  });

  it('transport and adapter entries export their factories', () => {
    assert.equal(typeof ses.sesTransport, 'function');
    assert.equal(typeof ses.parseSesEvents, 'function');
    assert.equal(typeof ses.verifySnsMessage, 'function');
    assert.equal(typeof smtp.smtpTransport, 'function');
    assert.equal(typeof memory.memoryTransport, 'function');
    assert.equal(typeof pgEntry.pgExecutor, 'function');
  });

  it('the node resolver resolves localhost through the system lookup', async () => {
    const r = nodeDnsResolver();
    assert.equal(typeof r.lookup, 'function');
    const addrs = await nodeLookup('localhost');
    assert.ok(
      addrs.some((a) => a === '127.0.0.1' || a === '::1'),
      JSON.stringify(addrs),
    );
    assert.deepEqual(await nodeLookup('definitely-not-a-host.invalid'), []);
    // and localhost is refused by the guard whatever it resolves to
    await assert.rejects(
      root.assertWebhookUrlAllowed(new URL('https://localhost/x'), { resolve: nodeLookup }),
      (e: unknown) => root.MailError.hasCode(e, 'webhook_url_forbidden'),
    );
  });
});
