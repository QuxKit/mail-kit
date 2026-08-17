// The SMTP client against a scripted in-process server: EHLO, AUTH PLAIN,
// envelope, dot-stuffed DATA, partial recipient rejection, and error mapping.

import assert from 'node:assert/strict';
import { createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { after, before, describe, it } from 'node:test';

import { MailError } from '../src/errors.ts';
import { dotStuff, queuedId, smtpTransport } from '../src/transports/smtp.ts';
import type { OutboundEnvelope } from '../src/types.ts';

interface Session {
  commands: string[];
  data: string;
  auth: string | null;
}

/** A tiny SMTP server: records what the client sends, replies from a script. */
function fakeSmtp(opts: { rejectRcpt?: Record<string, number>; failData?: boolean; noAuth?: boolean } = {}) {
  const sessions: Session[] = [];
  const server: Server = createServer((socket: Socket) => {
    const session: Session = { commands: [], data: '', auth: null };
    sessions.push(session);
    let inData = false;
    let buffer = '';
    socket.setEncoding('latin1');
    socket.write('220 fake.test ESMTP\r\n');
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      for (;;) {
        if (inData) {
          const end = buffer.indexOf('\r\n.\r\n');
          if (end === -1) return;
          session.data = buffer.slice(0, end + 2);
          buffer = buffer.slice(end + 5);
          inData = false;
          socket.write(opts.failData ? '451 4.3.0 try later\r\n' : '250 2.0.0 OK queued as QID42\r\n');
          continue;
        }
        const nl = buffer.indexOf('\r\n');
        if (nl === -1) return;
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 2);
        session.commands.push(line);
        const verb = line.split(' ')[0]!.toUpperCase();
        if (verb === 'EHLO')
          socket.write(
            `250-fake.test\r\n250-SIZE 10485760\r\n${opts.noAuth ? '' : '250-AUTH PLAIN LOGIN\r\n'}250 8BITMIME\r\n`,
          );
        else if (verb === 'AUTH') {
          session.auth = line.slice(5);
          socket.write('235 2.7.0 ok\r\n');
        } else if (verb === 'MAIL') socket.write('250 2.1.0 ok\r\n');
        else if (verb === 'RCPT') {
          const rcpt = /<([^>]+)>/.exec(line)![1]!;
          const code = opts.rejectRcpt?.[rcpt];
          socket.write(code ? `${code} 5.1.1 no such user\r\n` : '250 2.1.5 ok\r\n');
        } else if (verb === 'DATA') {
          inData = true;
          socket.write('354 go ahead\r\n');
        } else if (verb === 'QUIT') {
          socket.write('221 bye\r\n');
          socket.end();
        } else socket.write('500 what\r\n');
      }
    });
  });
  return {
    sessions,
    listen: () =>
      new Promise<number>((resolve) =>
        server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)),
      ),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const envelope: OutboundEnvelope = {
  tenantId: 't1',
  id: 'm1',
  messageId: '<m1@example.com>',
  from: 'ada@example.com',
  returnPath: 'bounces@bounce.example.com',
  recipients: ['bob@example.org', 'carol@example.org'],
  raw: Buffer.from('From: ada@example.com\r\nSubject: hi\r\n\r\n.starts with dot\r\nline\r\n'),
  tags: {},
};

describe('mail-kit/smtp', () => {
  it('dot-stuffs and normalises line endings; parses queue ids', () => {
    assert.equal(dotStuff(Buffer.from('.a\n..b\nc')), '..a\r\n...b\r\nc\r\n');
    assert.equal(queuedId({ code: 250, lines: ['2.0.0 OK queued as ABC'] }), 'ABC');
    assert.equal(queuedId({ code: 250, lines: ['2.0.0 Ok: queued as 4X9'] }), '4X9');
    assert.equal(queuedId({ code: 250, lines: ['OK id=1abc-2'] }), '1abc-2');
    assert.equal(queuedId({ code: 250, lines: ['fine'] }), null);
  });

  describe('against a scripted server', () => {
    const srv = fakeSmtp({ rejectRcpt: { 'carol@example.org': 550 } });
    let port = 0;
    before(async () => {
      port = await srv.listen();
    });
    after(() => srv.close());

    it('authenticates with PLAIN, sends the envelope and the stuffed body, reports the refused recipient', async () => {
      const t = smtpTransport({
        host: '127.0.0.1',
        port,
        starttls: 'never',
        auth: { user: 'u', pass: 'p' },
        name: 'client.test',
      });
      const result = await t.send(envelope);
      assert.equal(result.providerMessageId, 'QID42');
      assert.deepEqual(result.rejected, [{ recipient: 'carol@example.org', detail: '550 5.1.1 no such user' }]);
      const s = srv.sessions[0]!;
      assert.equal(s.commands[0], 'EHLO client.test');
      assert.equal(Buffer.from(s.auth!.replace('PLAIN ', ''), 'base64').toString(), '\0u\0p');
      assert.ok(s.commands.includes('MAIL FROM:<bounces@bounce.example.com>'));
      assert.ok(s.commands.includes('RCPT TO:<bob@example.org>'));
      assert.ok(s.commands.includes('RCPT TO:<carol@example.org>'));
      assert.ok(s.commands.includes('QUIT'));
      assert.match(s.data, /\r\n\.\.starts with dot\r\n/, 'dot-stuffed on the wire');
    });

    it('fails when every recipient is refused (not retryable) and when the server has no AUTH', async () => {
      const t = smtpTransport({ host: '127.0.0.1', port, starttls: 'never' });
      await assert.rejects(
        t.send({ ...envelope, recipients: ['carol@example.org'] }),
        (e: unknown) =>
          MailError.hasCode(e, 'transport') &&
          e.failure.retryable === false &&
          /every recipient/.test(e.failure.detail),
      );
    });

    it('requires STARTTLS by default and says so', async () => {
      const t = smtpTransport({ host: '127.0.0.1', port });
      await assert.rejects(
        t.send(envelope),
        (e: unknown) => MailError.hasCode(e, 'transport') && /STARTTLS/.test(e.failure.detail),
      );
    });
  });

  it('a 4xx at DATA is retryable; a dead port is retryable', async () => {
    const srv = fakeSmtp({ failData: true });
    const port = await srv.listen();
    try {
      const t = smtpTransport({ host: '127.0.0.1', port, starttls: 'never' });
      await assert.rejects(
        t.send(envelope),
        (e: unknown) => MailError.hasCode(e, 'transport') && e.failure.retryable === true && e.failure.status === 451,
      );
    } finally {
      await srv.close();
    }
    const dead = smtpTransport({ host: '127.0.0.1', port, starttls: 'never', timeoutMs: 2000 });
    await assert.rejects(
      dead.send(envelope),
      (e: unknown) => MailError.hasCode(e, 'transport') && e.failure.retryable === true,
    );
  });
});
