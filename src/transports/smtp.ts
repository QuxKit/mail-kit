// SMTP submission (RFC 5321 / 4954 / 3207), as a transport.
//
// A small client rather than a dependency, because what a relay needs from us
// is small: EHLO, STARTTLS, AUTH PLAIN or LOGIN, MAIL FROM, RCPT TO, DATA,
// QUIT. This is the transport for Postal, KumoMTA, Mailgun/Postmark/SendGrid
// SMTP endpoints, a corporate relay, or your own MTA — anything with a
// hostname and a port. It does not manage identities, so mail-kit holds the
// DKIM key and signs before this transport ever sees the bytes.

import { connect as netConnect, type Socket } from 'node:net';
import { connect as tlsConnect, type ConnectionOptions } from 'node:tls';
import { hostname } from 'node:os';
import { MailError } from '../errors.ts';
import type { MailTransport, OutboundEnvelope, TransportResult } from '../types.ts';

export interface SmtpTransportOptions {
  host: string;
  /** Default 587 (465 when `secure`). */
  port?: number;
  /** Implicit TLS from the first byte (port 465). */
  secure?: boolean;
  /** For plaintext connections: `require` (default) fails if the server does
   *  not offer STARTTLS; `opportunistic` upgrades when offered; `never` for a
   *  loopback relay or a test server. */
  starttls?: 'require' | 'opportunistic' | 'never';
  auth?: { user: string; pass: string };
  /** The name we announce in EHLO. Default: os.hostname(). */
  name?: string;
  /** The `include:` for the SPF record mail-kit asks the host to publish. */
  spfInclude?: string;
  timeoutMs?: number;
  tls?: Pick<ConnectionOptions, 'rejectUnauthorized' | 'servername' | 'ca'>;
}

interface Reply {
  code: number;
  lines: string[];
}

class SmtpError extends Error {
  constructor(
    readonly code: number | null,
    message: string,
  ) {
    super(message);
  }
}

/** A line-oriented reader over the socket that resolves one reply at a time. */
class Conn {
  private buffer = '';
  private waiting: { resolve: (r: Reply) => void; reject: (e: Error) => void } | null = null;
  private closed: Error | null = null;
  socket: Socket;

  constructor(
    socket: Socket,
    private readonly timeoutMs: number,
  ) {
    this.socket = socket;
    this.attach(socket);
  }

  private attach(socket: Socket): void {
    socket.setEncoding('latin1');
    socket.setTimeout(this.timeoutMs, () => this.fail(new SmtpError(null, 'timeout')));
    socket.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.pump();
    });
    socket.on('error', (e) => this.fail(new SmtpError(null, e.message)));
    socket.on('close', () => this.fail(new SmtpError(null, 'connection closed')));
  }

  private fail(e: Error): void {
    this.closed = e;
    if (this.waiting) {
      const w = this.waiting;
      this.waiting = null;
      w.reject(e);
    }
  }

  private pump(): void {
    if (!this.waiting) return;
    const lines = this.buffer.split('\r\n');
    const complete: string[] = [];
    for (let i = 0; i < lines.length - 1; i += 1) {
      complete.push(lines[i]!);
      if (/^\d{3}(?: |$)/.test(lines[i]!)) {
        this.buffer = lines.slice(i + 1).join('\r\n');
        const w = this.waiting;
        this.waiting = null;
        w.resolve({ code: Number(complete[complete.length - 1]!.slice(0, 3)), lines: complete.map((l) => l.slice(4)) });
        return;
      }
    }
  }

  read(): Promise<Reply> {
    if (this.closed) return Promise.reject(this.closed);
    return new Promise((resolve, reject) => {
      this.waiting = { resolve, reject };
      this.pump();
    });
  }

  async command(line: string): Promise<Reply> {
    if (this.closed) throw this.closed;
    this.socket.write(`${line}\r\n`, 'latin1');
    return this.read();
  }

  write(data: string): void {
    this.socket.write(data, 'latin1');
  }

  /** Upgrade to TLS after a 220 to STARTTLS. */
  async upgrade(options: ConnectionOptions): Promise<void> {
    const plain = this.socket;
    plain.removeAllListeners('data');
    plain.removeAllListeners('error');
    plain.removeAllListeners('close');
    plain.setTimeout(0);
    const secured = await new Promise<Socket>((resolve, reject) => {
      const s = tlsConnect({ socket: plain, ...options }, () => resolve(s));
      s.once('error', reject);
    });
    this.buffer = '';
    this.socket = secured;
    this.attach(secured);
  }

  end(): void {
    this.socket.end();
  }
}

/** Dot-stuff and normalise line endings for DATA. */
export function dotStuff(raw: Uint8Array): string {
  let text = Buffer.from(raw).toString('latin1').replace(/\r?\n/g, '\r\n');
  if (!text.endsWith('\r\n')) text += '\r\n';
  return text.replace(/(^|\r\n)\./g, '$1..');
}

/** `250 2.0.0 OK queued as ABC123` → `ABC123`, else null. */
export function queuedId(reply: Reply): string | null {
  const last = reply.lines[reply.lines.length - 1] ?? '';
  const m = /(?:queued as|id=|Message accepted for delivery|Queued mail for delivery)\s*[:\-]?\s*([\w.@<>+-]+)?/i.exec(last);
  return m?.[1] ?? null;
}

export function smtpTransport(opts: SmtpTransportOptions): MailTransport {
  const secure = opts.secure ?? false;
  const port = opts.port ?? (secure ? 465 : 587);
  const starttls = opts.starttls ?? 'require';
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const ehloName = opts.name ?? hostname();

  const retryable = (code: number | null): boolean => code === null || (code >= 400 && code < 500);
  const transportError = (code: number | null, detail: string): MailError =>
    new MailError({ code: 'transport', transport: 'smtp', retryable: retryable(code), status: code ?? undefined, detail });

  const expect = (reply: Reply, ok: number[], what: string): Reply => {
    if (!ok.includes(reply.code)) throw new SmtpError(reply.code, `${what}: ${reply.code} ${reply.lines.join(' / ')}`);
    return reply;
  };

  const open = async (): Promise<Conn> => {
    const socket = await new Promise<Socket>((resolve, reject) => {
      const s = secure
        ? tlsConnect({ host: opts.host, port, servername: opts.host, ...opts.tls }, () => resolve(s))
        : netConnect({ host: opts.host, port }, () => resolve(s));
      s.once('error', reject);
    });
    return new Conn(socket, timeoutMs);
  };

  /** EHLO; returns the extension keywords and the AUTH mechanisms line. */
  const ehlo = async (conn: Conn): Promise<{ ext: Set<string>; auth: string }> => {
    const reply = expect(await conn.command(`EHLO ${ehloName}`), [250], 'EHLO');
    const lines = reply.lines.slice(1);
    return {
      ext: new Set(lines.map((l) => l.split(' ')[0]!.toUpperCase())),
      auth: lines.find((l) => l.toUpperCase().startsWith('AUTH')) ?? '',
    };
  };

  const authenticate = async (conn: Conn, ext: Set<string>, mechanisms: string): Promise<void> => {
    if (!opts.auth) return;
    if (!ext.has('AUTH')) throw new SmtpError(500, 'server offers no AUTH');
    const { user, pass } = opts.auth;
    if (/\bPLAIN\b/i.test(mechanisms)) {
      // RFC 4616: [authzid] NUL authcid NUL passwd
      const token = Buffer.from(`\0${user}\0${pass}`, 'utf8').toString('base64');
      expect(await conn.command(`AUTH PLAIN ${token}`), [235], 'AUTH PLAIN');
      return;
    }
    if (/\bLOGIN\b/i.test(mechanisms)) {
      expect(await conn.command('AUTH LOGIN'), [334], 'AUTH LOGIN');
      expect(await conn.command(Buffer.from(user, 'utf8').toString('base64')), [334], 'AUTH LOGIN user');
      expect(await conn.command(Buffer.from(pass, 'utf8').toString('base64')), [235], 'AUTH LOGIN pass');
      return;
    }
    throw new SmtpError(500, `no supported AUTH mechanism in: ${mechanisms}`);
  };

  return {
    name: 'smtp',
    spfInclude: opts.spfInclude,

    async send(envelope: OutboundEnvelope): Promise<TransportResult> {
      let conn: Conn | null = null;
      try {
        conn = await open();
        expect(await conn.read(), [220], 'greeting');
        let hello = await ehlo(conn);

        if (!secure && starttls !== 'never') {
          if (hello.ext.has('STARTTLS')) {
            expect(await conn.command('STARTTLS'), [220], 'STARTTLS');
            await conn.upgrade({ servername: opts.host, ...opts.tls });
            hello = await ehlo(conn);
          } else if (starttls === 'require') {
            throw new SmtpError(500, 'server does not offer STARTTLS (set starttls: "opportunistic" or "never" only on a trusted network)');
          }
        }
        await authenticate(conn, hello.ext, hello.auth);

        expect(await conn.command(`MAIL FROM:<${envelope.returnPath}>`), [250], 'MAIL FROM');
        const rejected: Array<{ recipient: string; detail: string }> = [];
        let accepted = 0;
        for (const rcpt of envelope.recipients) {
          const r = await conn.command(`RCPT TO:<${rcpt}>`);
          if (r.code === 250 || r.code === 251) accepted += 1;
          else if (r.code >= 500) rejected.push({ recipient: rcpt, detail: `${r.code} ${r.lines.join(' ')}` });
          else throw new SmtpError(r.code, `RCPT TO ${rcpt}: ${r.code} ${r.lines.join(' ')}`);
        }
        if (accepted === 0) {
          throw new SmtpError(550, `every recipient was refused: ${rejected.map((r) => `${r.recipient} (${r.detail})`).join('; ')}`);
        }
        expect(await conn.command('DATA'), [354], 'DATA');
        conn.write(dotStuff(envelope.raw));
        const done = expect(await conn.command('.'), [250], 'end of DATA');
        try {
          await conn.command('QUIT');
        } catch {
          /* the server may close first; the message is already accepted */
        }
        conn.end();
        return { providerMessageId: queuedId(done) ?? envelope.messageId, rejected: rejected.length ? rejected : undefined };
      } catch (error) {
        conn?.end();
        if (error instanceof SmtpError) throw transportError(error.code, error.message);
        throw transportError(null, error instanceof Error ? error.message : String(error));
      }
    },
  };
}
