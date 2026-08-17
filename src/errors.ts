// Typed failures.
//
// Same rule as the rest of the family: errors are a discriminated union, never a
// message string. A caller deciding what to do — retry, show "verify your
// domain first", drop the recipient — must not make the decision by matching
// prose that changes the first time someone improves the wording.

export type MailFailure =
  | { code: 'invalid_address'; address: string; reason: string }
  | { code: 'header_injection'; header: string }
  | { code: 'invalid_input'; reason: string }
  /** The `from` domain is not registered for this tenant, or not verified. */
  | { code: 'domain_not_verified'; domain: string; status: 'missing' | 'pending' | 'failed' }
  /** Same idempotency key, different content. */
  | { code: 'idempotency_conflict'; key: string }
  | { code: 'not_found'; what: string; id: string }
  /** The message is past the point where the operation applies (cancel a sent one). */
  | { code: 'invalid_state'; id: string; status: string; operation: string }
  /** The transport failed. `retryable` is the transport's own judgement. */
  | { code: 'transport'; transport: string; retryable: boolean; status?: number; detail: string }
  /** A domain on a non-signing transport needs `config.dkimKey`. */
  | { code: 'dkim_key_required' }
  /** Something else needs `config.dkimKey` (the mail key): unsubscribe tokens. */
  | { code: 'mail_key_required'; purpose: string }
  | { code: 'signature_invalid'; reason: string }
  /** A webhook URL that is not https (without `allowInsecureHttp`), or whose
   *  host is loopback, private, link-local, multicast or otherwise internal. */
  | { code: 'webhook_url_forbidden'; url: string; reason: string };

export type MailErrorCode = MailFailure['code'];

function describe(failure: MailFailure): string {
  switch (failure.code) {
    case 'invalid_address':
      return `invalid address ${JSON.stringify(failure.address)}: ${failure.reason}`;
    case 'header_injection':
      return `header ${JSON.stringify(failure.header)} contains a line break`;
    case 'invalid_input':
      return failure.reason;
    case 'domain_not_verified':
      return failure.status === 'missing'
        ? `domain ${failure.domain} is not registered for this tenant`
        : `domain ${failure.domain} is ${failure.status}, not verified`;
    case 'idempotency_conflict':
      return `idempotency key ${JSON.stringify(failure.key)} was used with different content`;
    case 'not_found':
      return `no ${failure.what} ${failure.id}`;
    case 'invalid_state':
      return `cannot ${failure.operation} message ${failure.id}: it is ${failure.status}`;
    case 'transport':
      return `${failure.transport}: ${failure.detail}${failure.retryable ? ' (retryable)' : ''}`;
    case 'dkim_key_required':
      return 'this transport does not sign; set config.dkimKey so mail-kit can hold a DKIM key for the domain';
    case 'mail_key_required':
      return `set config.dkimKey (the mail key) to use ${failure.purpose}`;
    case 'signature_invalid':
      return `signature invalid: ${failure.reason}`;
    case 'webhook_url_forbidden':
      return `webhook url ${failure.url} is not allowed: ${failure.reason}`;
  }
}

/** The one error class. Carries the union; the message is derived from it. */
export class MailError extends Error {
  readonly failure: MailFailure;
  readonly code: MailErrorCode;

  constructor(failure: MailFailure) {
    super(describe(failure));
    this.name = 'MailError';
    this.failure = failure;
    this.code = failure.code;
  }

  /** Narrow without instanceof, which fails across duplicated module copies. */
  static is(error: unknown): error is MailError {
    return error instanceof Error && error.name === 'MailError' && 'failure' in error;
  }

  static hasCode<C extends MailErrorCode>(
    error: unknown,
    code: C,
  ): error is MailError & { failure: Extract<MailFailure, { code: C }> } {
    return MailError.is(error) && error.code === code;
  }
}
