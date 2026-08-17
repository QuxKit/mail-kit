// @quxkit/mail-kit/ses — the Amazon SES transport, SNS parsing and verification.

export type { SesTransportOptions, SnsMessage } from './transports/ses.ts';
export { parseSesEvents, sesTransport, verifySnsMessage } from './transports/ses.ts';
export type { AwsCredentials, SignInput } from './transports/sigv4.ts';
export { signV4 } from './transports/sigv4.ts';
