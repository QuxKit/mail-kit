// @quxkit/mail-kit/ses — the Amazon SES transport, SNS parsing and verification.
export { sesTransport, parseSesEvents, verifySnsMessage } from './transports/ses.ts';
export type { SesTransportOptions, SnsMessage } from './transports/ses.ts';
export { signV4 } from './transports/sigv4.ts';
export type { AwsCredentials, SignInput } from './transports/sigv4.ts';
