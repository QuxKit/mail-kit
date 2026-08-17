# Templates: the renderer seam

mail-kit sends `html` and `text` strings and has no template engine. The
seam is a function:

```ts
type Renderer<T> = (input: T) => RenderedContent | Promise<RenderedContent>;
interface RenderedContent { html?: string; text?: string; subject?: string }
```

`mail.sendRendered(tenantId, renderer, input, envelope, opts?)` calls the
renderer, then `send`s the result in the envelope — everything a
`SendInput` has except `html`/`text`, and an optional `subject` that wins
over the renderer's. Neither side having a subject, or the renderer
yielding neither `html` nor `text`, is `invalid_input`; a rendered subject
with a line break is `header_injection`, exactly as a sent one would be; a
throwing renderer throws. Nothing is written until the render succeeds.

## A plain function

```ts
import type { Renderer } from '@quxkit/mail-kit';

interface Welcome { name: string; plan: string }

const welcome: Renderer<Welcome> = ({ name, plan }) => ({
  subject: `Welcome, ${name}`,
  html: `<h1>Hi ${name}</h1><p>You are on ${plan}.</p>`,
  text: `Hi ${name}\n\nYou are on ${plan}.`,
});

await mail.sendRendered(tenantId, welcome, { name: 'Ada', plan: 'Pro' }, {
  from: 'Acme <hello@example.com>',
  to: 'ada@example.org',
  idempotencyKey: 'welcome-ada',
});
```

Escape what you interpolate. mail-kit treats `html` as finished markup.

## react-email

`react-email` (and `@react-email/components`) is **your** dependency, not
mail-kit's — mail-kit stays zero-runtime-dep and knows nothing about React.
The recipe is one adapter function:

```sh
pnpm add react react-dom @react-email/components @react-email/render
```

```tsx
// emails/Welcome.tsx
import { Body, Container, Head, Heading, Html, Text } from '@react-email/components';

export interface WelcomeProps { name: string; plan: string }

export function Welcome({ name, plan }: WelcomeProps) {
  return (
    <Html>
      <Head />
      <Body>
        <Container>
          <Heading>Hi {name}</Heading>
          <Text>You are on {plan}.</Text>
        </Container>
      </Body>
    </Html>
  );
}
```

```ts
// mail/renderers.ts
import { render } from '@react-email/render';
import type { Renderer } from '@quxkit/mail-kit';
import { Welcome, type WelcomeProps } from '../emails/Welcome';

/** Turn a react-email component into a Renderer. `render` is async in
 *  @react-email/render >= 1; sendRendered awaits either way. */
export function reactEmail<P>(
  Component: (props: P) => JSX.Element,
  subject: (props: P) => string,
): Renderer<P> {
  return async (props) => {
    const element = Component(props);
    return {
      subject: subject(props),
      html: await render(element),
      text: await render(element, { plainText: true }),
    };
  };
}

export const welcome = reactEmail<WelcomeProps>(Welcome, ({ name }) => `Welcome, ${name}`);
```

```ts
await mail.sendRendered(tenantId, welcome, { name: 'Ada', plan: 'Pro' }, {
  from: 'Acme <hello@example.com>',
  to: 'ada@example.org',
});
```

Render both `html` and `text`: mail-kit builds `multipart/alternative` when
both are present, and a text part is what keeps a message out of the
"images only" bucket at strict receivers.

## mjml, Handlebars, anything else

Same shape. `mjml2html(source).html` for the body, your own string for the
subject; a Handlebars template compiled once and called per input. If the
engine renders `subject` too, return it and let the envelope stay silent;
if a campaign tool wants to override, set `envelope.subject`.

## Batches

`sendRendered` is one message. For a batch, render per recipient and hand
the results to `sendBatch`, which runs them under the concurrency cap:

```ts
const inputs = await Promise.all(
  recipients.map(async (r) => ({ ...(await welcome(r)), from, to: r.email, listId: 'newsletter' })),
);
const results = await mail.sendBatch(tenantId, inputs);
```
