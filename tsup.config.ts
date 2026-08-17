// Build config — esbuild via tsup, matching the QuxKit family.
//
// tsc cannot emit this source: it imports with explicit `.ts` extensions, which
// tsc only accepts under `allowImportingTsExtensions` + `noEmit`. esbuild
// rewrites those specifiers to the emitted files, so the style is fine in src/.
import { defineConfig, type Options } from 'tsup';

const shared: Options = {
  sourcemap: true,
  splitting: false,
  bundle: true,
  // pg is an optional peer loaded by the host; nothing else is a dependency.
  external: ['pg'],
  skipNodeModulesBundle: true,
  target: 'es2022',
  platform: 'node',
  removeNodeProtocol: false,
  outExtension: ({ format }) => ({ js: format === 'esm' ? '.mjs' : '.cjs' }),
};

export default defineConfig([
  {
    ...shared,
    entry: ['src/index.ts', 'src/ses.ts', 'src/smtp.ts', 'src/memory.ts', 'src/pg.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
  },
]);
