import { build } from 'esbuild';
import { mkdir, rm } from 'node:fs/promises';
import { writeFilesystemNotices } from './filesystem-license-notices.mjs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';


const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const extensionDir = join(rootDir, 'apps/chrome-extension');
const distDir = join(extensionDir, 'dist');

async function bundle() {
  console.log('Bundling Castalia Wallet with runtime provider trust (no pretrusted issuers)...');

  // Never retain stale entry points from an older source checkout.
  await rm(distDir, { recursive: true, force: true });
  await mkdir(distDir, { recursive: true });

  const shimPath = join(extensionDir, 'src/crypto-browser.ts');

  const common = {
    bundle: true,
    platform: 'browser',
    target: 'es2022',
    minifySyntax: true,
    logLevel: 'info',
    tsconfig: join(extensionDir, 'tsconfig.json'),
    plugins: [
      {
        name: 'local-shim-resolver',
        setup(build) {
          build.onResolve({ filter: /^\.\/crypto-browser(\.ts)?$/ }, (args) => {
            return { path: shimPath };
          });
        },
      },
    ],
  };

  // Bundle Service Worker (ESM is fine)
  await build({
    ...common,
    format: 'esm',
    entryPoints: [join(extensionDir, 'src/service-worker.ts')],
    outfile: join(distDir, 'service-worker.js'),
  });

  await build({...common,format:'iife',entryPoints:[join(extensionDir,'src/wallet-identities.ts')],outfile:join(distDir,'wallet-identities.js')});
  await build({...common,format:'iife',entryPoints:[join(extensionDir,'src/holder-grants.ts')],outfile:join(distDir,'holder-grants.js')});

  // Bundle Content Script as IIFE (required for MV3 content scripts)
  await build({
    ...common,
    format: 'iife',
    entryPoints: [join(extensionDir, 'src/content-script.ts')],
    outfile: join(distDir, 'content-script.js'),
  });

  // Bundle the page-world provider as an IIFE loaded through web_accessible_resources.
  await build({
    ...common,
    format: 'iife',
    entryPoints: [join(extensionDir, 'src/provider.ts')],
    outfile: join(distDir, 'provider.js'),
  });

  await build({
    ...common,
    format: 'iife',
    entryPoints: [join(extensionDir, 'src/onboarding.ts')],
    outfile: join(distDir, 'onboarding.js'),
  });

  await build({
    ...common,
    format: 'iife',
    entryPoints: [join(extensionDir, 'src/confirmation.ts')],
    outfile: join(distDir, 'confirmation.js'),
  });

  await build({ ...common, format: 'iife', entryPoints: [join(extensionDir, 'src/files-key-confirmation.ts')], outfile: join(distDir, 'files-key-confirmation.js') });

  await build({ ...common, format: 'iife', entryPoints: [join(extensionDir, 'src/credential-presentation-confirmation.ts')], outfile: join(distDir, 'credential-presentation-confirmation.js') });

  await build({ ...common, format: 'iife', entryPoints: [join(extensionDir, 'src/registration-confirmation.ts')], outfile: join(distDir, 'registration-confirmation.js') });


  await build({
    ...common,
    format: 'iife',
    entryPoints: [join(extensionDir, 'src/popup.ts')],
    outfile: join(distDir, 'popup.js'),
  });

  await build({ ...common, format: 'iife', entryPoints: [join(extensionDir, 'src/provider-settings.ts')], outfile: join(distDir, 'provider-settings.js') });
  await build({ ...common, format: 'iife', entryPoints: [join(extensionDir, 'src/read-access-confirmation.ts')], outfile: join(distDir, 'read-access-confirmation.js') });
  await writeFilesystemNotices(extensionDir);
  console.log('✅ Extension bundles created successfully.');
}

bundle().catch(err => {
  console.error(err);
  process.exit(1);
});
