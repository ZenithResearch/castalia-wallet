#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import process from 'node:process'
import { writeFilesystemNotices } from './filesystem-license-notices.mjs'
import { writeExtensionPackageDigest } from './extension-package-digest.mjs'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(scriptDir, '..')
const extensionRoot = join(repoRoot, 'apps/chrome-extension')
const outputRoot = resolve(
  repoRoot,
  process.env.CASTALIA_EXTENSION_OUTPUT ?? 'build/castalia-wallet-production',
)
// Trust is runtime data, never an entity-specific build input.
if (process.argv.length > 2 || ['CASTALIA_ZENITH_MEMBERSHIP_ISSUER_URL','CASTALIA_ZENITH_MEMBERSHIP_ISSUER_KEY_ID','CASTALIA_ZENITH_MEMBERSHIP_ISSUER_PUBLIC_KEY','CASTALIA_PRESENTATION_TRUST_PINS_JSON'].some(k => process.env[k])) {
  throw new Error('Issuer build configuration is retired. Approve provider profiles in Wallet settings.')
}
const digestPath = `${outputRoot}.contents.sha256`

// A failed build must not leave a previous package looking current.
await rm(outputRoot, { recursive: true, force: true })
await rm(digestPath, { force: true })

const build = spawnSync(
  'npm',
  ['run', 'build', '--workspace', '@castalia-wallet/chrome-extension'],
  {
    cwd: repoRoot,
    env: process.env,
    stdio: 'inherit',
  },
)
if (build.error) throw build.error
if (build.status !== 0) process.exit(build.status ?? 1)

await mkdir(outputRoot, { recursive: true })
await cp(join(extensionRoot, 'icons'), join(outputRoot, 'icons'), { recursive: true })
// Only ship the self-contained production entry bundles, never raw tsc modules.
await mkdir(join(outputRoot, 'dist'), { recursive: true })
for (const file of [
  'read-access-confirmation.js', 'service-worker.js', 'content-script.js', 'provider.js', 'onboarding.js',
  'provider-settings.js', 'credential-presentation-confirmation.js', 'confirmation.js', 'registration-confirmation.js', 'files-key-confirmation.js', 'popup.js',
]) {
  await cp(join(extensionRoot, 'dist', file), join(outputRoot, 'dist', file))
}

await mkdir(join(outputRoot, 'src'), { recursive: true })
for (const file of [
  'provider-settings.html', 'provider-settings.css',
  'read-access-confirmation.html', 'confirmation.css',
  'credential-presentation-confirmation.html',
  'confirmation.html',
  'registration-confirmation.html',
  'files-key-confirmation.html',
  'onboarding.css',
  'onboarding.html',
  'popup.css',
  'popup.html',
  'sidepanel.html',
]) {
  await cp(join(extensionRoot, 'src', file), join(outputRoot, 'src', file))
}

const manifest = JSON.parse(
  await readFile(join(extensionRoot, 'manifest.json'), 'utf8'),
)
manifest.host_permissions = []
manifest.optional_host_permissions = ['https://*/*']
await writeFile(join(outputRoot, 'manifest.json'), `${JSON.stringify(manifest,null,2)}\n`)
await writeFile(join(outputRoot,'provider-configuration.json'), `${JSON.stringify({schema:'castalia.wallet-runtime-trust.v1',defaultProfiles:[],trustSource:'wallet-settings'},null,2)}\n`)

await writeFilesystemNotices(outputRoot)
const packageDigest = await writeExtensionPackageDigest(outputRoot, digestPath)

console.log(`Production Castalia Wallet package: ${outputRoot}`)
console.log('No pretrusted providers; trust is configured at runtime.')
console.log(`Content-tree SHA-256: ${packageDigest.digest}`)
console.log(`Digest sidecar: ${digestPath}`)
