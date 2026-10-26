import { localBuildEnvironment } from './local-build-environment.mjs'
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'


const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const buildEnv = process.env.BUILDKITE === 'true' ? await (await import('./canonical-build.mjs')).canonicalBuildEnvironment(root) : localBuildEnvironment(root)
// wasm-pack resolves metadata before cargo build and can otherwise repair a stale
// lockfile before its forwarded --locked flag reaches compilation.
const metadata = spawnSync('cargo', ['metadata', '--locked', '--format-version', '1'], {
  cwd: root, env: buildEnv, stdio: ['ignore', 'ignore', 'inherit'],
})
if (metadata.error) console.error(`failed to run cargo metadata: ${metadata.error.message}`)
if (metadata.status !== 0) process.exit(metadata.status ?? 1)
const generated = join(root, 'apps/chrome-extension/src/generated/castalia-wallet-core')
await rm(generated, { recursive: true, force: true })
await mkdir(generated, { recursive: true })
const result = spawnSync('wasm-pack', [
  'build', 'crates/castalia-wallet-core', ...(process.env.BUILDKITE === 'true' ? ['--mode', 'no-install'] : []), '--target', 'web', '--release',
  '--out-dir', generated, '--out-name', 'castalia_wallet_core', '--', '--locked',
], { cwd: root, env: buildEnv, stdio: 'inherit' })
if (result.error) console.error(`failed to run wasm-pack: ${result.error.message}`)
if (result.status !== 0) process.exit(result.status ?? 1)
const wasm = await readFile(join(generated, 'castalia_wallet_core_bg.wasm'))
const wasmModule = `export const CASTALIA_WALLET_CORE_WASM = Uint8Array.from(atob('${wasm.toString('base64')}'), c => c.charCodeAt(0))\n`
await writeFile(join(generated, 'wasm-bytes.js'), wasmModule)
await writeFile(join(generated, 'wasm-bytes.d.ts'), 'export declare const CASTALIA_WALLET_CORE_WASM: Uint8Array\n')
const bindings = await readFile(join(generated, 'castalia_wallet_core.js'), 'utf8')
await writeFile(join(generated, 'bindings.js'), bindings)
await writeFile(
  join(generated, 'bindings.d.ts'),
  "export { default, initSync, WasmWallet, servicePresentationContext, verifyServiceAccessPoint } from './castalia_wallet_core.js'\n",
)
