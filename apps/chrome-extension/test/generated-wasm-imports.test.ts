import assert from 'node:assert/strict'
import { access, readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const extensionRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

test('clean WASM generation creates every custody runtime import target', async () => {
  const source = await readFile(resolve(extensionRoot, 'src/custody-runtime.ts'), 'utf8')
  const imports = [...source.matchAll(/from ['"](\.\/generated\/castalia-wallet-core\/[^'"]+)['"]/g)]
    .map(match => match[1])

  assert.deepEqual(imports.sort(), [
    './generated/castalia-wallet-core/bindings.js',
    './generated/castalia-wallet-core/wasm-bytes.js',
  ])
  for (const specifier of imports) {
    await access(resolve(extensionRoot, 'src', specifier))
  }
})
