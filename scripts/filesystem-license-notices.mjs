import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const requireExtension = createRequire(join(root, 'apps/chrome-extension/package.json'))
const dependencyRoot = resolve(dirname(requireExtension.resolve('@castalia/filesystem/registration')), '../../..')
const FILESYSTEM_PACKAGE_SHA256 = '3c31baf3d619ebc63c0a8b24982dd2d7b9607e785083c81a2903d2fcf0ef91e2'
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')
const registrationFiles = [
  'address.mjs', 'registration-crypto.mjs', 'registration-membership.mjs',
  'registration.mjs', 'registration.d.mts',
]

async function noticeFiles(sourceRoot = dependencyRoot) {
  const consumer = JSON.parse(await readFile(join(root, 'apps/chrome-extension/package.json'), 'utf8'))
  const pin = consumer.dependencies['@castalia/filesystem']
  const providerTypes = JSON.parse(await readFile(join(root, 'packages/provider-types/package.json'), 'utf8'))
  if (providerTypes.dependencies['@castalia/filesystem'] !== pin)
    throw new Error('Filesystem runtime and provider declaration pins differ')
  const match = /^https:\/\/codeload\.github\.com\/ZenithResearch\/castalia-filesystem\/tar\.gz\/([0-9a-f]{40})$/.exec(pin)
  if (!match) throw new Error('Filesystem notices require an immutable source pin')
  const revision = match[1]
  const manifestBytes = await readFile(join(root, 'docs/filesystem-package-manifest.json'))
  if (sha256(manifestBytes) !== FILESYSTEM_PACKAGE_SHA256)
    throw new Error('Filesystem reviewed manifest digest mismatch')
  const manifest = JSON.parse(manifestBytes)
  if (manifest.schema !== 'castalia.filesystem.package.v1' ||
      manifest.source.repository !== 'https://github.com/ZenithResearch/castalia-filesystem' ||
      manifest.source.revision !== revision || manifest.source.dirty || manifest.source.mode !== 'candidate')
    throw new Error('Filesystem reviewed source revision mismatch')
  async function reviewedFile(path) {
    const entries = manifest.files.filter(file => file.path === path)
    const bytes = await readFile(join(sourceRoot, path))
    if (entries.length !== 1 || entries[0].size !== bytes.length || entries[0].sha256 !== sha256(bytes))
      throw new Error(`Filesystem installed source mismatch: ${path}`)
    return bytes
  }
  const files = new Map([
    ['castalia-filesystem-AGPL-3.0.txt', await reviewedFile('LICENSE')],
  ])
  for (const name of registrationFiles) {
    files.set(`filesystem-registration-source/${name}`, await reviewedFile(`packages/browser/src/${name}`))
  }
  files.set('castalia-filesystem-source.txt', Buffer.from(`Castalia filesystem registration library — review candidate
License: AGPL-3.0-or-later; see castalia-filesystem-AGPL-3.0.txt.
Source revision: ${revision}
Complete editable library source and build inputs: ${pin}
Source tree and build instructions: https://github.com/ZenithResearch/castalia-filesystem/tree/${revision}
The registration entry's four runtime modules and declaration are included in filesystem-registration-source/.
The library's copied notices and source files are unmodified. Wallet bundles its registration contract.
This entry does not import the browser adapter, filesystem WASM or ZIP implementation.
Inherited Wallet verifier/fixture permission and the combined Wallet distribution boundary remain unresolved.
These notices do not grant a license to unrelated Wallet code or establish distribution clearance.
The library is supplied without warranty; the full license states the applicable terms.
`))
  return files
}

export async function writeFilesystemNotices(packageRoot, { sourceRoot } = {}) {
  const files = await noticeFiles(sourceRoot)
  for (const [path, bytes] of files) {
    const destination = join(packageRoot, 'licenses', path)
    await mkdir(dirname(destination), { recursive: true })
    await writeFile(destination, bytes)
  }
  return files.size
}

export async function verifyFilesystemNotices(packageRoot) {
  for (const [path, expected] of await noticeFiles()) {
    let actual
    try { actual = await readFile(join(packageRoot, 'licenses', path)) }
    catch { throw new Error(`Filesystem notice missing: ${path}`) }
    if (!actual.equals(expected)) throw new Error(`Filesystem notice mismatch: ${path}`)
  }
}
