import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createBrowserAcceptancePackage } from './package-browser-acceptance-extension.mjs'
import { writeFilesystemNotices } from './filesystem-license-notices.mjs'
import { digestExtensionPackage, writeExtensionPackageDigest } from './extension-package-digest.mjs'

const revision = 'a1'.repeat(20)
async function setup() {
  const base = await mkdtemp(join(tmpdir(), 'castalia-browser-package-'))
  const sourceRoot = join(base, 'ci-contract'), outputRoot = join(base, 'browser-acceptance')
  await mkdir(join(sourceRoot, 'dist'), { recursive: true })
  await writeFilesystemNotices(sourceRoot)
  await writeFile(join(sourceRoot, 'manifest.json'), JSON.stringify({ manifest_version: 3, host_permissions: [], optional_host_permissions:['https://*/*'], background: { service_worker: 'dist/service-worker.js', type: 'module' } }))
  await writeFile(join(sourceRoot, 'provider-configuration.json'), JSON.stringify({ schema:'castalia.wallet-runtime-trust.v1',defaultProfiles:[],trustSource:'wallet-settings' }))
  await writeFile(join(sourceRoot, 'dist/service-worker.js'), `const wasm = Uint8Array.from(atob('AGFzbQEAAAA='), c => c.charCodeAt(0));\n`)
  await writeFile(join(sourceRoot, 'dist/provider.js'), 'export const provider = true;\n')
  const sourceSidecar = `${sourceRoot}.contents.sha256`
  await writeExtensionPackageDigest(sourceRoot, sourceSidecar)
  return { base, sourceRoot, sourceSidecar, outputRoot, sourceRevision: revision }
}

test('separate fixture is deterministic, preserves source/WASM, and records exact provenance', async () => {
  const f = await setup()
  try {
    const before = await digestExtensionPackage(f.sourceRoot)
    const result = await createBrowserAcceptancePackage(f)
    assert.deepEqual(await digestExtensionPackage(f.sourceRoot), before)
    const second = await createBrowserAcceptancePackage({ ...f, outputRoot: join(f.base, 'second') })
    assert.equal(result.digest, second.digest)
    const provenance = JSON.parse(await readFile(`${f.outputRoot}.provenance.json`, 'utf8'))
    assert.equal(provenance.sourceRevision, revision)
    assert.equal(provenance.sourcePackageDigest, before.digest)
    assert.equal(result.digest,before.digest)
    assert.deepEqual(provenance.transformations,[])
    assert.equal(provenance.embeddedWasm.sha256, '93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476')
    assert.equal(await readFile(join(f.outputRoot, 'dist/provider.js'), 'utf8'), await readFile(join(f.sourceRoot, 'dist/provider.js'), 'utf8'))
    assert.equal(await readFile(`${f.outputRoot}.contents.sha256`, 'utf8'), `${result.digest}  browser-acceptance\n`)
  } finally { await rm(f.base, { recursive: true, force: true }) }
})

test('pretrusted source profile and stale source bytes fail before creating a fixture', async () => {
  const f = await setup()
  try {
    const path = join(f.sourceRoot, 'provider-configuration.json')
    const network = JSON.parse(await readFile(path, 'utf8'))
    await writeFile(path, JSON.stringify({ ...network, defaultProfiles: [{issuer:'pretrusted'}] }))
    await writeExtensionPackageDigest(f.sourceRoot, f.sourceSidecar)
    await assert.rejects(() => createBrowserAcceptancePackage(f), /zero pretrusted/)
    await assert.rejects(readFile(`${f.outputRoot}.provenance.json`), { code: 'ENOENT' })
    await writeFile(path, JSON.stringify(network))
    await writeExtensionPackageDigest(f.sourceRoot, f.sourceSidecar)
    await writeFile(join(f.sourceRoot, 'dist/provider.js'), 'changed')
    await assert.rejects(() => createBrowserAcceptancePackage(f), /digest mismatch/)
  } finally { await rm(f.base, { recursive: true, force: true }) }
})

test('malformed WASM, revision, overlap, and existing output are rejected without overwriting input', async () => {
  const f = await setup()
  try {
    const before = await digestExtensionPackage(f.sourceRoot)
    await assert.rejects(() => createBrowserAcceptancePackage({ ...f, sourceRevision: 'main' }), /exact source commit/)
    await assert.rejects(() => createBrowserAcceptancePackage({ ...f, outputRoot: join(f.sourceRoot, 'nested') }), /separate/)
    await createBrowserAcceptancePackage(f)
    const packaged = await digestExtensionPackage(f.outputRoot)
    await assert.rejects(() => createBrowserAcceptancePackage(f), /exist/)
    assert.deepEqual(await digestExtensionPackage(f.outputRoot), packaged)
    assert.deepEqual(await digestExtensionPackage(f.sourceRoot), before)
    const worker = join(f.sourceRoot, 'dist/service-worker.js')
    await writeFile(worker, (await readFile(worker, 'utf8')).replace('AGFzbQEAAAA=', 'bm90LXdhc20='))
    await writeExtensionPackageDigest(f.sourceRoot, f.sourceSidecar)
    await assert.rejects(() => createBrowserAcceptancePackage({ ...f, outputRoot: join(f.base, 'invalid') }), /embedded WASM/)
  } finally { await rm(f.base, { recursive: true, force: true }) }
})
