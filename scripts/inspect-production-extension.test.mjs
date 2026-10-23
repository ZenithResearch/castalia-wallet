import assert from 'node:assert/strict'
import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { writeExtensionPackageDigest } from './extension-package-digest.mjs'
import { writeFilesystemNotices } from './filesystem-license-notices.mjs'
import { inspectProductionExtension } from './inspect-production-extension.mjs'

async function writeValidPackage(root) {
  await mkdir(join(root, 'dist'), { recursive: true })
  await writeFilesystemNotices(root)
  await writeFile(join(root, 'manifest.json'), `${JSON.stringify({
    manifest_version: 3,
    host_permissions: [], optional_host_permissions:['https://*/*'],
    background: { service_worker: 'dist/service-worker.js', type: 'module' },
  })}\n`)
  await writeFile(join(root,'provider-configuration.json'),JSON.stringify({schema:'castalia.wallet-runtime-trust.v1',defaultProfiles:[],trustSource:'wallet-settings'}))
  await writeFile(join(root,'dist/service-worker.js'),'export const noPretrustedProviders = true;')
}

test('inspection proves the zero default trust and content-tree sidecar', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-production-inspect-'))
  const root = join(fixture, 'castalia-wallet-production')
  const sidecar = `${root}.contents.sha256`
  try {
    await writeValidPackage(root)
    const packaged = await writeExtensionPackageDigest(root, sidecar)
    assert.deepEqual(
      await inspectProductionExtension(root, sidecar),
      packaged,
    )
  } finally {
    await rm(fixture, { recursive: true, force: true })
  }
})

test('inspection rejects permission drift, loopback residue, and stale content', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-production-reject-'))
  const root = join(fixture, 'castalia-wallet-production')
  const sidecar = `${root}.contents.sha256`
  try {
    await writeValidPackage(root)
    await writeExtensionPackageDigest(root, sidecar)

    await writeFile(join(root, 'dist', 'extra.js'), 'fetch("http://127.0.0.1:3002/health")\n')
    await assert.rejects(
      () => inspectProductionExtension(root, sidecar),
      /loopback membership issuer/,
    )

    await rm(join(root, 'dist', 'extra.js'))
    await writeFile(join(root, 'manifest.json'), `${JSON.stringify({
      manifest_version: 3,
      host_permissions: ['<all_urls>'],
      background: { service_worker: 'dist/service-worker.js', type: 'module' },
    })}\n`)
    await assert.rejects(
      () => inspectProductionExtension(root, sidecar),
      /host permissions/,
    )

    await writeValidPackage(root)
    await writeFile(join(root, 'dist', 'extra.js'), '// changed after digest\n')
    await assert.rejects(
      () => inspectProductionExtension(root, sidecar),
      /content-tree digest mismatch/,
    )
  } finally {
    await rm(fixture, { recursive: true, force: true })
  }
})


test('inspection rejects missing or modified license material even with a fresh content digest', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-production-notices-'))
  const root = join(fixture, 'package')
  const sidecar = `${root}.contents.sha256`
  try {
    await writeValidPackage(root)
    await rm(join(root, 'licenses/castalia-filesystem-AGPL-3.0.txt'))
    await writeExtensionPackageDigest(root, sidecar)
    await assert.rejects(() => inspectProductionExtension(root, sidecar), /Filesystem notice missing/)
    await writeValidPackage(root)
    await writeFile(join(root, 'licenses/castalia-filesystem-source.txt'), 'incorrect source pin')
    await writeExtensionPackageDigest(root, sidecar)
    await assert.rejects(() => inspectProductionExtension(root, sidecar), /Filesystem notice mismatch/)
  } finally { await rm(fixture, { recursive: true, force: true }) }
})


test('notice packaging rejects changed installed registration source against the independent candidate manifest', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-registration-source-'))
  const sourceRoot = join(fixture, 'source')
  try {
    await cp(new URL('../node_modules/@castalia/filesystem/', import.meta.url), sourceRoot, { recursive: true })
    await writeFile(join(sourceRoot, 'packages/browser/src/registration.mjs'), 'export const stale = true;')
    await assert.rejects(() => writeFilesystemNotices(join(fixture, 'package'), { sourceRoot }), /Filesystem installed source mismatch/)
  } finally { await rm(fixture, { recursive: true, force: true }) }
})

test('inspection rejects retired adapters even with a fresh valid package digest', async () => {
 const fixture=await mkdtemp(join(tmpdir(),'castalia-retired-adapters-'))
 try {
  for(const [name,body] of [['legacy.js','wallet.prepareDevgraphWork()'],['devgraph-confirmation.html','obsolete UI'],['legacy.wasm','signDevgraphWork'],['bridge.js','chrome.runtime.connectNative("application.host")']]) {
   const root=join(fixture,name);await writeValidPackage(root)
   await writeFile(join(root,'dist',name),body)
   await writeExtensionPackageDigest(root,root+'.contents.sha256')
   await assert.rejects(()=>inspectProductionExtension(root,root+'.contents.sha256'),/application adapter/)
  }
 } finally {await rm(fixture,{recursive:true,force:true})}
})

test('inspection checks decoded embedded WASM instead of incidental base64 text', async () => {
 const fixture=await mkdtemp(join(tmpdir(),'castalia-wasm-adapter-scan-'))
 try {
  const root=join(fixture,'package');await writeValidPackage(root)
  // Valid empty module with a custom section whose binary encodes an accidental ArENA substring.
  const innocent=Buffer.from('0061736d010000000006000002b10d03','hex')
  assert.doesNotThrow(()=>new WebAssembly.Module(innocent));assert.match(innocent.toString('base64'),/arena/i)
  const js=bytes=>`const wasm=Uint8Array.from(atob("${bytes.toString('base64')}"),c=>c.charCodeAt(0));`
  await writeFile(join(root,'dist/service-worker.js'),js(innocent))
  await writeExtensionPackageDigest(root,root+'.contents.sha256')
  await inspectProductionExtension(root,root+'.contents.sha256')
  const name=Buffer.from('prepareDevgraphWork')
  const retired=Buffer.from([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,7,name.length+4,1,name.length,...name,0,0,10,4,1,2,0,11])
  assert.equal(WebAssembly.Module.exports(new WebAssembly.Module(retired))[0].name,'prepareDevgraphWork')
  await writeFile(join(root,'dist/service-worker.js'),js(retired))
  await writeExtensionPackageDigest(root,root+'.contents.sha256')
  await assert.rejects(()=>inspectProductionExtension(root,root+'.contents.sha256'),/application adapter/)
 } finally {await rm(fixture,{recursive:true,force:true})}
})

test('inspection rejects private compiler paths in JavaScript and embedded WASM even with a new digest', async () => {
 const fixture = await mkdtemp(join(tmpdir(), 'castalia-private-build-path-'))
 try {
  const path = '/Users/synthetic-builder/source'
  // Valid custom section: empty name followed by a synthetic source-path payload.
  const section = Buffer.concat([Buffer.from([0]), Buffer.from(path)])
  const wasm = Buffer.concat([Buffer.from('0061736d01000000', 'hex'), Buffer.from([0, section.length]), section])
  assert.doesNotThrow(() => new WebAssembly.Module(wasm))
  for (const [name, body] of [['plain', `const source = ${JSON.stringify(path)}`], ['embedded', `const module = atob('${wasm.toString('base64')}')`]]) {
   const root = join(fixture, name); await writeValidPackage(root)
   await writeFile(join(root, 'dist/service-worker.js'), body)
   await writeExtensionPackageDigest(root, root + '.contents.sha256')
   await assert.rejects(() => inspectProductionExtension(root, root + '.contents.sha256'), /private build path/)
  }
 } finally { await rm(fixture, { recursive: true, force: true }) }
})
