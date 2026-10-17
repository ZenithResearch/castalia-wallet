import test from 'node:test'
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {presentationTrustPins} from './presentation-build-config.mjs'
test('generic signing surfaces have no application operations or adapters',async()=>{
 for(const file of ['crates/castalia-wallet-presentation/src/lib.rs','crates/castalia-wallet-core/src/credential_presentation.rs','apps/chrome-extension/src/credential-presentation.ts','apps/chrome-extension/src/credential-presentation-runtime.ts','packages/provider-types/src/credential-presentation.ts','apps/chrome-extension/src/credential-presentation-content.ts','apps/chrome-extension/src/credential-presentation-confirmation.ts','apps/chrome-extension/src/operation-confirmation-broker.ts','crates/castalia-wallet-cli/src/main.rs']){
  const source=await readFile(new URL('../'+file,import.meta.url),'utf8');assert.doesNotMatch(source,/devgraph|kanban|arena|org\.devgraph|monitor\//i,file)
 }
})
test('operator pins reject ambiguity and insecure origins',()=>{
 const pin={issuer:'issuer',key_id:'key',public_key:'11'.repeat(32),audience:'service',callers:[{kind:'browser',id:'https://site.test'}]}
 assert.equal(presentationTrustPins(JSON.stringify([pin])).length,1)
 assert.throws(()=>presentationTrustPins(JSON.stringify([pin,pin])))
 assert.throws(()=>presentationTrustPins(JSON.stringify([{...pin,callers:[{kind:'browser',id:'http://site.test'}]}])))
 assert.throws(()=>presentationTrustPins(JSON.stringify([{...pin,callers:[{kind:'browser',id:'https://site.test/path'}]}])))
 assert.deepEqual(presentationTrustPins(),[])
})

test('generic Rust crates cannot depend on application protocol or host crates', async () => {
 for (const file of ['crates/castalia-wallet-presentation/Cargo.toml', 'crates/castalia-wallet-cli/Cargo.toml', 'crates/castalia-wallet-private-files/Cargo.toml']) {
  const manifest = await readFile(new URL('../' + file, import.meta.url), 'utf8')
  assert.doesNotMatch(manifest, /devgraph|kanban|arena|native.host|secS|secs-/i, file)
 }
})

test('all Wallet production sources and dependency manifests exclude application adapters', async () => {
 const {readdir} = await import('node:fs/promises')
 async function check(directory) {
  for (const entry of await readdir(new URL('../'+directory,import.meta.url), {withFileTypes:true})) {
   if (entry.name === 'generated') continue
   const file=directory+'/'+entry.name
   if (entry.isDirectory()) await check(file)
   else if (/\.(ts|rs|html|json|toml)$/.test(file)) {
    const source=await readFile(new URL('../'+file,import.meta.url),'utf8')
    assert.doesNotMatch(source,/devgraph|kanban|arena|connectNative|nativeMessaging/i,file)
   }
  }
 }
 for(const directory of ['apps/chrome-extension/src', 'packages/provider-types/src', 'packages/core/src', 'crates/castalia-wallet-core/src']) await check(directory)
 for(const file of ['Cargo.toml','Cargo.lock','crates/castalia-wallet-core/Cargo.toml','package.json','packages/core/package.json','apps/chrome-extension/manifest.json']) {
  assert.doesNotMatch(await readFile(new URL('../'+file,import.meta.url),'utf8'),/devgraph|kanban|arena|nativeMessaging/i,file)
 }
})

test('retired historical vectors retain their source hashes outside executable packages', async () => {
 const {createHash}=await import('node:crypto')
 const manifest=JSON.parse(await readFile(new URL('../docs/vectors/retired-application-signing/provenance.json',import.meta.url),'utf8'))
 assert.equal(manifest.sourceRevision,'58d32a40559ffff0a9d99411f967b0889524c994')
 assert.equal(manifest.files.length,4)
 for(const file of manifest.files) {
  assert.ok(file.preservedPath.startsWith('docs/vectors/retired-application-signing/'))
  assert.equal(createHash('sha256').update(await readFile(new URL('../'+file.preservedPath,import.meta.url))).digest('hex'),file.sha256,file.sourcePath)
 }
})
