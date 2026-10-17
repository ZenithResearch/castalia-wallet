import test from 'node:test'
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
const source = path => readFile(new URL('../'+path,import.meta.url),'utf8')
test('production package has no mandatory issuer or compiled credential trust',async()=>{
 const manifest=JSON.parse(await source('apps/chrome-extension/manifest.json'))
 assert.deepEqual(manifest.host_permissions,[])
 assert.deepEqual(manifest.optional_host_permissions,['https://*/*'])
 for(const file of ['scripts/bundle-castalia-extension.mjs','apps/chrome-extension/src/service-worker.ts']) {
  const text=await source(file)
  assert.doesNotMatch(text,/__CASTALIA_ZENITH_ISSUER_|__CASTALIA_PRESENTATION_TRUST_|extension-build-config|presentation-build-config/,file)
 }
 assert.match(await source('apps/chrome-extension/src/service-worker.ts'),/installProviderProfilesRuntime/)
 assert.match(await source('scripts/package-production-extension.mjs'),/provider-configuration\.json/)
})
