import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const popupSource = new URL('../src/popup.ts', import.meta.url)
const panelHtml = new URL('../src/sidepanel.html', import.meta.url)
const panelCss = new URL('../src/popup.css', import.meta.url)
const manifestFile = new URL('../manifest.json', import.meta.url)
const onboardingHtml = new URL('../src/onboarding.html', import.meta.url)
const onboardingSource = new URL('../src/onboarding.ts', import.meta.url)
const serviceWorkerSource = new URL('../src/service-worker.ts', import.meta.url)
const contentScriptSource = new URL('../src/content-script.ts', import.meta.url)
const importFileSource = new URL('../src/import-file.ts', import.meta.url)

test('wallet panel keeps developer language and raw identity out of the primary surface', async () => {
  const source = await readFile(popupSource, 'utf8')
  for (const forbidden of [
    'Checkpoint A (Option B)',
    'Demo mode',
    '<strong>Public Key:</strong>',
    '<strong>Subject:</strong>',
    'Generate fresh key',
    'Refresh State',
    'class="brand-lockup"',
  ]) {
    assert.equal(source.includes(forbidden), false, `primary panel still contains: ${forbidden}`)
  }
  assert.match(source, /Create wallet/)
  assert.match(source, /Connect this site/)
  assert.match(source, /<details class="advanced"/)
  assert.doesNotMatch(source, /Temporary wallet|clear when the extension reloads/)
  assert.doesNotMatch(source, /Session wallet/)
})

test('wallet panel exposes the complete extension-owned custody ceremony', async () => {
  const source = await readFile(popupSource, 'utf8')
  for (const required of [
    'Create wallet',
    'Unlock',
    'Lock wallet',
    'Export recovery file',
    'Import recovery file',
    'Import encrypted recovery file',
    'Passphrase for this encrypted recovery file',
    '.castalia-recovery',
    "pendingImport ? 'open' : ''",
    'replacement-confirm',
    'another copy of signing authority',
    'not membership or admission',
  ]) {
    assert.ok(source.includes(required), `missing custody ceremony: ${required}`)
  }
  assert.equal(source.includes('.castaway'), false, '.castaway must remain available for its future format')
  assert.doesNotMatch(source, /privateKey|derivedKey|passphrase.*postMessage/i)
})

test('wallet panel labels every displayed chain account as Preview', async () => {
  const source = await readFile(popupSource, 'utf8')
  for (const label of [
    'Cardano · Preview',
    'Ethereum · Preview',
    'Robinhood Chain · Preview',
    'Solana · Preview',
  ]) {
    assert.ok(source.includes(label), `missing explicit preview label: ${label}`)
  }
})

test('wallet panel reveals only the complete public Member Key after setup', async () => {
  const source = await readFile(popupSource, 'utf8')
  for (const required of [
    'publicMemberKeyForDisplay(state)',
    'id="public-member-key"',
    'readonly',
    'Copy public Member Key',
    "document.execCommand('copy')",
    'navigator.clipboard?.writeText',
  ]) {
    assert.ok(source.includes(required), `missing public Member Key surface: ${required}`)
  }
  assert.doesNotMatch(source, /CUSTODY_(?:EXPORT|UNLOCK|CREATE).*copy-public-member-key/is)
  const copyStart = source.indexOf("document.getElementById('copy-public-member-key')")
  const copyEnd = source.indexOf("document.getElementById('create-form')", copyStart)
  const copyHandler = source.slice(copyStart, copyEnd)
  assert.doesNotMatch(copyHandler, /send\(|passphrase|private|seed|recovery/i)
})

test('wallet panel rejects oversized imports before file contents or runtime messaging', async () => {
  const [popup, boundary] = await Promise.all([
    readFile(popupSource, 'utf8'),
    readFile(importFileSource, 'utf8'),
  ])
  assert.match(popup, /readWalletImportFile\(file\)/)
  assert.match(boundary, /file\.size > MAX_WALLET_IMPORT_BYTES/)
  assert.ok(boundary.indexOf('file.size > MAX_WALLET_IMPORT_BYTES') < boundary.indexOf('file.text()'))
})

test('identity replacement clears old authorizations before custody import', async () => {
  const source = await readFile(serviceWorkerSource, 'utf8')
  const clear = source.indexOf('await sessionState.clearIdentityAuthorizations()')
  const imported = source.indexOf('await recovery.importWallet', clear)
  assert.notEqual(clear, -1)
  assert.notEqual(imported, -1)
  assert.ok(clear < imported)
})

test('provider custody reads and signing enter the service-worker FIFO', async () => {
  const source = await readFile(serviceWorkerSource, 'utf8')
  const listener = source.indexOf("message.type !== 'CASTALIA_PROVIDER_REQUEST'")
  const queued = source.indexOf('custodyOperations.run(async () =>', listener)
  const stateRead = source.indexOf('getCurrentExtensionStateForProvider()', listener)
  const providerCall = source.indexOf('handleProviderRequest({', listener)
  assert.notEqual(listener, -1)
  assert.notEqual(queued, -1)
  assert.notEqual(stateRead, -1)
  assert.notEqual(providerCall, -1)
  assert.ok(queued < stateRead)
  assert.ok(queued < providerCall)
})

test('identity authorization mutations share the custody replacement FIFO', async () => {
  const source = await readFile(serviceWorkerSource, 'utf8')
  const cases = [
    ['APPROVE_ORIGIN', "case 'REVOKE_ORIGIN'"],
    ['REVOKE_ORIGIN', "case 'BIND_MEMBERSHIP'"],
    ['BIND_MEMBERSHIP', "case 'UNBIND_MEMBERSHIP'"],
    ['UNBIND_MEMBERSHIP', 'default:'],
  ]
  for (const [name, next] of cases) {
    const start = source.indexOf(`case '${name}'`)
    const end = source.indexOf(next, start + 1)
    const body = source.slice(start, end)
    assert.notEqual(start, -1, `missing ${name}`)
    assert.notEqual(end, -1, `missing boundary after ${name}`)
    assert.match(body, /custodyOperations\.run\(async \(\) =>/)
  }
})

test('wallet panel uses current Castalia cobalt on paper brand tokens', async () => {
  const [html, css] = await Promise.all([
    readFile(panelHtml, 'utf8'),
    readFile(panelCss, 'utf8'),
  ])
  assert.match(html, /popup\.css/)
  assert.match(css, /--castalia-cobalt:\s*#064dbd/)
  assert.match(css, /--castalia-paper:\s*#fffdf5/)
  assert.match(css, /Georgia/)
  assert.match(css, /\.primary-action/)
  assert.match(css, /\.advanced/)
})

test('Chrome-owned wallet header uses the approved compact Castalia mark', async () => {
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'))
  assert.equal(manifest.name, 'Castalia')
  assert.equal(manifest.short_name, 'Castalia')
  assert.deepEqual(manifest.icons, {
    16: 'icons/castalia-16.png',
    32: 'icons/castalia-32.png',
    48: 'icons/castalia-48.png',
    128: 'icons/castalia-128.png',
  })
  assert.deepEqual(manifest.action.default_icon, manifest.icons)
  assert.equal(
    manifest.content_security_policy.extension_pages,
    "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
  )
})

test('Chrome-owned Join creates or unlocks durable custody before opening membership issuance', async () => {
  const [html, source] = await Promise.all([
    readFile(onboardingHtml, 'utf8'),
    readFile(onboardingSource, 'utf8'),
  ])
  assert.match(html, /id="continue"[^>]*disabled/)
  assert.match(html, /id="passphrase"[^>]*type="password"/)
  assert.match(html, /id="embedding-origin"/)
  const create = source.indexOf("type: 'CUSTODY_CREATE'")
  const unlock = source.indexOf("type: 'CUSTODY_UNLOCK'")
  const begin = source.indexOf("type: 'BEGIN_MEMBERSHIP_FLOW'")
  assert.ok(create >= 0 && unlock >= 0 && begin >= 0)
  assert.ok(create < begin && unlock < begin)
  assert.match(source, /expectedOrigin:\s*embeddingOrigin/)
  assert.match(source, /requestId/)
  assert.match(source, /embeddingOriginElement\.textContent\s*=\s*embeddingOrigin/)
  assert.match(source, /window\.close\(\)/)
  assert.doesNotMatch(source, /window\.parent\.postMessage/)
  assert.doesNotMatch(source, /createDevWalletKeyPair|sessionState\.setup/)
})

test('page bridge opens membership in Chrome UI rather than page-owned DOM', async () => {
  const source = await readFile(contentScriptSource, 'utf8')
  assert.match(source, /castalia-provider-profiles-v1/)
  assert.match(source, /navigator\.userActivation\?\.isActive/)
  assert.doesNotMatch(source, /createElement\(['"]iframe['"]\)|mountMembershipFlow/)
})

test('legacy background enrollment cannot fall back to a compiled issuer or session identity', async () => {
  const source = await readFile(serviceWorkerSource, 'utf8')
  const start = source.indexOf("case 'BEGIN_MEMBERSHIP_FLOW'")
  const end = source.indexOf("case 'SETUP'", start)
  assert.match(source.slice(start,end),/throw new Error/)
  assert.doesNotMatch(source,/compiledZenithMembershipConfig|__CASTALIA_ZENITH_MEMBERSHIP_/)
})
