import {clickClosingApproval} from './approval-popup-smoke-helpers.mjs'
import assert from 'node:assert/strict'
import { chromium, type BrowserContext, type Page } from 'playwright-core'
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createPublicKey, verify } from 'node:crypto'
import { buildFilesConsent, filesBase64url, type FilesKeyBindingV1, type FilesKeyEnvelopeV1, type FilesOperationV1 } from '@castalia-wallet/provider-types'

// Synthetic key and two disposable profiles; HTTPS is intercepted locally.
// The retained encrypted envelope models remote key storage, not a live Sia test.
const extensionPath = await mkdtemp(join(tmpdir(), 'castalia-files-extension-'))
const profiles: string[] = []
let context: BrowserContext | undefined
const passphrase = 'disposable files browser recovery test'
const dataKey = filesBase64url(new Uint8Array(32).fill(9))
const pages = '<!doctype html><button id="request">Request Files operation</button><script>document.getElementById("request").onclick=()=>{window.outcome=null;window.castaliaWallet[window.method](window.request).then(result=>window.outcome={ok:true,result},error=>window.outcome={ok:false,error:error.message})}</script>'
await cp(process.env.CASTALIA_EXTENSION_DIRECTORY ?? join(process.cwd(), 'apps/chrome-extension'), extensionPath, { recursive: true, filter: source => !source.includes('/node_modules') && !source.includes('/generated') })
async function openProfile() {
  const profile = await mkdtemp(join(tmpdir(), 'castalia-files-profile-')); profiles.push(profile)
  context = await chromium.launchPersistentContext(profile, {
    headless: false, executablePath: process.env.CASTALIA_CHROMIUM_EXECUTABLE ?? chromium.executablePath(), ignoreDefaultArgs: ['--disable-extensions'],
    args: ['--disable-features=DisableLoadExtensionCommandLineSwitch', `--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
  })
  await context.route('https://files-a.test/**', route => route.fulfill({ contentType: 'text/html', body: pages }))
  await context.route('https://files-b.test/**', route => route.fulfill({ contentType: 'text/html', body: pages }))
  await context.route('https://departure.test/**', route => route.fulfill({ contentType: 'text/html', body: '<p>Departed</p>' }))
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker', { timeout: 10_000 })
  const extensionId = new URL(worker.url()).host
  const custody = await context.newPage(); await custody.goto(`chrome-extension://${extensionId}/src/sidepanel.html`)
  await custody.getByLabel('Passphrase').waitFor()
  return { context, extensionId, custody }
}
async function openRecovery(custody: Page) {
  const details = custody.locator('details.advanced')
  if (!(await details.evaluate(element => (element as HTMLDetailsElement).open))) await details.locator('summary').click()
}
async function connect(context: BrowserContext, custody: Page, origin: string) {
  assert.equal((await custody.evaluate(origin => new Promise<any>(resolve => (window as any).chrome.runtime.sendMessage({ type: 'APPROVE_ORIGIN', origin }, resolve)), origin)).ok, true)
  const page = await context.newPage(); await page.goto(`${origin}/files`)
  await page.waitForFunction(() => (window as any).castaliaWallet?.filesKeyProtocol === 'castalia.files-key-wrap.v1')
  return page
}
async function request(context: BrowserContext, page: Page, extensionId: string, operation: FilesOperationV1, body: unknown) {
  const method = { wrap: 'wrapFilesKey', unwrap: 'unwrapFilesKey', authenticate: 'requestFilesServiceAuthentication' }[operation]
  const consent = await buildFilesConsent(operation, body, new URL(page.url()).origin)
  await page.evaluate(({ method, request }) => { (window as any).method = method; (window as any).request = request }, { method, request: { ...(body as object), consent } })
  const popupPromise = context.waitForEvent('page')
  await page.locator('#request').click()
  const popup = await popupPromise; await popup.waitForURL(`chrome-extension://${extensionId}/src/files-key-confirmation.html?*`)
  await popup.getByRole('button', { name: 'Approve request', exact: true }).waitFor()
  await popup.waitForFunction(() => !(document.getElementById('approve') as HTMLButtonElement).disabled)
  assert.equal(await popup.locator('#origin').innerText(), consent.origin)
  assert.equal(await popup.locator('#digest').innerText(), consent.requestDigest)
  assert.equal((await popup.locator('body').innerText()).includes(dataKey), false)
  return popup
}
async function outcome(page: Page) {
  await page.waitForFunction(() => (window as any).outcome !== null)
  return page.evaluate(() => (window as any).outcome)
}
try {
  const first = await openProfile()
  await first.custody.getByLabel('Passphrase').fill(passphrase)
  await first.custody.getByRole('button', { name: 'Create wallet', exact: true }).click()
  await first.custody.getByText('Wallet ready').waitFor()
  const owner = await first.custody.locator('#public-member-key').inputValue()
  assert.match(owner, /^[0-9a-f]{64}$/)
  const binding: FilesKeyBindingV1 = { schema: 'castalia.files-key-binding.v1', ownerMemberKey: owner, serviceId: '11'.repeat(32), storageAccountId: 'disposable-browser-fixture', namespaceId: '22'.repeat(32), workspaceId: '33'.repeat(32), submissionId: '44'.repeat(32), revisionId: '55'.repeat(32) }
  const page = await connect(first.context, first.custody, 'https://files-a.test')
  const approval = await request(first.context, page, first.extensionId, 'wrap', { binding, key: dataKey })
  assert.equal(await approval.locator('#revision').innerText(), binding.revisionId)
  assert.equal(await approval.locator('#member').innerText(), owner)
  await clickClosingApproval(approval, 'Approve request', page)
  const wrapped = await outcome(page); assert.equal(wrapped.ok, true, wrapped.error)
  const envelope: FilesKeyEnvelopeV1 = wrapped.result
  assert.equal(envelope.schema, 'castalia.files-key-envelope.v1')
  assert.equal(JSON.stringify(envelope).includes(dataKey), false)
  await page.locator('#request').click(); assert.match((await outcome(page)).error, /replay/)
  const denial = await request(first.context, page, first.extensionId, 'unwrap', { binding, envelope })
  await clickClosingApproval(denial, 'Don’t approve', page)
  assert.match((await outcome(page)).error, /denied/)
  const pending = await request(first.context, page, first.extensionId, 'unwrap', { binding, envelope })
  const closed = pending.waitForEvent('close'); await page.goto('https://departure.test/'); await closed
  assert.equal(pending.isClosed(), true)
  await openRecovery(first.custody)
  first.custody.once('dialog', dialog => dialog.accept(passphrase))
  const downloadPromise = first.custody.waitForEvent('download')
  await first.custody.getByRole('button', { name: 'Export recovery file', exact: true }).click()
  const download = await downloadPromise
  assert.match(download.suggestedFilename(), /^Castalia-Recovery-\d+\.castalia-recovery$/)
  const recoveryPath = await download.path(); assert.ok(recoveryPath)
  const recovery = await readFile(recoveryPath)
  await first.context.close(); context = undefined

  const second = await openProfile()
  await second.custody.getByRole('button', { name: 'Create wallet', exact: true }).waitFor()
  await openRecovery(second.custody)
  await second.custody.locator('#import').setInputFiles({ name: download.suggestedFilename(), mimeType: 'application/json', buffer: recovery })
  second.custody.once('dialog', dialog => dialog.accept(passphrase))
  await second.custody.getByRole('button', { name: 'Import encrypted recovery file', exact: true }).click()
  await second.custody.getByText('Wallet locked').waitFor()
  await second.custody.getByLabel('Passphrase').fill(passphrase)
  await second.custody.getByRole('button', { name: 'Unlock', exact: true }).click()
  await second.custody.getByText('Wallet ready').waitFor()
  assert.equal(await second.custody.locator('#public-member-key').inputValue(), owner)
  const recoveredPage = await connect(second.context, second.custody, 'https://files-b.test')
  const unwrap = await request(second.context, recoveredPage, second.extensionId, 'unwrap', { binding, envelope })
  await clickClosingApproval(unwrap, 'Approve request', recoveredPage)
  const unwrapped = await outcome(recoveredPage); assert.equal(unwrapped.ok, true, unwrapped.error); assert.equal(unwrapped.result.key, dataKey)
  const now = Date.now(), challenge = { audience: `castalia-files://index/${binding.serviceId}`, domain: 'castalia-wallet' as const, expiresAt: new Date(now + 60_000).toISOString(), issuedAt: new Date(now).toISOString(), nonce: 'disposable-browser-auth-nonce', operation: 'castalia.wallet.signChallenge' as const, origin: 'https://files-b.test', version: 1 as const }
  const authentication = await request(second.context, recoveredPage, second.extensionId, 'authenticate', { serviceKind: 'index', serviceId: binding.serviceId, challenge })
  await clickClosingApproval(authentication, 'Approve request', recoveredPage)
  const signed = await outcome(recoveredPage); assert.equal(signed.ok, true, signed.error)
  assert.equal(signed.result.subject.dreggOwnerPublicKey, owner)
  assert.equal(signed.result.signatureAlgorithm, 'ed25519')
  assert.ok(verify(null, Buffer.from(JSON.stringify(challenge)), createPublicKey(signed.result.subject.publicKey), Buffer.from(signed.result.signature, 'base64')))
  await openRecovery(second.custody); await second.custody.getByRole('button', { name: 'Lock wallet', exact: true }).click()
  await second.custody.getByText('Wallet locked').waitFor()
  assert.equal(await recoveredPage.evaluate(async () => { try { await (window as any).castaliaWallet.getSubject(); return false } catch { return true } }), true)
  console.log(JSON.stringify({ schema: 'castalia.files-custody-chrome-smoke.v1', browser: second.context.browser()?.version(), cases: ['fresh UI-created identity', 'Chrome-owned wrap consent and scoped disclosure', 'consumed consent replay', 'explicit denial', 'navigation cancels approval', 'unchanged encrypted recovery export', 'second fresh-profile recovery import', 'same Member Key cross-origin envelope unwrap', 'scoped service authentication with verified Ed25519 signature', 'locked provider rejects subject'], liveSia: 'not exercised', realWallets: 'untouched' }))
} finally {
  await context?.close()
  for (const profile of profiles) await rm(profile, { recursive: true, force: true })
  await rm(extensionPath, { recursive: true, force: true })
}
