import {clickClosingApproval} from './approval-popup-smoke-helpers.mjs'
import assert from 'node:assert/strict'
import { chromium } from 'playwright-core'
import { mkdtemp, readFile, rm, cp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createPrivateKey, sign } from 'node:crypto'
import { createRegistrationManifest, registrationManifestDigest, verifySignedRegistration, ORGANIZATION_CLASS } from '@castalia/filesystem/registration'
import { deriveZenithMembershipId, zenithMembershipCredentialTranscript } from '@castalia-wallet/zenith-membership'

// Disposable profile, committed synthetic custody/issuer fixtures, intercepted HTTPS.
// This verifies extension registration acceptance, not remote namespace acceptance.
const extensionPath = await mkdtemp(join(tmpdir(), 'castalia-registration-extension-'))
const profile = await mkdtemp(join(tmpdir(), 'castalia-registration-profile-'))
await cp(process.env.CASTALIA_EXTENSION_DIRECTORY ?? join(process.cwd(), 'apps/chrome-extension'), extensionPath, { recursive: true, filter: source => !source.includes('/node_modules') && !source.includes('/generated') })
const context = await chromium.launchPersistentContext(profile, {
  headless: false, executablePath: process.env.CASTALIA_CHROMIUM_EXECUTABLE ?? chromium.executablePath(), ignoreDefaultArgs: ['--disable-extensions'],
  args: ['--disable-features=DisableLoadExtensionCommandLineSwitch', `--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
})
try {
  await context.route('https://registration.test/**', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html><button id="request">Request registration</button><script>document.getElementById("request").onclick=()=>{window.outcome=null;window.castaliaWallet.requestRegistrationV2(window.proposal).then(result=>window.outcome={ok:true,result},error=>window.outcome={ok:false,error:error.message})}</script>' }))
  await context.route('https://departure.test/**', route => route.fulfill({ contentType: 'text/html', body: '<p>Departed</p>' }))
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker')
  const extensionId = new URL(worker.url()).host
  const fixture = JSON.parse(await readFile('docs/contracts/castalia-wallet-custody-v1.vector.json', 'utf8'))
  const owner = fixture.container.publicKey, origin = 'https://registration.test'
  const credential = { schema: 'castalia.zenith-membership-credential.v3', version: 3, membershipId: await deriveZenithMembershipId(owner), ownerPublicKey: owner, status: 'active', issuerId: 'zenith-research', issuerKeyId: 'zenith-membership-issuer-fixture-ed25519-1', signatureSuite: 'Ed25519' }
  const issuer = createPrivateKey({ key: Buffer.from(fixture.intermediates.privateKeyPkcs8Hex, 'hex'), format: 'der', type: 'pkcs8' })
  const signedCredential = { ...credential, issuerSignature: sign(null, zenithMembershipCredentialTranscript(credential), issuer).toString('base64url') }
  await worker.evaluate(async ({ fixture, signedCredential }) => {
    await (globalThis as any).chrome.storage.local.set({ 'castalia-encrypted-custody-v1': { encryptedRecord: JSON.stringify(fixture.container), publicKey: fixture.container.publicKey } })
  }, { fixture, signedCredential })
  const custody = await context.newPage(); await custody.goto(`chrome-extension://${extensionId}/src/sidepanel.html`)
  await custody.getByLabel('Passphrase').fill(fixture.inputs.passphraseUnicode); await custody.getByRole('button', { name: 'Unlock', exact: true }).click(); await custody.getByText('Wallet ready').waitFor()
  assert.equal((await custody.evaluate(origin => new Promise<any>(resolve => (window as any).chrome.runtime.sendMessage({ type: 'APPROVE_ORIGIN', origin }, resolve)), origin)).ok, true)
  const page = await context.newPage(); await page.goto(`${origin}/files`); await page.waitForFunction(() => typeof (window as any).castaliaWallet?.requestRegistrationV2 === 'function')
  const manifest = await createRegistrationManifest({ entityClass: ORGANIZATION_CLASS, creatorMemberKey: owner, genesisNonce: '01'.repeat(32), initialWorkspaceId: '02'.repeat(32), displayName: '<img src=x onerror=alert(1)>' })
  let number = 0
  async function request() {
    number++; const now = Date.now()
    const proposal = { manifest, consent: { requestId: `chrome-registration-${number}`, origin, audience: origin, nonce: number.toString(16).padStart(64, '0'), issuedAtMs: now, expiresAtMs: now + 60_000, manifestDigest: await registrationManifestDigest(manifest) } }
    await page.evaluate(proposal => { (window as any).proposal = proposal }, proposal)
    const popupPromise = context.waitForEvent('page', { predicate: candidate => candidate !== page && candidate !== custody })
    await page.locator('#request').click()
    const popup = await popupPromise; await popup.waitForURL(`chrome-extension://${extensionId}/src/registration-confirmation.html?*`)
    await popup.getByRole('button', { name: 'Sign proposal', exact: true }).waitFor()
    return popup
  }
  const approval = await request()
  assert.equal(await approval.locator('#name').innerText(), manifest.displayName)
  assert.equal(await approval.locator('#name img').count(), 0)
  assert.equal(await approval.locator('#origin').innerText(), origin)
  await clickClosingApproval(approval, 'Sign proposal', page)
  await page.waitForFunction(() => (window as any).outcome !== null)
  const result = await page.evaluate(() => (window as any).outcome)
  assert.equal(result.ok, true, result.error); assert.equal((await verifySignedRegistration(result.result)).signerMemberKey, owner)
  await page.locator('#request').click(); await page.waitForFunction(() => (window as any).outcome !== null)
  assert.match((await page.evaluate(() => (window as any).outcome)).error, /replay/)
  const denial = await request()
  await clickClosingApproval(denial, 'Don’t sign', page)
  await page.waitForFunction(() => (window as any).outcome !== null)
  assert.match((await page.evaluate(() => (window as any).outcome)).error, /denied/)
  const pending = await request(); const closed = pending.waitForEvent('close'); await page.goto('https://departure.test/'); await closed
  assert.equal(pending.isClosed(), true)
  console.log(JSON.stringify({ schema: 'castalia.registration-chrome-smoke.v1', browser: context.browser()?.version(), cases: ['actual WASM custody with receiver-owned eligibility and zero trusted profiles', 'provider user action and Chrome-owned disclosure', 'text-only hostile display name', 'verified shared-contract signature', 'consumed consent replay', 'explicit denial', 'navigation cancels pending proposal'], remoteAcceptance: 'not exercised', realWallets: 'untouched' }))
} finally { await context.close(); await rm(profile, { recursive: true, force: true }); await rm(extensionPath, { recursive: true, force: true }) }
