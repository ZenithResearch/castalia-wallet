/** Exact public package, disposable Chrome custody and synthetic service only. */
import assert from 'node:assert/strict'
import { chromium, type Page } from 'playwright-core'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto'
import { verifyExtensionPackageDigest } from './extension-package-digest.mjs'
import { clickClosingApproval } from './approval-popup-smoke-helpers.mjs'

assert.ok(process.env.CASTALIA_EXTENSION_DIRECTORY, 'Pass the exact public extension package')
assert.ok(process.env.DEVGRAPH_SOURCE_DIRECTORY, 'Pass the DevGraph source checkout under qualification')
const root = resolve(process.env.CASTALIA_EXTENSION_DIRECTORY!)
const devgraph = resolve(process.env.DEVGRAPH_SOURCE_DIRECTORY!)
const before = await verifyExtensionPackageDigest(root, `${root}.contents.sha256`)
const directory = await mkdtemp(join(tmpdir(), 'castalia-public-graph-'))
const origin = 'https://graph.example.test'
const issuer = createPrivateKey({ key: Buffer.from('302e020100300506032b657004220420' + '09'.repeat(32), 'hex'), format: 'der', type: 'pkcs8' })
const issuerPublic = createPublicKey(issuer).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
const canonical = (value: any): string => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`
const hash = (v: unknown) => createHash('sha256').update(canonical(v)).digest('hex')
const body = `<!doctype html><button id="select">Select Wallet</button><button id="advance">Continue</button><button id="request">Send request</button><button id="read">Read</button><script type="module">
import {WalletReadClient} from '/assets/credential-v2/read-access.mjs';
window.client=new WalletReadClient();await client.initialize();window.ready=true;
function run(f){window.result=null;Promise.resolve().then(f).then(v=>window.result={ok:true,value:v},e=>window.result={ok:false,error:e.code??e.message});}
document.querySelector('#select').onclick=()=>run(()=>client.useProvider(window.castaliaWallet));
// Start consent synchronously in the actual click, as the SDK requires.
document.querySelector('#advance').onclick=()=>{window.result=null;client.advance().then(()=>window.result={ok:true},e=>window.result={ok:false,error:e.code??e.message})};
document.querySelector('#request').onclick=()=>{window.result=null;client.approveAccess(window.challenge).then(v=>window.result={ok:true,value:v},e=>window.result={ok:false,error:e.code??e.message})};
document.querySelector('#read').onclick=()=>run(()=>client.read('/todos/v2?limit=1'));
</script>`
let grant = false, enrollments = 0, reads = 0, owner = '', installation = ''
const proposals = new Map<string, any>()
const verifyHolder = (challenge: any, signature: string, domain: string, encoding: 'hex' | 'base64url') => {
 const key = createPublicKey({ key: Buffer.from('302a300506032b6570032100' + owner, 'hex'), format: 'der', type: 'spki' })
 assert.ok(verify(null, Buffer.concat([Buffer.from(domain), Buffer.from(canonical(challenge))]), key, Buffer.from(signature, encoding)))
}
const profile = { schema: 'castalia.provider-profile.v1', display_name: 'Synthetic graph authority', origins: [origin], membership: null, presentations: [{ issuer: 'synthetic-provider', key_id: 'read-key', public_key: issuerPublic, audience: 'synthetic-service', callers: [{ kind: 'browser', id: origin }] }] }
const context = await chromium.launchPersistentContext(join(directory, 'profile'), { headless: process.env.CASTALIA_HEADLESS === '1', executablePath: process.env.CASTALIA_CHROMIUM_EXECUTABLE ?? chromium.executablePath(), ignoreDefaultArgs: ['--disable-extensions'], args: ['--disable-features=DisableLoadExtensionCommandLineSwitch', `--disable-extensions-except=${root}`, `--load-extension=${root}`] })
await context.route(origin + '/**', async route => {
 try {
  const req = route.request(), path = new URL(req.url()).pathname
  const send = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) })
  if (path === '/') return route.fulfill({ contentType: 'text/html', body })
  if (path.startsWith('/assets/credential-v2/')) {
   const file = path.slice('/assets/credential-v2/'.length)
   assert.match(file, /^[a-z-]+\.mjs$/)
   return route.fulfill({ contentType: 'text/javascript', body: await readFile(join(devgraph, 'src/devgraph/frontend/static/credential-v2', file)) })
  }
  if (path === '/monitor/wallet-access/v1') return send({ schema: 'devgraph.wallet-read-configuration.v1', endpoint: path, access_requests_endpoint: '/devgraph/access-requests/v2', provider_profile: profile })
  if (path.endsWith('/challenges')) {
   const identity = req.postDataJSON(); owner = identity.subject_public_key; installation = identity.installation_id
   if (!grant) return send({ error: 'access_denied' }, 401)
   const now = Math.floor(Date.now() / 1000)
   const policy = { schema: 'castalia.read-policy.v1', issuer: 'synthetic-provider', key_id: 'read-key', public_key: issuerPublic, receiver: origin, audience: 'synthetic-service', max_lifetime_seconds: 600, permissions: [{ operation: 'devgraph.work.list', resource: 'https://work.zenith-research.ca/devgraph', constraints: { ids: ['Task/included'] } }] }
   const challenge = { schema: 'castalia.read-access-challenge.v1', request_id: randomBytes(16).toString('hex'), nonce: randomBytes(32).toString('base64url'), subject_public_key: owner, installation_id: installation, issuer: policy.issuer, receiver: origin, issued_at: now, expires_at: now + 120, credential_expires_at: now + 600, details: { authority_policy: policy } }
   proposals.set(challenge.request_id, challenge); return send(challenge)
  }
  if (path.endsWith('/enrollments')) {
   const enrollment = req.postDataJSON(), c = enrollment.challenge
   assert.deepEqual(proposals.get(c.request_id), c); assert.deepEqual(enrollment.proof, {})
   verifyHolder(c, enrollment.signature, 'castalia/read-access-approval/v1\0', 'base64url')
   const policy = c.details.authority_policy
   const claims = { schema: 'castalia.read-credential.v1', credential_id: randomBytes(16).toString('hex'), holder_public_key: owner, installation_id: installation, issuer: policy.issuer, key_id: policy.key_id, receiver: origin, audience: policy.audience, policy_digest: hash(policy), permissions: policy.permissions, issued_at: Math.floor(Date.now() / 1000), expires_at: c.credential_expires_at }
   const credential = { claims, signature: sign(null, Buffer.concat([Buffer.from('castalia.read-credential.v1/signature\0'), Buffer.from(canonical(claims))]), issuer).toString('hex') }
   enrollments++; return send({ schema: 'devgraph.native-read-result.v3', credential })
  }
  if (path.endsWith('/requests')) {
   const result = req.postDataJSON(), proof = { ...result.proof }; delete proof.signature
   assert.equal(result.call.operation, 'devgraph.work.list')
   assert.equal(result.proof.credential_digest, hash(result.credential)); assert.equal(result.proof.call_digest, hash(result.call))
   verifyHolder(proof, result.proof.signature, 'castalia.read-presentation.v1/signature\0', 'hex')
   reads++; return send({ items: [{ kind: 'Task', id: 'included' }], total: 1 })
  }
  return send({}, 404)
 } catch (e) { console.error(e); await route.fulfill({ status: 500, body: 'fixture failed' }) }
})
async function result(page: Page) { await page.waitForFunction(() => (window as any).result !== null); return page.evaluate(() => (window as any).result) }
try {
 const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker'), id = new URL(worker.url()).host
 const custody = await context.newPage(); await custody.goto(`chrome-extension://${id}/src/sidepanel.html`)
 await custody.getByLabel('Passphrase').fill('disposable graph test password')
 await custody.getByRole('button', { name: 'Create wallet', exact: true }).click(); await custody.getByText('Wallet ready', { exact: true }).waitFor()
 const page = await context.newPage(); await page.goto(origin); await page.waitForFunction(() => (window as any).ready && (window as any).castaliaWallet?.readAccess)
 await page.locator('#select').click(); assert.equal((await result(page)).ok, true)
 async function advance(dialog: 'profile' | 'connection' | 'read') {
  const opened = context.waitForEvent('page'); await page.locator('#advance').click(); const popup = await opened
  if (dialog === 'profile') { await popup.getByLabel('Trust these authorities for the specified request credentials').check(); await clickClosingApproval(popup, 'Approve selected purposes', page) }
  else await clickClosingApproval(popup, dialog === 'connection' ? 'Connect' : 'Allow read access', page)
  return result(page)
 }
 assert.equal((await advance('profile')).ok, true)
 const denied = await advance('connection'); assert.equal(denied.ok, false); assert.equal(denied.error, 'wallet_read_denied')
 assert.equal(enrollments, 0)
 const now = Math.floor(Date.now() / 1000)
 const challenge = { schema: 'castalia.access-request-challenge.v1', challenge_id: 'c'.repeat(32), nonce: randomBytes(32).toString('base64url'), issuer: 'synthetic-provider', receiver: origin, subject_public_key: owner, installation_id: installation, operation: 'access.request', issued_at: now, expires_at: now + 120, details: { schema: 'devgraph.access-request-action.v2', action: 'submit', request_id: 'd'.repeat(32), subject_public_key: owner, installation_id: installation, intent: null } }
 await page.evaluate(c => { (window as any).challenge = c }, challenge)
 const requested = context.waitForEvent('page'); await page.locator('#request').click(); const requestPopup = await requested
 await requestPopup.getByText('Send access request?', { exact: true }).waitFor(); await clickClosingApproval(requestPopup, 'Send request', page)
 const requestResult = await result(page); assert.equal(requestResult.ok, true, requestResult.error); assert.deepEqual(requestResult.value.proof, {})
 verifyHolder(challenge, requestResult.value.signature, 'castalia/access-request-approval/v1\0', 'base64url'); assert.equal(enrollments, 0)
 grant = true
 await page.locator('#advance').click(); assert.equal((await result(page)).ok, true)
 assert.equal((await advance('read')).ok, true)
 assert.equal(await page.evaluate(() => (window as any).client.stage), 'ready')
 await page.locator('#read').click(); const read = await result(page); assert.equal(read.ok, true, read.error); assert.equal(read.value.total, 1)
 assert.equal(enrollments, 1); assert.equal(reads, 1)
 await custody.getByText('Recovery', { exact: true }).click(); await custody.getByRole('button', { name: 'Lock wallet', exact: true }).click(); await custody.getByText('Wallet locked', { exact: true }).waitFor()
 await page.locator('#read').click(); assert.equal((await result(page)).ok, false)
 assert.equal((await verifyExtensionPackageDigest(root, `${root}.contents.sha256`)).digest, before.digest)
 console.log(JSON.stringify({ qualification: 'Loaded public Chrome package + actual DevGraph client + synthetic issuer/receiver', package_digest: before.digest, request_consent: true, membership_optional: true, no_grant_no_read: true, issuer_signature_checked: true, scoped_read: true, lock_denies: true, enrollments, reads }))
} finally { await context.close(); await rm(directory, { recursive: true, force: true }) }
