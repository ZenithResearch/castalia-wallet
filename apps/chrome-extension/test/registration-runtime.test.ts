import assert from 'node:assert/strict'
import test from 'node:test'
import { generateKeyPairSync, sign } from 'node:crypto'
import { createRegistrationManifest, registrationManifestDigest, ORGANIZATION_CLASS } from '@castalia/filesystem/registration'
import { installRegistrationRuntime } from '../src/registration-runtime.ts'
import { forwardRegistration } from '../src/registration-content.ts'
import { createCastaliaWalletProvider } from '../src/provider.ts'

function event() {
  const listeners = new Set<(...args: any[]) => any>()
  return { addListener: (f: (...args: any[]) => any) => listeners.add(f), removeListener: (f: (...args: any[]) => any) => listeners.delete(f), emit: (...args: any[]) => { for (const f of [...listeners]) f(...args) } }
}
async function fixture() {
  const keys = generateKeyPairSync('ed25519'), origin = 'https://castalia.example'
  const key = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
  const manifest = await createRegistrationManifest({ entityClass: ORGANIZATION_CLASS, creatorMemberKey: key, genesisNonce: '01'.repeat(32), initialWorkspaceId: '02'.repeat(32), displayName: '<img src=x onerror=alert(1)>' })
  const now = Date.now()
  const request = { manifest, consent: { requestId: 'runtime-request-1', origin, audience: origin, nonce: '03'.repeat(32), issuedAtMs: now, expiresAtMs: now + 60_000, manifestDigest: await registrationManifestDigest(manifest) } }
  const storage: any = {}, changes = event(), windows: string[] = []
  let signs = 0
  const chrome: any = {
    runtime: { id: 'wallet-test', getURL: (p: string) => `chrome-extension://wallet-test/${p}`, onConnect: event(), onMessage: event() },
    storage: { session: { get: async () => storage, set: async (value: any) => Object.assign(storage, value) } },
    tabs: { get: async () => ({ url: `${origin}/files` }), onUpdated: event(), onRemoved: event() },
    windows: { create: async ({ url }: any) => { windows.push(url); return { id: 77 } }, remove: async () => {}, onRemoved: event() },
  }
  installRegistrationRuntime(chrome, { run: async fn => fn(), state: async () => ({ memberKey: key, approvedOrigins: new Set([origin]), signBytes: async bytes => { signs++; return sign(null, bytes, keys.privateKey).toString('base64') } }), epoch: () => 1, onChange: listener => { changes.addListener(listener); return () => changes.removeListener(listener) }, verifyMembership: async () => {} })
  const replies: any[] = []
  let disconnected = false
  const port: any = { name: 'castalia-registration-v1', sender: { id: chrome.runtime.id, frameId: 0, url: `${origin}/files`, tab: { id: 1, url: `${origin}/files` } }, onMessage: event(), onDisconnect: event(), postMessage: (v: any) => replies.push(v), disconnect: () => { if (!disconnected) { disconnected = true; port.onDisconnect.emit() } } }
  const connect = () => { chrome.runtime.onConnect.emit(port); port.onMessage.emit(request) }
  const wait = async () => { for (let i = 0; i < 50 && windows.length === 0 && replies.length === 0; i++) await new Promise(resolve => setTimeout(resolve, 2)) }
  const confirmation = (type: string, url = windows[0], approved?: boolean) => { let response: any; chrome.runtime.onMessage.emit({ type, requestId: new URL(windows[0]).searchParams.get('request'), approved }, { id: chrome.runtime.id, url }, (v: any) => { response = v }); return response }
  return { chrome, port, request, replies, windows, changes, connect, wait, confirmation, signs: () => signs }
}

test('provider exposes the wallet-neutral requestRegistration method', async () => {
  const f = await fixture(); let seen: any
  const provider = createCastaliaWalletProvider(async request => { seen = request; return {} })
  await provider.requestRegistration(f.request)
  assert.equal(seen.method, 'castalia.wallet.requestRegistration'); assert.deepEqual(seen.payload, f.request)
})

test('runtime binds actual top-level sender and Chrome-owned claimed confirmation', async () => {
  const f = await fixture(); f.connect(); await f.wait()
  assert.equal(f.confirmation('GET_REGISTRATION_CONFIRMATION', 'https://castalia.example/').ok, false)
  assert.equal(f.confirmation('RESOLVE_REGISTRATION_CONFIRMATION', undefined, true).ok, false)
  const claimed = f.confirmation('GET_REGISTRATION_CONFIRMATION'); assert.equal(claimed.ok, true); assert.equal(claimed.summary.manifest.displayName, f.request.manifest.displayName)
  assert.equal(f.confirmation('GET_REGISTRATION_CONFIRMATION').ok, false)
  assert.equal(f.confirmation('RESOLVE_REGISTRATION_CONFIRMATION', undefined, true).ok, true)
  for (let i = 0; i < 50 && !f.replies.length; i++) await new Promise(r => setTimeout(r, 2))
  assert.equal(f.replies[0]?.ok, true); assert.equal(f.signs(), 1)
})

for (const reason of ['navigation', 'disconnect', 'custody']) test(`runtime cancels pending confirmation on ${reason}`, async () => {
  const f = await fixture(); f.connect(); await f.wait(); assert.equal(f.confirmation('GET_REGISTRATION_CONFIRMATION').ok, true)
  if (reason === 'navigation') f.chrome.tabs.onUpdated.emit(1, { url: 'https://elsewhere.example/' })
  if (reason === 'disconnect') f.port.disconnect()
  if (reason === 'custody') f.changes.emit()
  assert.equal(f.confirmation('RESOLVE_REGISTRATION_CONFIRMATION', undefined, true).ok, false)
  await new Promise(r => setTimeout(r, 5)); assert.equal(f.signs(), 0)
})

test('runtime rejects iframe and sender/tab origin mismatch', async () => {
  for (const change of [(p: any) => { p.sender.frameId = 1 }, (p: any) => { p.sender.url = 'https://evil.example/' }]) {
    const f = await fixture(); change(f.port); f.connect(); await f.wait()
    assert.equal(f.replies[0]?.ok, false); assert.equal(f.windows.length, 0); assert.equal(f.signs(), 0)
  }
})

test('content lifecycle forwards once and disconnects on pagehide', () => {
  const messages: any[] = [], replies: any[] = [], listeners = new Map<string, () => void>()
  let closed = 0
  const port = { onMessage: event(), onDisconnect: event(), postMessage: (v: any) => messages.push(v), disconnect: () => { closed++; port.onDisconnect.emit() } }
  const page: any = { addEventListener: (name: string, fn: () => void) => listeners.set(name, fn), removeEventListener: (name: string) => listeners.delete(name) }
  forwardRegistration(port, { test: 'request' }, v => replies.push(v), page)
  assert.deepEqual(messages, [{ test: 'request' }]); listeners.get('pagehide')!()
  port.onMessage.emit({ ok: true }); assert.equal(replies.length, 1); assert.equal(replies[0].ok, false); assert.equal(closed, 1); assert.equal(listeners.size, 0)
})
