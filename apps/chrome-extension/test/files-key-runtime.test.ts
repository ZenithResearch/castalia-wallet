import assert from 'node:assert/strict'
import test from 'node:test'
import { buildFilesConsent, filesBase64url } from '../src/files-key-contract.js'
import { installFilesKeyRuntime } from '../src/files-key-runtime.ts'
import { forwardFilesKey } from '../src/files-key-content.ts'
import { createCastaliaWalletProvider } from '../src/provider.ts'

function event() {
  const listeners = new Set<(...args: any[]) => any>()
  return { addListener: (f: (...args: any[]) => any) => listeners.add(f), removeListener: (f: (...args: any[]) => any) => listeners.delete(f), emit: (...args: any[]) => { for (const f of [...listeners]) f(...args) } }
}
async function fixture() {
  const origin = 'https://castalia.example', key = 'ab'.repeat(32)
  const binding = { schema: 'castalia.files-key-binding.v1' as const, ownerMemberKey: key, serviceId: '11'.repeat(32), storageAccountId: 'owned-account', namespaceId: '22'.repeat(32), workspaceId: '33'.repeat(32), submissionId: '44'.repeat(32), revisionId: '55'.repeat(32) }
  const body = { binding, key: filesBase64url(new Uint8Array(32)) }
  const request = { ...body, consent: await buildFilesConsent('wrap', body, origin) }
  const envelope = { schema: 'castalia.files-key-envelope.v1', binding, nonce: filesBase64url(new Uint8Array(12)), ciphertext: filesBase64url(new Uint8Array(48)) }
  const storage: any = {}, changes = event(), windows: string[] = []
  let signs = 0
  const chrome: any = {
    runtime: { id: 'wallet-test', getURL: (p: string) => `chrome-extension://wallet-test/${p}`, onConnect: event(), onMessage: event() },
    storage: { session: { get: async () => storage, set: async (value: any) => Object.assign(storage, value) } },
    tabs: { get: async () => ({ url: `${origin}/files` }), onUpdated: event(), onRemoved: event() },
    windows: { create: async ({ url }: any) => { windows.push(url); return { id: 77 } }, remove: async () => {}, onRemoved: event() },
  }
  const installed = installFilesKeyRuntime(chrome, { run: async fn => fn(), state: async () => ({ memberKey: key, approvedOrigins: new Set([origin]), wrap: async () => { signs++; return envelope }, unwrap: async () => new Uint8Array(32), authenticate: async () => { throw Error('unused') } }), epoch: () => 1, onChange: listener => { changes.addListener(listener); return () => changes.removeListener(listener) } })

  const replies: any[] = []
  let disconnected = false
  const port: any = { name: 'castalia-files-key-v1', sender: { id: chrome.runtime.id, frameId: 0, url: `${origin}/files`, tab: { id: 1, url: `${origin}/files` } }, onMessage: event(), onDisconnect: event(), postMessage: (v: any) => replies.push(v), disconnect: () => { if (!disconnected) { disconnected = true; port.onDisconnect.emit() } } }
  const connect = () => { chrome.runtime.onConnect.emit(port); port.onMessage.emit({ operation: 'wrap', payload: request }) }
  const wait = async () => { for (let i = 0; i < 50 && windows.length === 0 && replies.length === 0; i++) await new Promise(resolve => setTimeout(resolve, 2)) }
  const confirmation = (type: string, url = windows[0], approved?: boolean) => { let response: any; chrome.runtime.onMessage.emit({ type, requestId: new URL(windows[0]).searchParams.get('request'), approved }, { id: chrome.runtime.id, url }, (v: any) => { response = v }); return response }
  return { installed, chrome, port, request, replies, windows, changes, connect, wait, confirmation, signs: () => signs }
}

test('provider exposes the wallet-neutral wrapFilesKey method', async () => {
  const f = await fixture(); let seen: any
  const provider = createCastaliaWalletProvider(async request => { seen = request; return {} })
  await provider.wrapFilesKey(f.request)
  assert.equal(seen.method, 'castalia.wallet.wrapFilesKey'); assert.deepEqual(seen.payload, f.request)
})

test('runtime binds actual top-level sender and Chrome-owned claimed confirmation', async () => {
  const f = await fixture(); f.connect(); await f.wait()
  assert.equal(f.confirmation('GET_FILES_KEY_CONFIRMATION', 'https://castalia.example/').ok, false)
  assert.equal(f.confirmation('RESOLVE_FILES_KEY_CONFIRMATION', undefined, true).ok, false)
  const claimed = f.confirmation('GET_FILES_KEY_CONFIRMATION'); assert.equal(claimed.ok, true); assert.equal(claimed.summary.binding.storageAccountId, f.request.binding.storageAccountId)
  assert.equal(f.confirmation('GET_FILES_KEY_CONFIRMATION').ok, false)
  assert.equal(f.confirmation('RESOLVE_FILES_KEY_CONFIRMATION', undefined, true).ok, true)
  for (let i = 0; i < 50 && !f.replies.length; i++) await new Promise(r => setTimeout(r, 2))
  assert.equal(f.replies[0]?.ok, true); assert.equal(f.signs(), 1)
})

for (const reason of ['navigation', 'disconnect', 'custody', 'revocation']) test(`runtime cancels pending confirmation on ${reason}`, async () => {
  const f = await fixture(); f.connect(); await f.wait(); assert.equal(f.confirmation('GET_FILES_KEY_CONFIRMATION').ok, true)
  if (reason === 'navigation') f.chrome.tabs.onUpdated.emit(1, { url: 'https://elsewhere.example/' })
  if (reason === 'disconnect') f.port.disconnect()
  if (reason === 'custody') f.changes.emit()
  if (reason === 'revocation') f.installed.invalidate()
  assert.equal(f.confirmation('RESOLVE_FILES_KEY_CONFIRMATION', undefined, true).ok, false)
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
  forwardFilesKey(port, { test: 'request' }, v => replies.push(v), page)
  assert.deepEqual(messages, [{ test: 'request' }]); listeners.get('pagehide')!()
  port.onMessage.emit({ ok: true }); assert.equal(replies.length, 1); assert.equal(replies[0].ok, false); assert.equal(closed, 1); assert.equal(listeners.size, 0)
})

test('runtime bounds active connections and rejects unknown operation or duplicate messages', async () => {
  const f = await fixture(), ports: any[] = []
  for (let i=0;i<65;i++) {
    let disconnected = false
    const port: any = { ...f.port, onMessage:event(), onDisconnect:event(), disconnect:()=>{disconnected=true;port.onDisconnect.emit()}, postMessage:()=>{} }
    f.chrome.runtime.onConnect.emit(port); ports.push(port)
    assert.equal(disconnected, i===64)
  }
  for (const p of ports) p.disconnect()
  const g = await fixture();g.chrome.runtime.onConnect.emit(g.port);g.port.onMessage.emit({operation:'signAnything',payload:{}})
  assert.equal(g.replies[0]?.ok,false);assert.equal(g.windows.length,0)
  const h = await fixture();h.connect();h.port.onMessage.emit({operation:'wrap',payload:h.request});await h.wait()
  assert.equal(h.replies[0]?.ok,false);assert.equal(h.signs(),0)
})
