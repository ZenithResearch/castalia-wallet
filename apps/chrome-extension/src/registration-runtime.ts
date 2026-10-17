import { createOperationConfirmationBroker } from './operation-confirmation-broker.js'
import { createRegistrationHandler, createRegistrationReplayStore, type RegistrationConfirmationSummary, type RegistrationSigningState } from './registration.js'

type Custody = {
  run<T>(operation: () => Promise<T>): Promise<T>
  state(): Promise<RegistrationSigningState | null>
  epoch(): number
  onChange(listener: () => void): () => void
  verifyMembership(memberKey: string, origin: string): Promise<void>
}
function webOrigin(url: unknown): string {
  if (typeof url !== 'string') throw new Error('Registration sender URL unavailable')
  const parsed = new URL(url)
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname))) throw new Error('Registration requires HTTPS or loopback')
  return parsed.origin
}
export function installRegistrationRuntime(chrome: any, custody: Custody) {
  const pageUrl = chrome.runtime.getURL('src/registration-confirmation.html')
  const replayKey = 'castalia-registration-consents-v1'
  const replay = createRegistrationReplayStore({
    get: async () => (await chrome.storage.session.get(replayKey))[replayKey],
    set: async value => { await chrome.storage.session.set({ [replayKey]: value }) },
  })
  const broker = createOperationConfirmationBroker<RegistrationConfirmationSummary>({
    confirmationUrl: id => `${pageUrl}?request=${encodeURIComponent(id)}`,
    createWindow: async url => { const w = await chrome.windows.create({ url, type: 'popup', width: 520, height: 760, focused: true }); if (typeof w?.id !== 'number') throw new Error('Registration confirmation unavailable'); return w.id },
    closeWindow: id => chrome.windows.remove(id),
    addWindowRemovedListener: listener => chrome.windows.onRemoved.addListener(listener),
    removeWindowRemovedListener: listener => chrome.windows.onRemoved.removeListener(listener),
    setTimeout: (callback, ms) => globalThis.setTimeout(callback, ms), clearTimeout: timer => globalThis.clearTimeout(timer as ReturnType<typeof setTimeout>),
    randomId: () => crypto.randomUUID(), nowMs: Date.now,
  })
  const active = new Set<{ tabId: number; cancel(): void }>()
  custody.onChange(() => { for (const entry of [...active]) entry.cancel() })
  chrome.tabs.onUpdated.addListener((tabId: number, change: { url?: string; status?: string }) => {
    if (change.url !== undefined || change.status === 'loading') for (const entry of [...active]) if (entry.tabId === tabId) entry.cancel()
  })
  chrome.tabs.onRemoved.addListener((tabId: number) => { for (const entry of [...active]) if (entry.tabId === tabId) entry.cancel() })
  chrome.runtime.onMessage.addListener((message: any, sender: any, respond: (value: unknown) => void) => {
    if (!['GET_REGISTRATION_CONFIRMATION', 'RESOLVE_REGISTRATION_CONFIRMATION'].includes(message?.type)) return false
    try {
      const url = new URL(sender?.url)
      if (sender?.id !== chrome.runtime.id || typeof message.requestId !== 'string' || url.href !== `${pageUrl}?request=${encodeURIComponent(message.requestId)}`) throw new Error('Invalid registration confirmation sender')
      if (message.type === 'GET_REGISTRATION_CONFIRMATION') {
        const pending = broker.claimPending(message.requestId)
        if (!pending) throw new Error('Registration confirmation unavailable')
        respond({ ok: true, summary: pending.summary })
      } else {
        if (!broker.resolve(message.requestId, message.approved === true)) throw new Error('Registration confirmation unavailable')
        respond({ ok: true })
      }
    } catch (error) { respond({ ok: false, error: error instanceof Error ? error.message : 'Registration confirmation unavailable' }) }
    return false
  })
  chrome.runtime.onConnect.addListener((port: any) => {
    if (!['castalia-registration-v1','castalia-registration-v2'].includes(port.name)) return
    if (active.size >= 64) { port.disconnect(); return }
    let live = true, used = false
    let deadline: ReturnType<typeof setTimeout> | undefined
    const sender = port.sender
    const tabId = sender?.tab?.id
    const owner = { tabId, cancel() { if (!live) return; live = false; clearTimeout(deadline); broker.cancelForOwner(owner); active.delete(owner); try { port.disconnect() } catch {} } }
    const fail = (error: unknown) => { try { port.postMessage({ ok: false, error: error instanceof Error ? error.message : 'Registration signing failed' }) } catch {} owner.cancel() }
    let origin: string
    try {
      if (sender?.id !== chrome.runtime.id || sender.frameId !== 0 || !Number.isInteger(tabId)) throw new Error('Registration requires a top-level extension content script')
      origin = webOrigin(sender.url)
      if (origin !== webOrigin(sender.tab.url)) throw new Error('Registration sender origin mismatch')
    } catch (error) { fail(error); return }
    active.add(owner)
    deadline = setTimeout(() => owner.cancel(), 125_000)
    port.onDisconnect.addListener(() => owner.cancel())
    const handler = createRegistrationHandler({
      runCustody: operation => custody.run(operation), getState: () => custody.state(), epoch: custody.epoch, nowMs: Date.now,
      currentOrigin: async () => webOrigin((await chrome.tabs.get(tabId))?.url), isCurrent: () => live,
      verifyMembership: custody.verifyMembership, reserve: (consent, key) => replay.reserve(consent, key, Date.now()),
      confirm: async summary => { try { return await broker.confirm({ summary, tabId, owner }) } catch { throw new Error('Registration confirmation unavailable') } },
    }, port.name === 'castalia-registration-v2' ? 'proposal-v2' : 'legacy-v1')
    port.onMessage.addListener((message: any) => {
      if (used || !live) { fail(new Error('Registration connection already used')); return }
      used = true
      void handler(message, origin).then(result => {
        try { if (live) port.postMessage({ ok: true, result }) } catch {} finally { owner.cancel() }
      }, fail)
    })
  })
  return { invalidate: () => { for (const entry of [...active]) entry.cancel() } }
}
