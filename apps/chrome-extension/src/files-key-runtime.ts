import { createOperationConfirmationBroker } from './operation-confirmation-broker.js'
import { createFilesKeyHandler, createFilesReplayStore, type FilesConfirmationSummary, type FilesSigningState } from './files-key-handler.js'

type Custody = {
  run<T>(operation: () => Promise<T>): Promise<T>
  state(): Promise<FilesSigningState | null>
  epoch(): number
  onChange(listener: () => void): () => void
}
function webOrigin(url: unknown): string {
  if (typeof url !== 'string') throw new Error('FilesKey sender URL unavailable')
  const parsed = new URL(url)
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname))) throw new Error('FilesKey requires HTTPS or loopback')
  return parsed.origin
}
export function installFilesKeyRuntime(chrome: any, custody: Custody) {
  const pageUrl = chrome.runtime.getURL('src/files-key-confirmation.html')
  const replayKey = 'castalia-files-key-consents-v1'
  const replay = createFilesReplayStore({
    get: async () => (await chrome.storage.session.get(replayKey))[replayKey],
    set: async value => { await chrome.storage.session.set({ [replayKey]: value }) },
  })
  const broker = createOperationConfirmationBroker<FilesConfirmationSummary>({
    confirmationUrl: id => `${pageUrl}?request=${encodeURIComponent(id)}`,
    createWindow: async url => { const w = await chrome.windows.create({ url, type: 'popup', width: 520, height: 760, focused: true }); if (typeof w?.id !== 'number') throw new Error('FilesKey confirmation unavailable'); return w.id },
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
    if (!['GET_FILES_KEY_CONFIRMATION', 'RESOLVE_FILES_KEY_CONFIRMATION'].includes(message?.type)) return false
    try {
      const url = new URL(sender?.url)
      if (sender?.id !== chrome.runtime.id || typeof message.requestId !== 'string' || url.href !== `${pageUrl}?request=${encodeURIComponent(message.requestId)}`) throw new Error('Invalid files-key confirmation sender')
      if (message.type === 'GET_FILES_KEY_CONFIRMATION') {
        const pending = broker.claimPending(message.requestId)
        if (!pending) throw new Error('FilesKey confirmation unavailable')
        respond({ ok: true, summary: pending.summary })
      } else {
        if (!broker.resolve(message.requestId, message.approved === true)) throw new Error('FilesKey confirmation unavailable')
        respond({ ok: true })
      }
    } catch (error) { respond({ ok: false, error: error instanceof Error ? error.message : 'FilesKey confirmation unavailable' }) }
    return false
  })
  chrome.runtime.onConnect.addListener((port: any) => {
    if (port.name !== 'castalia-files-key-v1') return
    if (active.size >= 64) { port.disconnect(); return }
    let live = true, used = false
    let deadline: ReturnType<typeof setTimeout> | undefined
    const sender = port.sender
    const tabId = sender?.tab?.id
    const owner = { tabId, cancel() { if (!live) return; live = false; clearTimeout(deadline); broker.cancelForOwner(owner); active.delete(owner); try { port.disconnect() } catch {} } }
    const fail = (error: unknown) => { try { port.postMessage({ ok: false, error: error instanceof Error ? error.message : 'FilesKey signing failed' }) } catch {} owner.cancel() }
    let origin: string
    try {
      if (sender?.id !== chrome.runtime.id || sender.frameId !== 0 || !Number.isInteger(tabId)) throw new Error('FilesKey requires a top-level extension content script')
      origin = webOrigin(sender.url)
      if (origin !== webOrigin(sender.tab.url)) throw new Error('FilesKey sender origin mismatch')
    } catch (error) { fail(error); return }
    active.add(owner)
    deadline = setTimeout(() => owner.cancel(), 125_000)
    port.onDisconnect.addListener(() => owner.cancel())
    const handler = createFilesKeyHandler({
      runCustody: operation => custody.run(operation), getState: () => custody.state(), epoch: custody.epoch, nowMs: Date.now,
      currentOrigin: async () => webOrigin((await chrome.tabs.get(tabId))?.url), isCurrent: () => live,
      reserve: (consent, key) => replay.reserve(consent, key, Date.now()),
      confirm: async summary => { try { return await broker.confirm({ summary, tabId, owner }) } catch { throw new Error('FilesKey confirmation unavailable') } },
    })
    port.onMessage.addListener((message: any) => {
      if (used || !live) { fail(new Error('FilesKey connection already used')); return }
      used = true
      if (!message || Object.keys(message).sort().join(',') !== 'operation,payload' || !['wrap', 'unwrap', 'authenticate'].includes(message.operation)) { fail(new Error('Invalid Files operation')); return }
      void handler(message.operation, message.payload, origin).then(result => {
        try { if (live) port.postMessage({ ok: true, result }) } catch {} finally { owner.cancel() }
      }, fail)
    })
  })
  return { invalidate: () => { for (const entry of [...active]) entry.cancel() } }
}
