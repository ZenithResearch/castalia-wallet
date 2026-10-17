/** One connection owns one pending scoped request; unload/disposal cancels approval. */
export function forwardFilesKey(port: any, payload: unknown, reply: (value: unknown) => void, page: Pick<Window, 'addEventListener' | 'removeEventListener'>) {
  let done = false
  const cleanup = () => { page.removeEventListener('pagehide', dispose); try { port.disconnect() } catch {} }
  const finish = (value: unknown) => { if (done) return; done = true; try { reply(value) } finally { cleanup() } }
  const dispose = () => finish({ ok: false, error: 'Files custody page disposed' })
  page.addEventListener('pagehide', dispose, { once: true })
  port.onMessage.addListener((value: unknown) => finish(value))
  port.onDisconnect.addListener(() => finish({ ok: false, error: 'Files custody connection closed' }))
  try { port.postMessage(payload) } catch { dispose() }
}
