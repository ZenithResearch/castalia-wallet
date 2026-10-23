import { forwardCredentialPresentation } from './credential-presentation-content.js'

/** A fresh top-level gesture is required for every new read/request consent. */
export function forwardReadAccess(chrome: any, payload: unknown, reply: (value: unknown) => void, page: Window, active: boolean) {
  const operation = (payload as { operation?: unknown } | null)?.operation
  if (page.top !== page || (['approve', 'approve_graph_v2', 'request'].includes(String(operation)) && !active)) {
    reply({ ok: false, error: 'approval_required' })
    return
  }
  forwardCredentialPresentation(chrome.runtime.connect({ name: 'castalia-read-access-v1' }), payload, reply, page)
}
