import { forwardCredentialPresentation } from './credential-presentation-content.js'

/** Chrome supplies the sender's document ID; page code cannot choose another. */
export function installReadDocumentLifecycle(chrome:any,page:Window){
  if(page.top!==page)return;
  page.addEventListener('pagehide',()=>{try{
    void Promise.resolve(chrome.runtime.sendMessage({type:'CASTALIA_READ_DOCUMENT_CLOSED'})).catch(()=>{});
  }catch{}},{once:true});
}

/** A fresh top-level gesture is required for every new read/request consent. */
export function forwardReadAccess(chrome: any, payload: unknown, reply: (value: unknown) => void, page: Window, active: boolean) {
  const operation = (payload as { operation?: unknown } | null)?.operation
  if (page.top !== page || (['approve', 'approve_graph_v2', 'request', 'save_grant', 'use_grant', 'open_holder_session'].includes(String(operation)) && !active)) {
    reply({ ok: false, error: 'approval_required' })
    return
  }
  forwardCredentialPresentation(chrome.runtime.connect({ name: 'castalia-read-access-v1' }), payload, reply, page)
}
