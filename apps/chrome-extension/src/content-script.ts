import { forwardReadAccess,installReadDocumentLifecycle } from './read-access-content.js'
import { forwardCredentialPresentation } from './credential-presentation-content.js'
import { forwardFilesKey } from './files-key-content.js'
import { forwardRegistration } from './registration-content.js'
import {
  CASTALIA_WALLET_REQUEST,
  CASTALIA_WALLET_RESPONSE,
  type CastaliaWalletRequestEnvelope
} from './provider.js'
import {
  parseZenithMembershipCredential,
  type ZenithMembershipCredentialV3,
} from '@castalia-wallet/zenith-membership'

export { CASTALIA_WALLET_RESPONSE }

export type PageMessageNormalizationInput = {
  message: unknown
  sourceOrigin: string
}

export type NormalizedProviderRequest = {
  id: string
  method: string
  payload: unknown
  computedOrigin: string
}

export function normalizePageMessage(
  input: PageMessageNormalizationInput,
): NormalizedProviderRequest | null {
  if (!isObject(input.message)) {
    return null
  }

  if (input.message.type !== CASTALIA_WALLET_REQUEST) {
    return null
  }

  if (typeof input.message.id !== 'string' || input.message.id.length === 0) {
    return null
  }

  if (typeof input.message.method !== 'string' || input.message.method.length === 0) {
    return null
  }

  const request = input.message as CastaliaWalletRequestEnvelope
  return {
    id: request.id,
    method: request.method,
    payload: request.payload,
    computedOrigin: input.sourceOrigin,
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

export type MembershipFlowSummary = ZenithMembershipCredentialV3

export function normalizeMembershipFlowReady(
  value: unknown,
): MembershipFlowSummary | null {
  if (!isObject(value) || value.type !== 'CASTALIA_MEMBERSHIP_FLOW_READY') return null
  if (!isObject(value.membership)) return null
  try {
    return parseZenithMembershipCredential(value.membership)
  } catch {
    return null
  }
}

export function injectPageProvider(documentRoot: Document, providerUrl: string): void {
  const script = documentRoot.createElement('script')
  script.src = providerUrl
  script.async = false
  script.addEventListener('load', () => script.remove(), { once: true })
  script.addEventListener('error', () => script.remove(), { once: true })
  ;(documentRoot.head ?? documentRoot.documentElement).appendChild(script)
}

// Chrome MV3 globals (content script context)
declare const chrome: any;

// === Wave 3/4: Actual runtime bridge — forward normalized requests to service worker ===

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome?.runtime?.sendMessage) {
  installReadDocumentLifecycle(chrome,window)
  injectPageProvider(document, chrome.runtime.getURL('dist/provider.js'))
  chrome.runtime.onMessage.addListener((message: any, sender: any) => {
    if (sender?.id === chrome.runtime.id && message?.type === 'CASTALIA_READ_ACCESS_INVALIDATED')
      window.dispatchEvent(new CustomEvent('castalia:wallet:read-access-invalidated'))
  })
  window.addEventListener('message', (event) => {
  // Only accept messages from the same origin (the page itself)
  if (event.source !== window) return

  const normalized = normalizePageMessage({
    message: event.data,
    sourceOrigin: event.origin,
  })

  if (!normalized) return

  if (normalized.method === 'castalia.wallet.readAccess') {
    const reply = (response: unknown) => window.postMessage({ type: CASTALIA_WALLET_RESPONSE, id: normalized.id, ...(response as object) }, window.location.origin)
    forwardReadAccess(chrome, normalized.payload, reply, window, navigator.userActivation?.isActive === true)
    return
  }

  if (normalized.method === 'castalia.wallet.presentCredential') {
    const reply = (response: unknown) => window.postMessage({ type: CASTALIA_WALLET_RESPONSE, id: normalized.id, ...(response as object) }, window.location.origin)
    if (window.top !== window || navigator.userActivation?.isActive !== true) { reply({ok:false,error:'approval_required'}); return }
    forwardCredentialPresentation(chrome.runtime.connect({name:'castalia-credential-presentation-v2'}),normalized.payload,reply,window)
    return
  }

  const profileOperation = ({
    'castalia.wallet.requestConnection':'connect','castalia.wallet.proposeProviderProfile':'propose',
    'castalia.wallet.listMembershipProfiles':'profiles','castalia.wallet.requestMembership':'join',
    'castalia.wallet.getMembershipCredential':'credential','castalia.wallet.getMembership':'legacyCredential',
    'castalia.wallet.openMembershipFlow':'legacyJoin',
  } as Record<string,string>)[normalized.method]
  if (profileOperation) {
    const reply = (response: unknown) => window.postMessage({ type: CASTALIA_WALLET_RESPONSE, id: normalized.id, ...(response as object) }, window.location.origin)
    if (window.top !== window || ['connect','propose','join','legacyJoin'].includes(profileOperation) && navigator.userActivation?.isActive !== true) { reply({ok:false,error:'approval_required'}); return }
    forwardCredentialPresentation(chrome.runtime.connect({name:'castalia-provider-profiles-v1'}),{operation:profileOperation,payload:normalized.payload},reply,window)
    return
  }

  const filesOperation = ({ 'castalia.wallet.wrapFilesKey': 'wrap', 'castalia.wallet.unwrapFilesKey': 'unwrap', 'castalia.wallet.requestFilesServiceAuthentication': 'authenticate' } as Record<string,string>)[normalized.method]
  if (filesOperation) {
    const reply = (response: unknown) => window.postMessage({ type: CASTALIA_WALLET_RESPONSE, id: normalized.id, ...(response as object) }, window.location.origin)
    if (window.top !== window) { reply({ ok: false, error: 'Files custody requires a top-level page' }); return }
    forwardFilesKey(chrome.runtime.connect({ name: 'castalia-files-key-v1' }), { operation: filesOperation, payload: normalized.payload }, reply, window)
    return
  }
  if (['castalia.wallet.requestRegistration','castalia.wallet.requestRegistrationV2'].includes(normalized.method)) {
    const reply = (response: unknown) => window.postMessage({ type: CASTALIA_WALLET_RESPONSE, id: normalized.id, ...(response as object) }, window.location.origin)
    if (window.top !== window || navigator.userActivation?.isActive !== true) {
      reply({ ok: false, error: 'Signing a namespace proposal requires a top-level user action' })
      return
    }
    forwardRegistration(chrome.runtime.connect({ name: normalized.method === 'castalia.wallet.requestRegistrationV2' ? 'castalia-registration-v2' : 'castalia-registration-v1' }), normalized.payload, reply, window)
    return
  }


  // Forward to the service worker
  chrome.runtime.sendMessage(
    {
      type: 'CASTALIA_PROVIDER_REQUEST',
      id: normalized.id,
      method: normalized.method,
      payload: normalized.payload,
      computedOrigin: normalized.computedOrigin,
      pageSuppliedOrigin: event.origin,
    },
    (response: any) => {
      if (chrome.runtime.lastError) {
        window.postMessage({
          type: CASTALIA_WALLET_RESPONSE,
          id: normalized.id,
          ok: false,
          error: chrome.runtime.lastError.message,
        }, '*')
        return
      }

      // Relay the response back to the page
      window.postMessage({
        type: CASTALIA_WALLET_RESPONSE,
        id: normalized.id,
        ...response,
      }, '*')
    }
  )
  })

  chrome.runtime.onMessage.addListener((message: unknown) => {
    const membership = normalizeMembershipFlowReady(message)
    if (!membership) return false
    window.dispatchEvent(new CustomEvent('castalia:wallet:membership-flow-ready', {
      detail: { membership },
    }))
    return false
  })
}

console.log('[CastaliaWallet ContentScript] Provider bridge active — forwarding page messages to SW')
