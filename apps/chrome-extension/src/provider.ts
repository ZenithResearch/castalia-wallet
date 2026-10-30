import type {
  RegistrationRequestV1,
  SignedRegistrationManifestV1,
  CastaliaMembershipSummary,
  CastaliaSubject,
  CastaliaWalletOnboardingRequest,
  CastaliaWalletProvider,
  MembershipPresentationRequestV2,
  MembershipPresentationV2,
  SignaturePresentation,
  SignChallengeRequest,
} from '@castalia-wallet/provider-types'

export const CASTALIA_WALLET_PROVIDER = 'castaliaWallet'
export const CASTALIA_WALLET_REQUEST = 'castalia:wallet:request'
export const CASTALIA_WALLET_RESPONSE = 'castalia:wallet:response'

export type CastaliaWalletRequestEnvelope = {
  type: typeof CASTALIA_WALLET_REQUEST
  id: string
  method: 'castalia.wallet.readAccess' | 'castalia.wallet.requestConnection' | 'castalia.wallet.proposeProviderProfile' | 'castalia.wallet.listMembershipProfiles' | 'castalia.wallet.requestMembership' | 'castalia.wallet.getMembershipCredential' | 'castalia.wallet.requestRegistrationV2' | 'castalia.wallet.getCapabilities' | 'castalia.wallet.presentCredential' | 'castalia.wallet.wrapFilesKey' | 'castalia.wallet.unwrapFilesKey' | 'castalia.wallet.requestFilesServiceAuthentication' | 'castalia.wallet.requestRegistration' | 'castalia.wallet.isAvailable' | 'castalia.wallet.openMembershipFlow' | 'castalia.wallet.getSubject' | 'castalia.wallet.getMembership' | 'castalia.wallet.signChallenge' | 'castalia.wallet.requestMembershipPresentation'
  payload: unknown
}

export type CastaliaWalletTransport = (
  request: CastaliaWalletRequestEnvelope,
) => Promise<SignedRegistrationManifestV1 | true | { state: 'opened' } | CastaliaSubject | CastaliaMembershipSummary | SignaturePresentation | MembershipPresentationV2 | Record<string, unknown>>

export function createCastaliaWalletProvider(
  transport: CastaliaWalletTransport,
): CastaliaWalletProvider {
  let nextRequestNumber = 1

  async function request<T>(
    method: CastaliaWalletRequestEnvelope['method'],
    payload: unknown,
  ): Promise<T> {
    const response = await transport({
      type: CASTALIA_WALLET_REQUEST,
      id: `castalia-${nextRequestNumber++}`,
      method,
      payload,
    })
    return response as T
  }

  return {
    readAccess: input => request('castalia.wallet.readAccess', input),
    getCapabilities: () => request<string[]>('castalia.wallet.getCapabilities', {}),
    requestConnection: () => request('castalia.wallet.requestConnection', {}),
    proposeProviderProfile: profile => request('castalia.wallet.proposeProviderProfile', profile),
    listMembershipProfiles: () => request('castalia.wallet.listMembershipProfiles', {}),
    requestMembership: input => request('castalia.wallet.requestMembership', input),
    getMembershipCredential: input => request('castalia.wallet.getMembershipCredential', input),
    requestRegistrationV2: input => request('castalia.wallet.requestRegistrationV2', input),
    presentCredential: input => request('castalia.wallet.presentCredential', input),
    filesKeyProtocol: 'castalia.files-key-wrap.v1',
    wrapFilesKey: input => request('castalia.wallet.wrapFilesKey', input),
    unwrapFilesKey: input => request('castalia.wallet.unwrapFilesKey', input),
    requestFilesServiceAuthentication: input => request('castalia.wallet.requestFilesServiceAuthentication', input),
    kind: 'castalia.wallet-provider',
    version: '1',
    membershipJoinProtocol: 'castalia.zenith-membership.v3',
    isAvailable: () => request<boolean>('castalia.wallet.isAvailable', {}),
    openMembershipFlow: () => request<{ state: 'opened' }>('castalia.wallet.openMembershipFlow', {}),
    getSubject: () => request<CastaliaSubject>('castalia.wallet.getSubject', {}),
    getMembership: () => request<CastaliaMembershipSummary>('castalia.wallet.getMembership', {}),
    requestRegistration: (input: RegistrationRequestV1) => request<SignedRegistrationManifestV1>('castalia.wallet.requestRegistration', input),
    signChallenge: (input: SignChallengeRequest) => request<SignaturePresentation>(
      'castalia.wallet.signChallenge',
      input,
    ),
    requestMembershipPresentation: (input: MembershipPresentationRequestV2) => request<MembershipPresentationV2>(
      'castalia.wallet.requestMembershipPresentation',
      input,
    ),
    getStatus: () => request<CastaliaSubject>('castalia.wallet.getSubject', {}).then(
      (subject) => ({ state: 'ready' as const, publicIdentity: subject.subjectId }),
      () => ({ state: 'locked' as const }),
    ),
    createAuthenticationPresentation: async (input: CastaliaWalletOnboardingRequest) => {
      const presentation = await request<SignaturePresentation>(
        'castalia.wallet.signChallenge',
        {
          domain: 'castalia-wallet',
          version: 1,
          nonce: input.nonce,
          origin: input.origin,
          audience: input.audience,
          operation: input.operation,
          issuedAt: new Date(input.issuedAtMs).toISOString(),
          expiresAt: new Date(input.expiresAtMs).toISOString(),
        } satisfies SignChallengeRequest,
      )
      return {
        format: 'castalia.wallet-presentation.v1',
        payload: JSON.stringify(presentation),
      }
    },
  }
}

type PageResponseEnvelope = {
  type: typeof CASTALIA_WALLET_RESPONSE
  id: string
  ok: boolean
  result?: unknown
  error?: string | { code: string, dispatched: boolean, stage?: string }
}

const DEFAULT_PAGE_MESSAGE_TIMEOUT_MS = 15_000

export function createPageMessageTransport(
  pageWindow: Window = window,
  timeoutMs = DEFAULT_PAGE_MESSAGE_TIMEOUT_MS,
): CastaliaWalletTransport {
  return (request) => new Promise((resolve, reject) => {
    const requestTimeoutMs = request.method==='castalia.wallet.readAccess'&&(request.payload as any)?.operation==='open_session_login' ? 305_000 : ['castalia.wallet.readAccess','castalia.wallet.requestConnection','castalia.wallet.proposeProviderProfile','castalia.wallet.requestMembership','castalia.wallet.openMembershipFlow','castalia.wallet.requestRegistrationV2','castalia.wallet.presentCredential','castalia.wallet.requestRegistration','castalia.wallet.wrapFilesKey','castalia.wallet.unwrapFilesKey','castalia.wallet.requestFilesServiceAuthentication'].includes(request.method) ? 125_000 : timeoutMs
    const timeout = pageWindow.setTimeout(() => {
      pageWindow.removeEventListener('message', onMessage)
      const error = new Error('Castalia Wallet request timed out')
      reject(error)
    }, requestTimeoutMs)

    function onMessage(event: MessageEvent<unknown>) {
      if (event.source !== pageWindow || event.origin !== pageWindow.location.origin) return
      if (!isPageResponse(event.data) || event.data.id !== request.id) return

      pageWindow.clearTimeout(timeout)
      pageWindow.removeEventListener('message', onMessage)
      if (!event.data.ok) {
        const detail = event.data.error
        const error = new Error(typeof detail === 'string' ? detail : detail?.code ?? 'Castalia Wallet request failed')
        if (detail && typeof detail === 'object') Object.assign(error, { code: detail.code, dispatched: detail.dispatched, ...(detail.stage?{stage:detail.stage}:{}) })
        reject(error)
        return
      }
      resolve(event.data.result as Awaited<ReturnType<CastaliaWalletTransport>>)
    }

    pageWindow.addEventListener('message', onMessage)
    pageWindow.postMessage(request, pageWindow.location.origin)
  })
}

export function installCastaliaWalletProvider(pageWindow: Window = window): CastaliaWalletProvider {
  const existing = (pageWindow as Window & { castaliaWallet?: CastaliaWalletProvider }).castaliaWallet
  if (existing) return existing

  const provider = createCastaliaWalletProvider(createPageMessageTransport(pageWindow))
  Object.defineProperty(pageWindow, CASTALIA_WALLET_PROVIDER, {
    configurable: false,
    enumerable: true,
    writable: false,
    value: provider,
  })
  return provider
}

function isPageResponse(value: unknown): value is PageResponseEnvelope {
  if (typeof value !== 'object' || value === null) return false
  const response = value as Partial<PageResponseEnvelope>
  return response.type === CASTALIA_WALLET_RESPONSE
    && typeof response.id === 'string'
    && typeof response.ok === 'boolean'
}

if (
  typeof window !== 'undefined'
  && typeof document !== 'undefined'
  && document.currentScript instanceof HTMLScriptElement
  && document.currentScript.src.startsWith('chrome-extension://')
) {
  installCastaliaWalletProvider(window)
}
