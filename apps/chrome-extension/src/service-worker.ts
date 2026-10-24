import { isWalletIdentityPage } from './wallet-identities-store.js'
import { walletIdentities } from './custody-runtime.js'
import { installReadAccessRuntime } from './read-access-runtime.js'
import { prepareReadAccess, prepareAccessRequest } from './custody-runtime.js'
import { installProviderProfilesRuntime, NEUTRAL_CAPABILITIES } from './provider-profiles-runtime.js'
import { invalidateCustodyApprovals } from './custody-runtime.js'
import { installCredentialPresentationRuntime } from './credential-presentation-runtime.js'
import { prepareCredentialPresentation } from './custody-runtime.js'
import { installRegistrationRuntime } from './registration-runtime.js'
import type { CastaliaMembershipSummary, CastaliaSubject, DreggHybridIdentity, MembershipPresentationRequestV2, MembershipPresentationV2, SignaturePresentation, SignChallengeRequest } from '@castalia-wallet/provider-types'
import { canonicalMembershipEnrollmentChallengeBytes } from '@castalia-wallet/core/membership-presentation-v2'
import {
  fetchCastaliaMembership,
  type DreggMembershipClientConfig,
  type PermissionlessMembershipBindingV2,
} from '@castalia-wallet/dregg-adapter'
import {
  issueZenithMembership,
  verifyZenithMembershipCredential,
  zenithMembershipJoinTranscript,
  type ZenithMembershipCredentialV3,
  type ZenithMembershipTrustPolicyV1,
} from '@castalia-wallet/zenith-membership'
import { validateChallengePayload } from './challenge-validation.js'
import { validateProviderRequest } from './bridge.js'
import { sessionState } from './state/session-state.js'
import { membershipState } from './state/membership-state.js'
import { zenithMembershipState } from './state/zenith-membership-state.js'
import { installFilesKeyRuntime } from './files-key-runtime.js'
import { filesCustody, custodyState, durableChainAccounts, durableSigningIdentity, recovery, custodyEpoch, subscribeCustodyChanges } from './custody-runtime.js'
import { createMembershipConfirmationBroker } from './confirmation-broker.js'
import { createMembershipFlowBroker } from './membership-flow-broker.js'
// Chrome MV3 globals (service worker runtime only; suppressed for tsc in node test env)
declare const chrome: any;

export type ExtensionWalletState = {
  setupComplete: boolean
  unlocked: boolean
  approvedOrigins: ReadonlySet<string>
  signingIdentity: {
    publicKey: string
    publicKeyRawHex: string
    dreggHybridIdentity?: DreggHybridIdentity
    signChallenge(challenge: SignChallengeRequest): Promise<string>
    signBytes(message: Uint8Array): Promise<string>
  }
  subjectId: string
  zenithMembershipCredential: ZenithMembershipCredentialV3 | null
  permissionlessMembershipBinding: PermissionlessMembershipBindingV2 | null
  membershipConfig: DreggMembershipClientConfig | null
}

export type ExtensionProviderDependencies = {
  fetchImpl?: typeof fetch
  confirmMembershipPresentation?: (summary: MembershipPresentationConfirmationSummary) => Promise<boolean>
  nowMs?: () => number
  zenithTrustPolicy?: ZenithMembershipTrustPolicyV1
}

export type MembershipPresentationConfirmationSummary = {
  origin: string
  memberKeyFingerprint: string
  issuedAt: number
  expiresAt: number
}

export type ExtensionProviderRequest = {
  method: string
  payload: unknown
  computedOrigin: string
  pageSuppliedOrigin?: string
  state: ExtensionWalletState
}

export type ExtensionProviderResponse =
  | { ok: true; result: true }
  | { ok: true; result: CastaliaSubject }
  | { ok: true; result: CastaliaMembershipSummary }
  | { ok: true; result: SignaturePresentation }
  | { ok: true; result: MembershipPresentationV2 }
  | { ok: false; error: string }

export async function handleProviderRequest(
  input: ExtensionProviderRequest,
  dependencies: ExtensionProviderDependencies = {},
): Promise<ExtensionProviderResponse> {
  const validation = validateProviderRequest({
    method: input.method,
    payload: input.payload,
    computedOrigin: input.computedOrigin,
    pageSuppliedOrigin: input.pageSuppliedOrigin,
    walletSetupComplete: input.state.setupComplete,
    walletUnlocked: input.state.unlocked,
    approvedOrigins: input.state.approvedOrigins,
  })

  if (!validation.ok) {
    return { ok: false, error: validation.error }
  }

  if (validation.method === 'castalia.wallet.isAvailable') {
    return { ok: true, result: true }
  }

  if (validation.method === 'castalia.wallet.getSubject') {
    return { ok: true, result: buildSubject(input.state) }
  }

  if (validation.method === 'castalia.wallet.getMembership') {
    if (!input.state.zenithMembershipCredential) {
      return { ok: false, error: 'Zenith membership is not bound to this wallet session' }
    }
    try {
      if (!dependencies.zenithTrustPolicy) {
        throw new Error('Zenith membership trust policy is unavailable')
      }
      return {
        ok: true,
        result: await verifyZenithMembershipCredential(
          input.state.zenithMembershipCredential,
          dependencies.zenithTrustPolicy,
          input.state.signingIdentity.publicKeyRawHex,
        ),
      }
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : 'membership lookup failed',
      }
    }
  }

  if (validation.method === 'castalia.wallet.signChallenge') {
    return await signChallenge(input, validation.origin)
  }

  if (validation.method === 'castalia.wallet.requestMembershipPresentation') {
    return await requestMembershipPresentation(input, validation.origin, dependencies)
  }

  return { ok: false, error: `unsupported Checkpoint A method: ${validation.method}` }
}

async function signChallenge(
  input: ExtensionProviderRequest,
  computedOrigin: string,
): Promise<ExtensionProviderResponse> {
  try {
    const challenge = structuredClone(input.payload) as SignChallengeRequest
    if (challenge.domain !== 'castalia-wallet' || challenge.version !== 1) {
      throw new Error('unsupported challenge version')
    }
    validateChallengePayload(challenge, { expectedOrigin: computedOrigin })

    return {
      ok: true,
      result: {
        subject: buildSubject(input.state),
        challenge,
        signature: await input.state.signingIdentity.signChallenge(challenge),
        signatureAlgorithm: 'ed25519',
      },
    }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'signing failed' }
  }
}

async function requestMembershipPresentation(
  input: ExtensionProviderRequest,
  computedOrigin: string,
  dependencies: ExtensionProviderDependencies,
): Promise<ExtensionProviderResponse> {
  try {
    const request = structuredClone(input.payload) as MembershipPresentationRequestV2
    const transcript = canonicalMembershipEnrollmentChallengeBytes(request.challenge, request.application)
    const nowMs = dependencies.nowMs ?? Date.now
    validateMembershipChallengeTime(request.challenge, nowMs())
    if (request.challenge.origin !== computedOrigin) throw new Error('challenge origin mismatch')
    if (request.challenge.ownerPublicKey !== input.state.signingIdentity.publicKeyRawHex) {
      throw new Error('challenge owner key does not match this wallet')
    }
    const confirmation = dependencies.confirmMembershipPresentation
    if (!confirmation) throw new Error('membership presentation confirmation is unavailable')
    const key = input.state.signingIdentity.publicKeyRawHex
    const approved = await confirmation({
      origin: computedOrigin,
      memberKeyFingerprint: `${key.slice(0, 12)}…${key.slice(-12)}`,
      issuedAt: request.challenge.issuedAt,
      expiresAt: request.challenge.expiresAt,
    })
    if (!approved) throw new Error('membership presentation signing denied')
    validateMembershipChallengeTime(request.challenge, nowMs())
    return {
      ok: true,
      result: {
        schema: 'castalia.wallet-membership-presentation.v2',
        ownerPublicKey: input.state.signingIdentity.publicKeyRawHex,
        challenge: request.challenge,
        signatureSuite: 'Ed25519',
        signature: standardBase64SignatureToBase64url(
          await input.state.signingIdentity.signBytes(transcript),
        ),
      },
    }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'membership presentation failed' }
  }
}

function validateMembershipChallengeTime(
  challenge: MembershipPresentationRequestV2['challenge'],
  nowMs: number,
): void {
  if (challenge.issuedAt > nowMs + 5_000 || nowMs > challenge.expiresAt) {
    throw new Error('membership presentation challenge time invalid')
  }
}

function standardBase64SignatureToBase64url(signature: string): string {
  if (!/^[A-Za-z0-9+/]{86}==$/.test(signature)) {
    throw new Error('Member Key returned an invalid Ed25519 signature')
  }
  const bytes = Uint8Array.from(atob(signature), character => character.charCodeAt(0))
  if (bytes.length !== 64) throw new Error('Member Key returned an invalid Ed25519 signature')
  return signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function buildSubject(state: ExtensionWalletState): CastaliaSubject {
  return {
    subjectId: state.subjectId,
    publicKey: state.signingIdentity.publicKey,
    dreggOwnerPublicKey: state.signingIdentity.publicKeyRawHex,
    ...(state.signingIdentity.dreggHybridIdentity
      ? { dreggHybridIdentity: state.signingIdentity.dreggHybridIdentity }
      : {}),
    walletKind: 'castalia-dregg',
    capabilities: [],
  }
}

// === Wave 3 additions: Per-session lifecycle + popup messaging ===

/**
 * Combine persistent custody state with per-session origin and membership policy.
 * The unlocked Member Key is the only provider signing identity.
 */
async function getCurrentExtensionStateForProvider(): Promise<ExtensionWalletState | null> {
  const [session, custody, membership, zenithMembership] = await Promise.all([
    sessionState.getState(),
    custodyState.getState(),
    membershipState.get(),
    zenithMembershipState.get(),
  ])
  if (!custody.setupComplete || !custody.unlocked || !custody.publicKey) return null
  const memberKey = durableSigningIdentity()
  return {
    setupComplete: true,
    unlocked: true,
    approvedOrigins: new Set(session.approvedOrigins),
    signingIdentity: {
      publicKey: memberKey.publicKey,
      publicKeyRawHex: memberKey.publicKeyRawHex,
      dreggHybridIdentity: memberKey.dreggHybridIdentity,
      async signChallenge(challenge) {
        const bytes = new TextEncoder().encode(JSON.stringify({
          audience: challenge.audience,
          domain: challenge.domain,
          expiresAt: challenge.expiresAt,
          issuedAt: challenge.issuedAt,
          nonce: challenge.nonce,
          operation: challenge.operation,
          origin: challenge.origin,
          version: challenge.version,
        }))
        return memberKey.signBytes(bytes)
      },
      async signBytes(message) {
        return memberKey.signBytes(message)
      },
    },
    subjectId: `did:castalia:member:${custody.publicKey}`,
    zenithMembershipCredential: zenithMembership,
    permissionlessMembershipBinding: membership,
    membershipConfig: session.membershipConfig,
  }
}

export function createCustodyOperationQueue() {
  let tail: Promise<void> = Promise.resolve()
  return {
    run<T>(operation: () => Promise<T>): Promise<T> {
      const result = tail.then(operation, operation)
      tail = result.then(() => undefined, () => undefined)
      return result
    },
  }
}

const custodyOperations = createCustodyOperationQueue()

// Enforce per-session reset on every SW start / extension reload (core of Option B safety)
async function enforceSessionReset(): Promise<void> {
  await custodyOperations.run(async () => {
    await sessionState.clearForReload()
    await custodyState.clearSensitiveMemoryForReload()
  })
  console.log('[CastaliaWallet SW] Unlocked Member Key and per-session approvals cleared on reload')
}

// Popup <-> Service Worker messaging (Wave 3 T1.3/T1.4 foundation)
type PopupMessage =
  | {type:'WALLET_IDENTITIES_READ'}
  | {type:'WALLET_IDENTITIES_SAVE';identities:unknown;expected_revision:number}
  | {type:'WALLET_IDENTITIES_REVIEW';file:string;password:string}
  | {type:'WALLET_IDENTITIES_CONFIRM';token:string}
  | {type:'WALLET_IDENTITIES_CANCEL'}
  | {type:'WALLET_IDENTITIES_EXPORT';password:string}
  | { type: 'GET_STATE' }
  | { type: 'CUSTODY_GET_STATE'; requestId?: string }
  | { type: 'CUSTODY_CREATE'; passphrase: string }
  | { type: 'CUSTODY_UNLOCK'; passphrase: string }
  | { type: 'CUSTODY_LOCK' }
  | { type: 'CUSTODY_EXPORT'; passphrase: string }
  | { type: 'CUSTODY_IMPORT'; contents: string; passphrase: string; replaceExisting: boolean }
  | { type: 'OPEN_MEMBERSHIP_FLOW' }
  | { type: 'BEGIN_MEMBERSHIP_FLOW'; requestId: string; expectedOrigin: string }
  | { type: 'SETUP' }
  | { type: 'UNLOCK' }
  | { type: 'LOCK' }
  | { type: 'APPROVE_ORIGIN'; origin: string }
  | { type: 'REVOKE_ORIGIN'; origin: string }
  | { type: 'BIND_MEMBERSHIP'; config: DreggMembershipClientConfig }
  | { type: 'UNBIND_MEMBERSHIP' }
  | { type: 'GET_MEMBERSHIP_CONFIRMATION'; requestId: string }
  | { type: 'RESOLVE_MEMBERSHIP_CONFIRMATION'; requestId: string; approved: boolean }

function webOriginFromSender(senderUrl: unknown): string {
  if (typeof senderUrl !== 'string') throw new Error('Embedding tab URL is required')
  const url = new URL(senderUrl)
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('Embedding tab must use an HTTP(S) origin')
  }
  if (
    url.protocol === 'http:'
    && url.hostname !== 'localhost'
    && url.hostname !== '127.0.0.1'
    && url.hostname !== '[::1]'
  ) {
    throw new Error('Embedding tab must use HTTPS outside loopback development')
  }
  return url.origin
}

export function approvedWebOriginFromSender(
  senderUrl: unknown,
  expectedOrigin: unknown,
): string {
  const origin = webOriginFromSender(senderUrl)
  if (typeof expectedOrigin !== 'string' || expectedOrigin !== origin) {
    throw new Error('Embedding tab origin changed before approval')
  }
  return origin
}

export function isExactMembershipConfirmationSender(
  senderUrlValue: unknown,
  confirmationPageUrl: string,
  requestId: unknown,
): boolean {
  if (typeof senderUrlValue !== 'string' || typeof requestId !== 'string' || requestId.length === 0) {
    return false
  }
  try {
    const senderUrl = new URL(senderUrlValue)
    const expectedUrl = new URL(confirmationPageUrl)
    return senderUrl.protocol === expectedUrl.protocol
      && senderUrl.host === expectedUrl.host
      && senderUrl.pathname === expectedUrl.pathname
      && senderUrl.hash === ''
      && senderUrl.searchParams.size === 1
      && senderUrl.searchParams.get('request') === requestId
  } catch {
    return false
  }
}

export function isExactMembershipFlowSender(
  senderUrlValue: unknown,
  onboardingPageUrl: string,
  requestId: unknown,
): boolean {
  if (typeof senderUrlValue !== 'string' || typeof requestId !== 'string' || requestId.length === 0) {
    return false
  }
  try {
    const senderUrl = new URL(senderUrlValue)
    const expectedUrl = new URL(onboardingPageUrl)
    return senderUrl.protocol === expectedUrl.protocol
      && senderUrl.host === expectedUrl.host
      && senderUrl.pathname === expectedUrl.pathname
      && senderUrl.hash === ''
      && senderUrl.searchParams.size === 1
      && senderUrl.searchParams.get('request') === requestId
  } catch {
    return false
  }
}

if (typeof chrome !== 'undefined' && chrome?.runtime?.onMessage) {
  const providerProfilesRuntime = installProviderProfilesRuntime(chrome, {
    run: operation => custodyOperations.run(operation), epoch: custodyEpoch, onChange: subscribeCustodyChanges,
    invalidate: invalidateCustodyApprovals,
    state: async () => { const state=await getCurrentExtensionStateForProvider();return state?{memberKey:state.signingIdentity.publicKeyRawHex,approvedOrigins:state.approvedOrigins}:null },
    approveOrigin: origin => sessionState.approveOrigin(origin).then(()=>undefined),
    sign: bytes => durableSigningIdentity().signBytes(bytes), legacyCredential: () => zenithMembershipState.get(),
  })
  installReadAccessRuntime(chrome, {
    run: <T>(f:()=>Promise<T>)=>custodyOperations.run(f), epoch:custodyEpoch, onChange:subscribeCustodyChanges,
    state:async()=>{const state=await getCurrentExtensionStateForProvider();return state?{memberKey:state.signingIdentity.publicKeyRawHex,approvedOrigins:state.approvedOrigins}:null},
    installation:async()=>{
      const key='castalia-read-installation-v1',saved=(await chrome.storage.local.get(key))[key]
      if(saved!==undefined){if(typeof saved!=='string'||!/^[a-f0-9]{32}$/.test(saved))throw new Error('invalid_installation');return saved}
      const value=Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('')
      await chrome.storage.local.set({[key]:value});return value
    },
    memberships:(origin:string)=>providerProfilesRuntime.memberships(origin),
    setupStatus:(profile:unknown,origin:string)=>providerProfilesRuntime.setupStatus(profile,origin),
    membership:(origin:string,holder:string,profileId?:string)=>providerProfilesRuntime.readMembership(origin,holder,profileId),
    prepareRequest:async(challenge:unknown,origin:string,installation:string)=>prepareAccessRequest(challenge,origin,installation,await providerProfilesRuntime.pins()),
    prepare:async(challenge:unknown,origin:string,installation:string)=>prepareReadAccess(challenge,origin,installation,await providerProfilesRuntime.pins()),
  })
  const credentialPresentationRuntime = installCredentialPresentationRuntime(chrome, {
    run: operation => custodyOperations.run(operation), epoch: custodyEpoch, onChange: subscribeCustodyChanges,
    state: async () => { const state=await getCurrentExtensionStateForProvider();return state?{memberKey:state.signingIdentity.publicKeyRawHex,approvedOrigins:state.approvedOrigins}:null },
    prepare: async (raw,caller) => prepareCredentialPresentation(raw,await providerProfilesRuntime.pins(),caller),
  })
  const filesKeyRuntime = installFilesKeyRuntime(chrome, {
    run: operation => custodyOperations.run(operation), epoch: custodyEpoch, onChange: subscribeCustodyChanges,
    state: async () => {
      const state = await getCurrentExtensionStateForProvider()
      return state ? { memberKey: state.signingIdentity.publicKeyRawHex, approvedOrigins: state.approvedOrigins,
        wrap: async (binding, key) => filesCustody.wrap(JSON.stringify(binding), key),
        unwrap: async (binding, envelope) => filesCustody.unwrap(JSON.stringify(binding), JSON.stringify(envelope)),
        authenticate: async (body, origin, nowMs) => ({ subject: buildSubject(state), challenge: body.challenge,
          signature: filesCustody.authenticate(JSON.stringify(body.challenge),origin,body.serviceKind,body.serviceId,nowMs), signatureAlgorithm: 'ed25519' }),
      } : null
    },
  })
  const registrationRuntime = installRegistrationRuntime(chrome, {
    run: operation => custodyOperations.run(operation), epoch: custodyEpoch, onChange: subscribeCustodyChanges,
    state: async () => { const state = await getCurrentExtensionStateForProvider(); return state ? { memberKey: state.signingIdentity.publicKeyRawHex, approvedOrigins: state.approvedOrigins, signBytes: state.signingIdentity.signBytes } : null },
    verifyMembership: async (memberKey,origin) => { await providerProfilesRuntime.legacy(origin,memberKey) },
  })

  const confirmationPageUrl = chrome.runtime.getURL('src/confirmation.html')
  const onboardingPageUrl = chrome.runtime.getURL('src/onboarding.html')
  const membershipConfirmationBroker = createMembershipConfirmationBroker({
    confirmationUrl: requestId => `${confirmationPageUrl}?request=${encodeURIComponent(requestId)}`,
    async createWindow(url) {
      const created = await chrome.windows.create({ url, type: 'popup', width: 420, height: 620, focused: true })
      if (typeof created?.id !== 'number') throw new Error('confirmation window could not be created')
      return created.id
    },
    closeWindow: windowId => chrome.windows.remove(windowId),
    addWindowRemovedListener: listener => chrome.windows.onRemoved.addListener(listener),
    removeWindowRemovedListener: listener => chrome.windows.onRemoved.removeListener(listener),
    setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
    clearTimeout: handle => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
    randomId: () => crypto.randomUUID(),
  })
  const membershipFlowBroker = createMembershipFlowBroker({
    flowUrl: requestId => `${onboardingPageUrl}?request=${encodeURIComponent(requestId)}`,
    async createWindow(url) {
      const created = await chrome.windows.create({ url, type: 'popup', width: 440, height: 660, focused: true })
      if (typeof created?.id !== 'number') throw new Error('membership flow window could not be created')
      return created.id
    },
    closeWindow: windowId => chrome.windows.remove(windowId),
    addWindowRemovedListener: listener => chrome.windows.onRemoved.addListener(listener),
    removeWindowRemovedListener: listener => chrome.windows.onRemoved.removeListener(listener),
    setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
    clearTimeout: handle => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
    randomId: () => crypto.randomUUID(),
  })
  function assertConfirmationSender(sender: any, requestId: string): void {
    if (!isExactMembershipConfirmationSender(sender?.url, confirmationPageUrl, requestId)) {
      throw new Error('invalid confirmation sender')
    }
  }

  function requireMembershipFlow(sender: any, requestId: string) {
    if (!isExactMembershipFlowSender(sender?.url, onboardingPageUrl, requestId)) {
      throw new Error('invalid membership flow sender')
    }
    const flow = membershipFlowBroker.get(requestId)
    if (!flow) throw new Error('membership flow is unavailable')
    return flow
  }

  async function requireCurrentMembershipFlowOrigin(
    requestId: string,
    expectedOrigin: unknown,
  ) {
    const flow = membershipFlowBroker.get(requestId)
    if (!flow) throw new Error('membership flow is unavailable')
    if (flow.origin !== expectedOrigin) throw new Error('Embedding tab origin changed before approval')
    const tab = await chrome.tabs.get(flow.tabId)
    const origin = approvedWebOriginFromSender(tab?.url, expectedOrigin)
    return { ...flow, origin }
  }
  chrome.runtime.onInstalled.addListener(() => {
    void enforceSessionReset()
  })

  chrome.runtime.onStartup.addListener(() => {
    void enforceSessionReset()
  })

  // Configure side panel behavior — clicking the extension icon opens the sidebar (like MetaMask)
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true })
    .catch((err: any) => console.error("[CastaliaWallet SW] Failed to set side panel behavior", err))

  chrome.runtime.onMessage.addListener((
  message: PopupMessage,
  sender: any,
  sendResponse: (response?: any) => void
) => {
  // IMPORTANT: Let provider requests (from content script) pass through to the dedicated listener below
  if ((message as any).type === "CASTALIA_PROVIDER_REQUEST" || ["GET_REGISTRATION_CONFIRMATION", "RESOLVE_REGISTRATION_CONFIRMATION", "GET_CREDENTIAL_PRESENTATION_CONFIRMATION", "RESOLVE_CREDENTIAL_PRESENTATION_CONFIRMATION", "GET_FILES_KEY_CONFIRMATION", "RESOLVE_FILES_KEY_CONFIRMATION", "PROFILE_SETTINGS_GET", "PROFILE_SETTINGS_SAVE", "PROFILE_SETTINGS_REMOVE", "PROFILE_SETTINGS_BIND_LEGACY", "GET_PROVIDER_APPROVAL", "RESOLVE_PROVIDER_APPROVAL"].includes((message as any).type)) {
    return false;
  }

  // Handle async response
  ;(async () => {
    try {
      switch (message.type) {
        case 'WALLET_IDENTITIES_SAVE':
        case 'WALLET_IDENTITIES_READ':
        case 'WALLET_IDENTITIES_REVIEW':
        case 'WALLET_IDENTITIES_CONFIRM':
        case 'WALLET_IDENTITIES_CANCEL':
        case 'WALLET_IDENTITIES_EXPORT': {
          if(!isWalletIdentityPage(sender,chrome.runtime.id,chrome.runtime.getURL('src/wallet-identities.html')))throw new Error('wallet_ui_required')
          const expectedFields=message.type==='WALLET_IDENTITIES_SAVE'?['expected_revision','identities','type']:message.type==='WALLET_IDENTITIES_REVIEW'?['file','password','type']:message.type==='WALLET_IDENTITIES_CONFIRM'?['token','type']:message.type==='WALLET_IDENTITIES_EXPORT'?['password','type']:['type']
          if(Object.keys(message).sort().join(',')!==expectedFields.sort().join(','))throw new Error('invalid_request')
          const result=await custodyOperations.run(async()=>{
            switch(message.type){
              case 'WALLET_IDENTITIES_READ':return walletIdentities.read()
              case 'WALLET_IDENTITIES_SAVE':return walletIdentities.saveIdentities(message.identities,message.expected_revision)
              case 'WALLET_IDENTITIES_REVIEW':return walletIdentities.reviewImport(message.file,message.password)
              case 'WALLET_IDENTITIES_CONFIRM':return walletIdentities.confirmImport(message.token)
              case 'WALLET_IDENTITIES_CANCEL':walletIdentities.cancel();return {}
              case 'WALLET_IDENTITIES_EXPORT':return {file:await walletIdentities.exportFile(message.password)}
            }
          })
          sendResponse({ok:true,...result});break
        }
        case 'GET_MEMBERSHIP_CONFIRMATION': {
          assertConfirmationSender(sender, message.requestId)
          const summary = membershipConfirmationBroker.claimPendingSummary(message.requestId)
          if (!summary) throw new Error('membership confirmation is unavailable')
          sendResponse({ ok: true, summary })
          break
        }
        case 'RESOLVE_MEMBERSHIP_CONFIRMATION': {
          assertConfirmationSender(sender, message.requestId)
          if (!membershipConfirmationBroker.resolve(message.requestId, message.approved === true)) {
            throw new Error('membership confirmation is unavailable')
          }
          sendResponse({ ok: true })
          break
        }
        case 'OPEN_MEMBERSHIP_FLOW': throw new Error('Use the document-bound membership provider API')
        case 'CUSTODY_GET_STATE': {
          const embeddingOrigin = message.requestId
            ? requireMembershipFlow(sender, message.requestId).origin
            : undefined
          const custody = await custodyOperations.run(async () => {
            const state = await custodyState.getState()
            return {
              state,
              chainAccounts: state.unlocked ? durableChainAccounts() : [],
            }
          })
          sendResponse({
            ok: true,
            ...custody,
            ...(embeddingOrigin ? { embeddingOrigin } : {}),
          })
          break
        }
        case 'CUSTODY_CREATE':
          sendResponse({
            ok: true,
            state: await custodyOperations.run(async () => {
              const created = await custodyState.create(message.passphrase, Date.now())
              await membershipState.clear()
              await zenithMembershipState.clear()
              await providerProfilesRuntime.store.clearIdentity()
              return created
            }),
          })
          break
        case 'CUSTODY_UNLOCK':
          sendResponse({
            ok: true,
            state: await custodyOperations.run(() => custodyState.unlock(message.passphrase)),
          })
          break
        case 'CUSTODY_LOCK': {
          const state = await custodyOperations.run(async () => {
            await custodyState.lock()
            return custodyState.getState()
          })
          sendResponse({ ok: true, state })
          break
        }
        case 'CUSTODY_EXPORT':
          sendResponse({
            ok: true,
            ...await custodyOperations.run(() => recovery.exportWallet(message.passphrase)),
          })
          break
        case 'CUSTODY_IMPORT': {
          const result = await custodyOperations.run(async () => {
            // Session and local storage cannot commit atomically. Clear old identity-bound
            // authority first so no failure can carry it onto a replacement key.
            await sessionState.clearIdentityAuthorizations()
            await membershipState.clear()
            await zenithMembershipState.clear()
              await providerProfilesRuntime.store.clearIdentity()
            const imported = await recovery.importWallet(message.contents, message.passphrase, {
              replaceExisting: message.replaceExisting,
            })
            return { ...imported, state: await custodyState.getState() }
          })
          sendResponse({ ok: true, ...result })
          break
        }
        case 'GET_STATE': {
          const state = await sessionState.getState()
          sendResponse({ ok: true, state })
          break
        }
        case 'BEGIN_MEMBERSHIP_FLOW': throw new Error('Choose a membership profile in Wallet settings and use the document-bound provider API')
        case 'SETUP': {
          const result = await sessionState.setup()
          const state = await sessionState.getState()
          sendResponse({ ok: true, result, state })
          break
        }
        case 'UNLOCK': {
          await sessionState.unlock()
          const state = await sessionState.getState()
          sendResponse({ ok: true, state })
          break
        }
        case 'LOCK': {
          await sessionState.lock()
          const state = await sessionState.getState()
          sendResponse({ ok: true, state })
          break
        }
        case 'APPROVE_ORIGIN': {
          if (!message.origin) throw new Error('origin required')
          const state = await custodyOperations.run(async () => {
            await sessionState.approveOrigin(message.origin)
            return sessionState.getState()
          })
          sendResponse({ ok: true, state })
          break
        }
        case 'REVOKE_ORIGIN': {
          invalidateCustodyApprovals()
          if (!message.origin) throw new Error('origin required')
          credentialPresentationRuntime.invalidate()
          registrationRuntime.invalidate()
          filesKeyRuntime.invalidate()
          const state = await custodyOperations.run(async () => {
            await sessionState.revokeOrigin(message.origin)
            return sessionState.getState()
          })
          sendResponse({ ok: true, state })
          break
        }
        case 'BIND_MEMBERSHIP': {
          const { membership, state } = await custodyOperations.run(async () => {
            const custody = await custodyState.getState()
            if (!custody.setupComplete || !custody.unlocked || !custody.publicKey) {
              throw new Error('Wallet must be set up and unlocked before binding membership')
            }
            if (
              message.config.expectation.application.ownerPublicKey.toLowerCase()
                !== custody.publicKey
            ) {
              throw new Error('Castalia membership owner key does not match this wallet')
            }
            const membership = await fetchCastaliaMembership(message.config)
            await sessionState.bindMembership(message.config)
            return { membership, state: await sessionState.getState() }
          })
          sendResponse({ ok: true, membership, state })
          break
        }
        case 'UNBIND_MEMBERSHIP': {
          const state = await custodyOperations.run(async () => {
            const current = await sessionState.getState()
            if (!current.unlocked) {
              throw new Error('Wallet must be unlocked before unbinding membership')
            }
            await sessionState.unbindMembership()
            await membershipState.clear()
            await zenithMembershipState.clear()
            return sessionState.getState()
          })
          sendResponse({ ok: true, state })
          break
        }
        default:
          sendResponse({ ok: false, error: 'unknown popup message type' })
      }
    } catch (error: any) {
      sendResponse({ ok: false, error: error?.message || String(error) })
    }
  })()

  return true // Important: keep the message channel open for async sendResponse
})

console.log('[CastaliaWallet SW] Service worker loaded (Wave 3 popup messaging + session reset active)')

// === Provider Request Listener (content-script → SW) — the missing runtime glue for actual browser calls ===

type ContentScriptProviderRequest = {
  type: 'CASTALIA_PROVIDER_REQUEST';
  id: string;
  method: string;
  payload: unknown;
  computedOrigin: string;
  pageSuppliedOrigin?: string;
};

chrome.runtime.onMessage.addListener((
  message: ContentScriptProviderRequest,
  sender: any,
  sendResponse: (response?: any) => void
) => {
  if (message.type !== 'CASTALIA_PROVIDER_REQUEST') {
    return false; // not for us
  }

  (async () => {
    try {
      if (message.method === 'castalia.wallet.getCapabilities') {
        sendResponse({ id: message.id, ok: true, result: NEUTRAL_CAPABILITIES }); return
      }
      if (message.method === 'castalia.wallet.isAvailable') {
        sendResponse({ id: message.id, ok: true, result: true })
        return
      }

      const result = await custodyOperations.run(async () => {
        const state = await getCurrentExtensionStateForProvider();

        if (!state) {
          return { ok: false as const, error: 'Wallet not set up or locked for this session' }
        }

        let legacyTrust: ZenithMembershipTrustPolicyV1 | undefined
        if (message.method === 'castalia.wallet.getMembership') {
          const selected = await providerProfilesRuntime.legacy(message.computedOrigin,state.signingIdentity.publicKeyRawHex)
          state.zenithMembershipCredential = selected.credential as ZenithMembershipCredentialV3
          legacyTrust = {schema:'castalia.zenith-membership-trust-policy.v1',version:1,roots:selected.profile.profile.membership!.roots}
        }
        return handleProviderRequest({
          method: message.method,
          payload: message.payload,
          computedOrigin: message.computedOrigin,
          pageSuppliedOrigin: message.pageSuppliedOrigin,
          state,
        }, {
          confirmMembershipPresentation: summary => membershipConfirmationBroker.confirm(summary),
          zenithTrustPolicy: legacyTrust,
        })
      })

      sendResponse({
        id: message.id,
        ...result,
      });
    } catch (error: any) {
      sendResponse({
        id: message.id,
        ok: false,
        error: error?.message || 'Internal error in provider handler'
      });
    }
  })();

  return true; // async response
});

console.log('[CastaliaWallet SW] Provider request listener active (content-script bridge ready)');
}
