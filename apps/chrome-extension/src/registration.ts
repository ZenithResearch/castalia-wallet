import {
  parseRegistrationConsent, registrationSigningBytes, validateRegistrationRequest,
  type RegistrationConsentV1, type RegistrationManifestV1, type SignedRegistrationManifestV1,
} from '@castalia/filesystem/registration'

export type RegistrationConfirmationSummary = {
  origin: string
  signerMemberKey: string
  manifest: Readonly<RegistrationManifestV1>
  manifestDigest: string
  expiresAt: number
}
export type RegistrationSigningState = {
  memberKey: string
  approvedOrigins: ReadonlySet<string>
  signBytes(bytes: Uint8Array): Promise<string>
}

type Dependencies = {
  runCustody<T>(operation: () => Promise<T>): Promise<T>
  getState(): Promise<RegistrationSigningState | null>
  epoch(): number
  nowMs(): number
  currentOrigin(): Promise<string>
  isCurrent(): boolean
  verifyMembership(memberKey: string, origin: string): Promise<void>
  reserve(consent: RegistrationConsentV1, memberKey: string): Promise<void>
  confirm(summary: RegistrationConfirmationSummary): Promise<boolean>
}

/** A signature is a proposal, not registration acceptance or file access authority. */
export function createRegistrationHandler(deps: Dependencies, mode: 'legacy-v1' | 'proposal-v2' = 'legacy-v1') {
  return async (input: unknown, origin: string): Promise<SignedRegistrationManifestV1> => {
    const epoch = deps.epoch()
    const startedAt = deps.nowMs()
    const raw = structuredClone(input)
    let expiresAtMs = Number.MAX_SAFE_INTEGER
    const assertCurrent = () => {
      const now = deps.nowMs()
      if (!deps.isCurrent() || deps.epoch() !== epoch) throw new Error('Registration session changed or disposed')
      if (!Number.isSafeInteger(now) || now < startedAt || now >= expiresAtMs) throw new Error('Registration consent expired or clock changed')
    }
    const readState = async () => {
      assertCurrent()
      const state = await deps.getState()
      assertCurrent()
      if (!state || !state.approvedOrigins.has(origin)) throw new Error('Wallet locked or registration origin not approved')
      return state
    }
    const initial = await deps.runCustody(async () => {
      const state = await readState()
      const request = await validateRegistrationRequest(raw, { origin, audience: origin, nowMs: deps.nowMs() })
      expiresAtMs = request.consent.expiresAtMs
      assertCurrent()
      if (request.manifest.revision === 0) {
        if (request.manifest.creatorMemberKey !== state.memberKey || request.manifest.controllerMemberKey !== state.memberKey) throw new Error('Registration creator must be this Member Key')
        if (mode === 'legacy-v1') await deps.verifyMembership(state.memberKey, origin)
        assertCurrent()
      }
      if (await deps.currentOrigin() !== origin) throw new Error('Registration tab origin changed')
      assertCurrent()
      await deps.reserve(request.consent, state.memberKey)
      assertCurrent()
      return { request, memberKey: state.memberKey }
    })
    assertCurrent()
    const approved = await deps.confirm({ origin, signerMemberKey: initial.memberKey, manifest: initial.request.manifest, manifestDigest: initial.request.consent.manifestDigest, expiresAt: Math.floor(expiresAtMs / 1_000) })
    assertCurrent()
    if (!approved) throw new Error('Registration signing denied')
    return deps.runCustody(async () => {
      let state = await readState()
      if (state.memberKey !== initial.memberKey) throw new Error('Registration Member Key changed')
      if (await deps.currentOrigin() !== origin) throw new Error('Registration tab origin changed')
      assertCurrent()
      // Re-read revocable approval after the tab lookup, then make no asynchronous
      // calls between the final check and the custody signer invocation.
      state = await readState()
      if (state.memberKey !== initial.memberKey) throw new Error('Registration Member Key changed')
      const signature = await state.signBytes(registrationSigningBytes(initial.request.manifest))
      assertCurrent()
      if (!/^[A-Za-z0-9+/]{86}==$/.test(signature) || atob(signature).length !== 64) throw new Error('Invalid registration signature')
      return {
        schema: 'castalia.signed-namespace-registration.v1', manifest: initial.request.manifest,
        signerMemberKey: initial.memberKey, signatureSuite: 'Ed25519',
        signature: signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
      }
    })
  }
}

type ReplayRecord = { owner: string; origin: string; requestId: string; nonce: string; expiresAtMs: number }
type ReplayState = { version: 1; observedAtMs: number; records: ReplayRecord[] }
/** Session-persistent one-shot consent reservations; denial and crashes consume consent. */
export function createRegistrationReplayStore(storage: { get(): Promise<unknown>; set(value: ReplayState): Promise<void> }) {
  let tail: Promise<unknown> = Promise.resolve()
  return {
    reserve(consentValue: RegistrationConsentV1, owner: string, nowMs: number): Promise<void> {
      const operation = tail.then(async () => {
        const consent = parseRegistrationConsent(consentValue)
        if (!Number.isSafeInteger(nowMs) || nowMs < consent.issuedAtMs || nowMs >= consent.expiresAtMs) throw new Error('Registration consent expired')
        const raw = await storage.get()
        let prior: ReplayState = { version: 1, observedAtMs: nowMs, records: [] }
        if (raw !== undefined) {
          const value = raw as ReplayState
          if (!value || value.version !== 1 || !Number.isSafeInteger(value.observedAtMs) || !Array.isArray(value.records) || value.records.length > 256
            || value.records.some(r => !r || typeof r.owner !== 'string' || typeof r.origin !== 'string' || typeof r.requestId !== 'string' || typeof r.nonce !== 'string' || !Number.isSafeInteger(r.expiresAtMs))) throw new Error('Invalid registration replay storage')
          prior = value
        }
        if (nowMs < prior.observedAtMs) throw new Error('Registration clock moved backwards')
        const records = prior.records.filter(r => r.expiresAtMs > nowMs)
        if (records.some(r => r.owner === owner && r.origin === consent.origin && (r.requestId === consent.requestId || r.nonce === consent.nonce))) throw new Error('Registration consent replay')
        if (records.length >= 256) throw new Error('Registration consent capacity reached')
        records.push({ owner, origin: consent.origin, requestId: consent.requestId, nonce: consent.nonce, expiresAtMs: consent.expiresAtMs })
        await storage.set({ version: 1, observedAtMs: nowMs, records })
      })
      tail = operation.catch(() => {})
      return operation
    },
  }
}
