import {
  filesBase64url, filesDecodeKey, parseFilesConsent, parseFilesKeyEnvelope, validateFilesRequest,
  type FilesKeyBindingV1, type FilesKeyConsentV1, type FilesKeyEnvelopeV1,
  type FilesOperationV1, type FilesSignaturePresentationV1,
  type FilesServiceAuthBodyV1,
} from './files-key-contract.js'

export type FilesConfirmationSummary = {
  origin: string; operation: FilesOperationV1; memberKey: string; audience: string
  binding: FilesKeyBindingV1 | null; requestDigest: string; expiresAt: number
}
export type FilesSigningState = {
  memberKey: string; approvedOrigins: ReadonlySet<string>
  wrap(binding: FilesKeyBindingV1, key: Uint8Array): Promise<unknown>
  unwrap(binding: FilesKeyBindingV1, envelope: FilesKeyEnvelopeV1): Promise<Uint8Array>
  authenticate(body: FilesServiceAuthBodyV1, origin: string, nowMs: number): Promise<unknown>
}
export type FilesHandlerDependencies = {
  runCustody<T>(operation: () => Promise<T>): Promise<T>
  getState(): Promise<FilesSigningState | null>
  epoch(): number; nowMs(): number; currentOrigin(): Promise<string>; isCurrent(): boolean
  reserve(consent: FilesKeyConsentV1, memberKey: string): Promise<void>
  confirm(summary: FilesConfirmationSummary): Promise<boolean>
}
/** Only the scoped DEK may leave custody. Denial, disposal and changed authority fail closed. */
export function createFilesKeyHandler(deps: FilesHandlerDependencies) {
  return async (operation: FilesOperationV1, input: unknown, origin: string): Promise<FilesKeyEnvelopeV1 | { key: string } | FilesSignaturePresentationV1> => {
    const epoch = deps.epoch(), startedAt = deps.nowMs(), raw: unknown = structuredClone(input)
    let deadline = Number.MAX_SAFE_INTEGER
    const assertCurrent = () => {
      const now = deps.nowMs()
      if (!deps.isCurrent() || deps.epoch() !== epoch) throw new Error('Files custody session changed or disposed')
      if (!Number.isSafeInteger(now) || now < startedAt || now >= deadline) throw new Error('Files consent expired or clock changed')
    }
    const readState = async () => {
      assertCurrent(); const state = await deps.getState(); assertCurrent()
      if (!state || !state.approvedOrigins.has(origin)) throw new Error('Wallet locked or Files origin not approved')
      return state
    }
    const initial = await deps.runCustody(async () => {
      const state = await readState()
      const request = await validateFilesRequest(operation, raw, { origin, nowMs: deps.nowMs() })
      deadline = Math.min(request.consent.expiresAtMs, 'challenge' in request ? Date.parse(request.challenge.expiresAt) : Infinity)
      assertCurrent()
      if ('binding' in request && request.binding.ownerMemberKey !== state.memberKey) throw new Error('Files owner does not match this Member Key')
      if (await deps.currentOrigin() !== origin) throw new Error('Files tab origin changed')
      assertCurrent(); await deps.reserve(request.consent, state.memberKey); assertCurrent()
      return { request, memberKey: state.memberKey }
    })
    assertCurrent()
    const approved = await deps.confirm({ origin, operation, memberKey: initial.memberKey,
      audience: initial.request.consent.audience, binding: 'binding' in initial.request ? initial.request.binding : null,
      requestDigest: initial.request.consent.requestDigest, expiresAt: Math.floor(deadline / 1000) })
    assertCurrent(); if (!approved) throw new Error('Files custody request denied')
    return deps.runCustody(async () => {
      const request = await validateFilesRequest(operation, initial.request, { origin, nowMs: deps.nowMs() })
      assertCurrent()
      if (await deps.currentOrigin() !== origin) throw new Error('Files tab origin changed')
      const state = await readState()
      if (state.memberKey !== initial.memberKey) throw new Error('Files Member Key changed')
      // No await between final revocation/epoch checks and custody invocation.
      if ('key' in request) {
        const key = filesDecodeKey(request.key)
        try {
          const envelope = parseFilesKeyEnvelope(await state.wrap(request.binding, key)); assertCurrent()
          if (JSON.stringify(envelope.binding) !== JSON.stringify(request.binding)) throw new Error('Files envelope binding changed')
          return envelope
        } finally { key.fill(0) }
      }
      if ('envelope' in request) {
        const key = await state.unwrap(request.binding, request.envelope)
        try { assertCurrent(); if (key.length !== 32) throw new Error('Invalid Files data key'); return { key: filesBase64url(key) } }
        finally { key.fill(0) }
      }
      const result = await state.authenticate(request, origin, deps.nowMs()); assertCurrent()
      if (!record(result) || !record(result.subject) || typeof result.subject.subjectId !== 'string' || typeof result.subject.publicKey !== 'string' || result.subject.walletKind !== 'castalia-dregg' || typeof result.signature !== 'string' || result.signatureAlgorithm !== 'ed25519' || result.subject.dreggOwnerPublicKey !== initial.memberKey
        || JSON.stringify(result.challenge) !== JSON.stringify(request.challenge)) throw new Error('Invalid Files authentication result')
      filesDecodeKey(result.signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 64)
      return result as FilesSignaturePresentationV1
    })
  }
}

function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }

type ReplayRecord = { owner: string; origin: string; requestId: string; nonce: string; expiresAtMs: number }
type ReplayState = { version: 1; observedAtMs: number; records: ReplayRecord[] }
export function createFilesReplayStore(storage: { get(): Promise<unknown>; set(value: ReplayState): Promise<void> }) {
  let tail: Promise<unknown> = Promise.resolve()
  return { reserve(consentValue: FilesKeyConsentV1, owner: string, nowMs: number): Promise<void> {
    const task = tail.then(async () => {
      const consent = parseFilesConsent(consentValue)
      if (!/^[0-9a-f]{64}$/.test(owner) || !Number.isSafeInteger(nowMs) || nowMs < consent.issuedAtMs || nowMs >= consent.expiresAtMs) throw new Error('Invalid Files consent reservation')
      const raw = await storage.get()
      let prior: ReplayState = { version: 1, observedAtMs: nowMs, records: [] }
      if (raw !== undefined) {
        if (!record(raw) || Object.keys(raw).sort().join(',') !== 'observedAtMs,records,version' || raw.version !== 1
          || typeof raw.observedAtMs !== 'number' || !Number.isSafeInteger(raw.observedAtMs) || !Array.isArray(raw.records) || raw.records.length > 256) throw new Error('Invalid Files replay storage')
        const records: ReplayRecord[] = raw.records.map((item: unknown) => {
          if (!record(item) || Object.keys(item).sort().join(',') !== 'expiresAtMs,nonce,origin,owner,requestId'
            || typeof item.owner !== 'string' || !/^[0-9a-f]{64}$/.test(item.owner)
            || typeof item.origin !== 'string' || typeof item.requestId !== 'string' || !/^[A-Za-z0-9._~-]{1,128}$/.test(item.requestId)
            || typeof item.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(item.nonce)
            || typeof item.expiresAtMs !== 'number' || !Number.isSafeInteger(item.expiresAtMs)) throw new Error('Invalid Files replay storage')
          return { owner: item.owner, origin: item.origin, requestId: item.requestId, nonce: item.nonce, expiresAtMs: item.expiresAtMs }
        })
        prior = { version: 1, observedAtMs: raw.observedAtMs, records }
      }
      if (nowMs < prior.observedAtMs) throw new Error('Files clock moved backwards')
      const records = prior.records.filter(r => r.expiresAtMs > nowMs)
      if (records.some(r => r.owner === owner && r.origin === consent.origin && (r.requestId === consent.requestId || r.nonce === consent.nonce))) throw new Error('Files consent replay')
      if (records.length >= 256) throw new Error('Files consent capacity reached')
      records.push({ owner, origin: consent.origin, requestId: consent.requestId, nonce: consent.nonce, expiresAtMs: consent.expiresAtMs })
      await storage.set({ version: 1, observedAtMs: nowMs, records })
    })
    tail = task.catch(() => {}); return task
  } }
}
