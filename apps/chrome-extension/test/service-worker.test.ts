import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { buildChallengePayload } from '../../../packages/core/src/challenge.ts'
import { verifyChallengeSignature } from '../../../packages/core/src/keys.ts'
import {
  canonicalMembershipEnrollmentChallengeBytes,
  commitMemberApplication,
  verifyMembershipPresentationV2,
} from '../../../packages/core/src/membership-presentation-v2.ts'
import { createDevWalletKeyPairBrowser, signBytesWithDevKeyBrowser, signChallengeWithDevKeyBrowser } from '../src/crypto-browser.ts'
import {
  approvedWebOriginFromSender,
  createCustodyOperationQueue,
  handleProviderRequest,
  isExactMembershipConfirmationSender,
  isExactMembershipFlowSender,
  type ExtensionWalletState,
} from '../src/service-worker.ts'
import {
  CASTALIA_PERMISSIONLESS_FACTORY_ID,
  CASTALIA_PERMISSIONLESS_PROGRAM_ID,
  CASTALIA_PERMISSIONLESS_TOKEN_ID,
  commitCastaliaMemberApplication,
  derivePermissionlessMembershipCellId,
  type CastaliaMemberApplicationV1,
} from '../../../packages/dregg-adapter/src/index.ts'
import type {
  ZenithMembershipCredentialV3,
  ZenithMembershipTrustPolicyV1,
} from '../../../packages/zenith-membership/src/index.ts'

test('service-worker custody queue keeps import clearing and replacement mutation FIFO', async () => {
  const queue = createCustodyOperationQueue()
  const events: string[] = []
  let started!:()=>void
  const importStarted=new Promise<void>(resolve=>{started=resolve})
  let releaseClear!: () => void
  const clearBlocked = new Promise<void>((resolve) => { releaseClear = resolve })

  const importOperation = queue.run(async () => {
    events.push('import:clear:start');started()
    await clearBlocked
    events.push('import:clear:done')
    events.push('import:mutation')
  })
  const laterCreate = queue.run(async () => {
    events.push('create:mutation')
  })

  await importStarted
  assert.deepEqual(events, ['import:clear:start'])
  releaseClear()
  await Promise.all([importOperation, laterCreate])
  assert.deepEqual(events, [
    'import:clear:start',
    'import:clear:done',
    'import:mutation',
    'create:mutation',
  ])
})

const keyPair = await createDevWalletKeyPairBrowser()
const dreggHybridIdentity = {
  version: 1 as const,
  signatureSuite: 'Ed25519+ML-DSA-65' as const,
  ed25519PublicKey: keyPair.publicKeyRawHex,
  mlDsa65PublicKey: 'A'.repeat(2_603),
  mlDsa65PublicKeyCommitment: 'ab'.repeat(32),
  derivation: 'dregg.hybrid-from-ed25519-seed.v1' as const,
}
const signingIdentity = {
  publicKey: keyPair.publicKey,
  publicKeyRawHex: keyPair.publicKeyRawHex,
  dreggHybridIdentity,
  signChallenge: (request: Parameters<typeof signChallengeWithDevKeyBrowser>[1]) =>
    signChallengeWithDevKeyBrowser(keyPair, request),
  signBytes: (message: Uint8Array) => signBytesWithDevKeyBrowser(message),
}

const PRESENTATION_VECTOR = JSON.parse(readFileSync(
  new URL('../../../docs/vectors/castalia-wallet-membership-presentation-v2.vector.json', import.meta.url),
  'utf8',
))

const ZENITH_VECTOR = JSON.parse(readFileSync(
  new URL('../../../docs/vectors/castalia-zenith-membership-v3.vector.json', import.meta.url),
  'utf8',
)) as {
  issuerPublicKey: string
  issuerKeyId: string
  credential: ZenithMembershipCredentialV3
}

const ZENITH_POLICY = {
  schema: 'castalia.zenith-membership-trust-policy.v1',
  version: 1,
  roots: [{
    issuerId: 'zenith-research',
    keyId: ZENITH_VECTOR.issuerKeyId,
    signatureSuite: 'Ed25519',
    publicKey: ZENITH_VECTOR.issuerPublicKey,
  }],
} as const satisfies ZenithMembershipTrustPolicyV1

test('membership setup approves only the displayed initiating tab origin', () => {
  assert.equal(
    approvedWebOriginFromSender(
      'https://castalia.example/start',
      'https://castalia.example',
    ),
    'https://castalia.example',
  )
  assert.equal(
    approvedWebOriginFromSender(
      'http://127.0.0.1:4173/start',
      'http://127.0.0.1:4173',
    ),
    'http://127.0.0.1:4173',
  )
  assert.throws(() => approvedWebOriginFromSender(
    'https://evil.example/start',
    'https://castalia.example',
  ), /changed before approval/)
  assert.throws(() => approvedWebOriginFromSender(
    'http://castalia.example/start',
    'http://castalia.example',
  ), /must use HTTPS/)
  assert.throws(() => approvedWebOriginFromSender(
    'chrome-extension://spoof/start',
    'chrome-extension://spoof',
  ))
  assert.throws(() => approvedWebOriginFromSender(undefined, undefined))
})
test('confirmation messages accept only the exact extension page and request id', () => {
  const page = 'chrome-extension://wallet-id/src/confirmation.html'
  assert.equal(isExactMembershipConfirmationSender(`${page}?request=req-1`, page, 'req-1'), true)
  for (const sender of [
    `${page}?request=req-2`,
    `${page}?request=req-1&extra=true`,
    `${page}?request=req-1#spoof`,
    'chrome-extension://evil-id/src/confirmation.html?request=req-1',
    'https://wallet-id/src/confirmation.html?request=req-1',
    undefined,
  ]) assert.equal(isExactMembershipConfirmationSender(sender, page, 'req-1'), false)
})

test('membership flow messages accept only the exact Chrome-owned popup and request id', () => {
  const page = 'chrome-extension://wallet-id/src/onboarding.html'
  assert.equal(isExactMembershipFlowSender(`${page}?request=flow-1`, page, 'flow-1'), true)
  for (const sender of [
    `${page}?request=flow-2`,
    `${page}?request=flow-1&extra=true`,
    `${page}?request=flow-1#spoof`,
    'chrome-extension://evil-id/src/onboarding.html?request=flow-1',
    'https://wallet-id/src/onboarding.html?request=flow-1',
    undefined,
  ]) assert.equal(isExactMembershipFlowSender(sender, page, 'flow-1'), false)
})

const APPLICATION: CastaliaMemberApplicationV1 = {
  factoryId: '61'.repeat(32),
  programId: '62'.repeat(32),
  officialDreggCellId: '63'.repeat(32),
  ownerPublicKey: keyPair.publicKeyRawHex,
  applicationKind: 7,
  applicationVersion: 1,
  applicationNonce: 9,
  membershipClass: 2,
  jurisdictionCode: 840,
  applicationFlags: 5,
  createdAt: 1_700_000_000,
}
const COMMITMENT = commitCastaliaMemberApplication(APPLICATION)

function readyState(overrides: Partial<ExtensionWalletState> = {}): ExtensionWalletState {
  return {
    setupComplete: true,
    unlocked: true,
    approvedOrigins: new Set(['https://app.example']),
    signingIdentity,
    subjectId: 'did:castalia:dev:subject-1',
    zenithMembershipCredential: null,
    permissionlessMembershipBinding: null,
    membershipConfig: {
      nodeUrl: 'http://127.0.0.1:8765',
      expectation: {
        cellId: '51'.repeat(32),
        authorityPublicKey: '41'.repeat(32),
        applicationCommitment: COMMITMENT,
        application: APPLICATION,
      },
    },
    ...overrides,
  }
}

test('returns only a reverified Zenith-signed v3 credential for its Member Key', async () => {
  const result = await handleProviderRequest({
    method: 'castalia.wallet.getMembership',
    payload: {},
    computedOrigin: 'https://app.example',
    state: readyState({
      signingIdentity: {
        ...signingIdentity,
        publicKeyRawHex: ZENITH_VECTOR.credential.ownerPublicKey,
      },
      zenithMembershipCredential: ZENITH_VECTOR.credential,
      permissionlessMembershipBinding: null,
      membershipConfig: null,
    }),
  }, {
    zenithTrustPolicy: ZENITH_POLICY,
    fetchImpl: async () => { throw new Error('stored v3 verification must not use the network') },
  })

  assert.deepEqual(result, { ok: true, result: ZENITH_VECTOR.credential })
})

test('rejects a persisted Zenith credential with a modified issuer signature', async () => {
  const result = await handleProviderRequest({
    method: 'castalia.wallet.getMembership',
    payload: {},
    computedOrigin: 'https://app.example',
    state: readyState({
      signingIdentity: {
        ...signingIdentity,
        publicKeyRawHex: ZENITH_VECTOR.credential.ownerPublicKey,
      },
      zenithMembershipCredential: {
        ...ZENITH_VECTOR.credential,
        issuerSignature: 'A'.repeat(86),
      },
      permissionlessMembershipBinding: null,
      membershipConfig: null,
    }),
  }, { zenithTrustPolicy: ZENITH_POLICY })

  assert.equal(result.ok, false)
  assert.match(result.error, /signature is invalid/)
})

function membershipCell() {
  const field = (value: bigint) => value.toString(16).padStart(64, '0')
  const commitment = Buffer.from(COMMITMENT, 'hex')
  const commitmentFields = Array.from({ length: 4 }, (_, limb) =>
    field(commitment.subarray(limb * 8, limb * 8 + 8).readBigUInt64LE()))
  return {
    id: '51'.repeat(32),
    found: true,
    balance: 3_000,
    nonce: 1,
    public_key: '41'.repeat(32),
    token_id: '52'.repeat(32),
    program_kind: 'Cases',
    fields: [
      field(3_552_571_879_494_730_051n), field(1n), field(7n), field(1n),
      field(9n), field(2n), field(840n), field(5n),
      ...commitmentFields,
      field(1n), field(1n), field(1_700_000_000n), field(1_700_000_001n),
    ],
    last_receipt_hash: '53'.repeat(32),
  }
}

function challenge(origin = 'https://app.example') {
  return buildChallengePayload({
    nonce: 'nonce-123',
    origin,
    audience: 'zenith-review-sdk',
    operation: 'castalia.wallet.signChallenge',
    issuedAt: '2030-05-28T12:00:00.000Z',
    expiresAt: '2030-05-28T12:05:00.000Z',
  })
}

test('reports availability without origin approval or setup', async () => {
  const result = await handleProviderRequest({
    method: 'castalia.wallet.isAvailable',
    payload: {},
    computedOrigin: 'https://unknown.example',
    state: readyState({ setupComplete: false, unlocked: false, approvedOrigins: new Set() }),
  })

  assert.deepEqual(result, { ok: true, result: true })
})

test('returns subject only for setup, unlocked, approved origins', async () => {
  const result = await handleProviderRequest({
    method: 'castalia.wallet.getSubject',
    payload: {},
    computedOrigin: 'https://app.example',
    state: readyState(),
  })

  assert.equal(result.ok, true)
  assert.equal(result.result.subjectId, 'did:castalia:dev:subject-1')
  assert.equal(result.result.publicKey, keyPair.publicKey)
  assert.equal(result.result.dreggOwnerPublicKey, keyPair.publicKeyRawHex)
  assert.deepEqual(result.result.dreggHybridIdentity, dreggHybridIdentity)
  assert.equal(result.result.walletKind, 'castalia-dregg')
})

test('does not expose a legacy authority-owned membership through the active v3 provider', async () => {
  const requested: string[] = []
  const result = await handleProviderRequest({
    method: 'castalia.wallet.getMembership',
    payload: {
      nodeUrl: 'https://evil.example',
      expectation: { cellId: 'ff'.repeat(32) },
    },
    computedOrigin: 'https://app.example',
    state: readyState(),
  }, {
    fetchImpl: async (input) => {
      requested.push(String(input))
      return new Response(JSON.stringify(membershipCell()), { status: 200 })
    },
  })

  assert.equal(result.ok, false)
  assert.match(result.error, /Zenith membership is not bound/i)
  assert.deepEqual(requested, [])
})

test('preserves but does not reinterpret a durable Dregg v2 binding as Zenith v3', async () => {
  const owner = keyPair.publicKeyRawHex
  const cellId = derivePermissionlessMembershipCellId(owner)
  const stateCommitment = '76'.repeat(32)
  const field = (value: bigint) => value.toString(16).padStart(64, '0')
  const state = readyState({
    membershipConfig: null,
    permissionlessMembershipBinding: {
      version: 2,
      nodeUrl: 'http://127.0.0.1:8420',
      cellId,
      ownerPublicKey: owner,
      factoryId: CASTALIA_PERMISSIONLESS_FACTORY_ID,
      programId: CASTALIA_PERMISSIONLESS_PROGRAM_ID,
      stateCommitment,
      receiptHash: '77'.repeat(32),
    },
  })
  const result = await handleProviderRequest({
    method: 'castalia.wallet.getMembership',
    payload: {},
    computedOrigin: 'https://app.example',
    state,
  }, {
    fetchImpl: async () => new Response(JSON.stringify({
      id: cellId,
      found: true,
      balance: 0,
      nonce: 0,
      public_key: owner,
      token_id: CASTALIA_PERMISSIONLESS_TOKEN_ID,
      program_kind: 'Cases',
      program: {
        kind: 'Cases',
        cases: [{
          guard: { kind: 'Always' },
          constraints: Array.from({ length: 16 }, (_, index) => ({
            kind: 'Immutable',
            index,
          })),
        }],
      },
      capability_count: 0,
      has_delegate: false,
      has_delegation: false,
      fields: [
        field(3_624_629_473_532_657_987n), field(2n), field(1n),
        ...Array.from({ length: 9 }, () => field(0n)),
        field(1n), field(0n), field(0n), field(0n),
      ],
      state_commitment: stateCommitment,
      last_receipt_hash: null,
    }), { status: 200 }),
  })

  assert.equal(result.ok, false)
  assert.match(result.error, /Zenith membership is not bound/i)
})

test('fails closed when no wallet-held membership binding exists', async () => {
  const result = await handleProviderRequest({
    method: 'castalia.wallet.getMembership',
    payload: {},
    computedOrigin: 'https://app.example',
    state: readyState({ membershipConfig: null }),
  })

  assert.equal(result.ok, false)
  assert.match(result.error, /Zenith membership is not bound/i)
})

test('rejects a membership committed to a different wallet owner key', async () => {
  const result = await handleProviderRequest({
    method: 'castalia.wallet.getMembership',
    payload: {},
    computedOrigin: 'https://app.example',
    state: readyState({
      zenithMembershipCredential: ZENITH_VECTOR.credential,
      permissionlessMembershipBinding: null,
      membershipConfig: null,
    }),
  }, { zenithTrustPolicy: ZENITH_POLICY })

  assert.equal(result.ok, false)
  assert.match(result.error, /owner does not match/i)
})

test('creates an enrollment-v2 possession presentation over exact canonical bytes', async () => {
  const application = {
    ...structuredClone(PRESENTATION_VECTOR.application),
    ownerPublicKey: keyPair.publicKeyRawHex,
  }
  const challenge = {
    ...structuredClone(PRESENTATION_VECTOR.challenge),
    origin: 'https://app.example',
    ownerPublicKey: keyPair.publicKeyRawHex,
    applicationCommitment: commitMemberApplication(application),
  }
  const original = structuredClone(challenge)
  const signed: Uint8Array[] = []
  const confirmations: unknown[] = []
  const state = readyState({
    signingIdentity: {
      ...signingIdentity,
      async signBytes(message) {
        signed.push(Uint8Array.from(message))
        return signBytesWithDevKeyBrowser(message)
      },
    },
  })
  const result = await handleProviderRequest({
    method: 'castalia.wallet.requestMembershipPresentation',
    payload: { application, challenge },
    computedOrigin: 'https://app.example',
    state,
  }, {
    nowMs: () => challenge.issuedAt,
    confirmMembershipPresentation: async summary => {
      confirmations.push(summary)
      assert.equal(signed.length, 0, 'custody must not sign before confirmation')
      return true
    },
  })

  assert.equal(result.ok, true)
  if (
    !result.ok
    || typeof result.result !== 'object'
    || result.result === null
    || !('schema' in result.result)
  ) throw new Error('expected v2 presentation')
  assert.deepEqual(result.result.challenge, original)
  assert.deepEqual(challenge, original, 'provider must not mutate the server challenge')
  assert.equal(signed.length, 1)
  assert.deepEqual(confirmations, [{
    origin: 'https://app.example',
    memberKeyFingerprint: `${keyPair.publicKeyRawHex.slice(0, 12)}…${keyPair.publicKeyRawHex.slice(-12)}`,
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt,
  }])
  assert.deepEqual(signed[0], canonicalMembershipEnrollmentChallengeBytes(challenge, application))
  await verifyMembershipPresentationV2(result.result, application, {
    expectedOrigin: 'https://app.example',
    expectedAudience: challenge.audience,
    nowMs: challenge.issuedAt,
  })
})

test('enrollment-v2 confirmation that completes after expiry never signs', async () => {
  const application = {
    ...structuredClone(PRESENTATION_VECTOR.application),
    ownerPublicKey: keyPair.publicKeyRawHex,
  }
  const challenge = {
    ...structuredClone(PRESENTATION_VECTOR.challenge),
    origin: 'https://app.example',
    ownerPublicKey: keyPair.publicKeyRawHex,
    applicationCommitment: commitMemberApplication(application),
  }
  let nowMs = challenge.issuedAt
  let signingCalls = 0
  const result = await handleProviderRequest({
    method: 'castalia.wallet.requestMembershipPresentation',
    payload: { application, challenge },
    computedOrigin: 'https://app.example',
    state: readyState({ signingIdentity: {
      ...signingIdentity,
      async signBytes() { signingCalls += 1; return 'not-used' },
    } }),
  }, {
    nowMs: () => nowMs,
    confirmMembershipPresentation: async () => {
      nowMs = challenge.expiresAt + 1
      return true
    },
  })
  assert.equal(result.ok, false)
  if (result.ok) throw new Error('expected expired confirmation refusal')
  assert.match(result.error, /time|expired/i)
  assert.equal(signingCalls, 0)
})

test('enrollment-v2 confirmation with excessive future skew never signs', async () => {
  const application = {
    ...structuredClone(PRESENTATION_VECTOR.application),
    ownerPublicKey: keyPair.publicKeyRawHex,
  }
  const challenge = {
    ...structuredClone(PRESENTATION_VECTOR.challenge),
    origin: 'https://app.example',
    ownerPublicKey: keyPair.publicKeyRawHex,
    applicationCommitment: commitMemberApplication(application),
  }
  let nowMs = challenge.issuedAt
  let signingCalls = 0
  const result = await handleProviderRequest({
    method: 'castalia.wallet.requestMembershipPresentation',
    payload: { application, challenge },
    computedOrigin: 'https://app.example',
    state: readyState({ signingIdentity: {
      ...signingIdentity,
      async signBytes() { signingCalls += 1; return 'not-used' },
    } }),
  }, {
    nowMs: () => nowMs,
    confirmMembershipPresentation: async () => {
      nowMs = challenge.issuedAt - 5_001
      return true
    },
  })
  assert.equal(result.ok, false)
  if (result.ok) throw new Error('expected future-skew refusal')
  assert.match(result.error, /time|future/i)
  assert.equal(signingCalls, 0)
})

test('denied enrollment-v2 confirmation never signs', async () => {
  const application = {
    ...structuredClone(PRESENTATION_VECTOR.application),
    ownerPublicKey: keyPair.publicKeyRawHex,
  }
  const challenge = {
    ...structuredClone(PRESENTATION_VECTOR.challenge),
    origin: 'https://app.example',
    ownerPublicKey: keyPair.publicKeyRawHex,
    applicationCommitment: commitMemberApplication(application),
  }
  let signingCalls = 0
  const result = await handleProviderRequest({
    method: 'castalia.wallet.requestMembershipPresentation',
    payload: { application, challenge },
    computedOrigin: 'https://app.example',
    state: readyState({ signingIdentity: {
      ...signingIdentity,
      async signBytes() { signingCalls += 1; return 'not-used' },
    } }),
  }, {
    nowMs: () => challenge.issuedAt,
    confirmMembershipPresentation: async () => false,
  })
  assert.equal(result.ok, false)
  if (result.ok) throw new Error('expected confirmation denial')
  assert.match(result.error, /denied/i)
  assert.equal(signingCalls, 0)
})

test('rejects enrollment-v2 trusted-field mismatches before signing', async () => {
  const application = {
    ...structuredClone(PRESENTATION_VECTOR.application),
    ownerPublicKey: keyPair.publicKeyRawHex,
  }
  const challenge = {
    ...structuredClone(PRESENTATION_VECTOR.challenge),
    origin: 'https://app.example',
    ownerPublicKey: keyPair.publicKeyRawHex,
    applicationCommitment: commitMemberApplication(application),
  }
  for (const mutation of [
    (value: typeof challenge) => { value.origin = 'https://evil.example' },
    (value: typeof challenge) => { value.ownerPublicKey = 'ff'.repeat(32) },
    (value: typeof challenge) => { value.applicationCommitment = 'ee'.repeat(32) },
  ]) {
    let signingCalls = 0
    const candidate = structuredClone(challenge)
    mutation(candidate)
    const result = await handleProviderRequest({
      method: 'castalia.wallet.requestMembershipPresentation',
      payload: { application, challenge: candidate },
      computedOrigin: 'https://app.example',
      state: readyState({
        signingIdentity: {
          ...signingIdentity,
          async signBytes() { signingCalls += 1; return 'not-used' },
        },
      }),
    })
    assert.equal(result.ok, false)
    assert.equal(signingCalls, 0)
  }
})

test('signs a challenge and returns a verifiable signature presentation', async () => {
  const request = challenge()
  const result = await handleProviderRequest({
    method: 'castalia.wallet.signChallenge',
    payload: request,
    computedOrigin: 'https://app.example',
    state: readyState(),
  })

  assert.equal(result.ok, true)
  assert.equal(result.result.subject.publicKey, keyPair.publicKey)
  assert.deepEqual(result.result.challenge, request)
  assert.equal(result.result.signatureAlgorithm, 'ed25519')
  assert.equal(verifyChallengeSignature({
    publicKey: keyPair.publicKey,
    challenge: request,
    signature: result.result.signature,
  }), true)
})

test('provider presentation is signed by the state Member Key identity', async () => {
  const signed: unknown[] = []
  const memberIdentity = {
    publicKey: 'member-key-spki',
    publicKeyRawHex: '7a'.repeat(32),
    async signChallenge(request: unknown) {
      signed.push(request)
      return 'member-key-signature'
    },
  }
  const request = challenge()
  const result = await handleProviderRequest({
    method: 'castalia.wallet.signChallenge',
    payload: request,
    computedOrigin: 'https://app.example',
    state: readyState({ signingIdentity: memberIdentity, membershipConfig: null }),
  })

  assert.equal(result.ok, true)
  assert.equal(result.result.subject.dreggOwnerPublicKey, memberIdentity.publicKeyRawHex)
  assert.equal(result.result.signature, 'member-key-signature')
  assert.equal(result.result.signatureAlgorithm, 'ed25519')
  assert.deepEqual(signed, [request])
})

test('rejects a challenge whose embedded origin differs from computed origin', async () => {
  const result = await handleProviderRequest({
    method: 'castalia.wallet.signChallenge',
    payload: challenge('https://evil.example'),
    computedOrigin: 'https://app.example',
    state: readyState(),
  })

  assert.equal(result.ok, false)
  assert.match(result.error, /origin mismatch/)
})

test('fails closed when setup, unlock, or origin approval is missing', async () => {
  for (const state of [
    readyState({ setupComplete: false }),
    readyState({ unlocked: false }),
    readyState({ approvedOrigins: new Set() }),
  ]) {
    const result = await handleProviderRequest({
      method: 'castalia.wallet.signChallenge',
      payload: challenge(),
      computedOrigin: 'https://app.example',
      state,
    })

    assert.equal(result.ok, false)
  }
}
)
