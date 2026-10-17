import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { buildChallengePayload } from '../../../packages/core/src/challenge.ts'
import {
  CASTALIA_WALLET_PROVIDER,
  CASTALIA_WALLET_REQUEST,
  createCastaliaWalletProvider,
} from '../src/provider.ts'
import {
  CASTALIA_WALLET_RESPONSE,
  normalizeMembershipFlowReady,
  normalizePageMessage,
} from '../src/content-script.ts'

const ZENITH_MEMBERSHIP = {
  schema: 'castalia.zenith-membership-credential.v3',
  version: 3,
  membershipId: 'b2409aad97015e17749442377f14acd6ccd9ce804661738e4aa7e860d554d8a9',
  ownerPublicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  status: 'active',
  issuerId: 'zenith-research',
  issuerKeyId: 'zenith-membership-issuer-fixture-ed25519-1',
  signatureSuite: 'Ed25519',
  issuerSignature: 'b4Sf_uSYTxfhQUaF_Arq44IxYNByxKsrUOgmXCB4dEYbfAlJ6to50ZeY_qBbvZYibHO6A4JrIERZ1DBDxSkRBA',
} as const

test('provider exposes the Checkpoint A wallet methods and request envelope', async () => {
  const calls: unknown[] = []
  const provider = createCastaliaWalletProvider(async (request) => {
    calls.push(request)
    if (request.method === 'castalia.wallet.isAvailable') return true
    if (request.method === 'castalia.wallet.openMembershipFlow') return { state: 'opened' as const }
    if (request.method === 'castalia.wallet.getSubject') {
      return { subjectId: 'did:castalia:dev:1', publicKey: 'pub', dreggOwnerPublicKey: '64'.repeat(32), walletKind: 'castalia-dregg' }
    }
    if (request.method === 'castalia.wallet.getMembership') {
      return ZENITH_MEMBERSHIP
    }
    return {
      subject: { subjectId: 'did:castalia:dev:1', publicKey: 'pub', dreggOwnerPublicKey: '64'.repeat(32), walletKind: 'castalia-dregg' },
      challenge: request.payload,
      signature: 'sig',
      signatureAlgorithm: 'node-ed25519',
    }
  })

  const challenge = buildChallengePayload({
    nonce: 'nonce-123',
    origin: 'https://app.example',
    audience: 'zenith-review-sdk',
    operation: 'castalia.wallet.signChallenge',
    issuedAt: '2030-05-28T12:00:00.000Z',
    expiresAt: '2030-05-28T12:05:00.000Z',
  })

  assert.equal(await provider.isAvailable(), true)
  assert.deepEqual(await provider.openMembershipFlow(), { state: 'opened' })
  assert.equal((await provider.getSubject()).subjectId, 'did:castalia:dev:1')
  assert.equal((await provider.getSubject()).dreggOwnerPublicKey, '64'.repeat(32))
  assert.equal((await provider.getMembership()).status, 'active')
  assert.equal((await provider.signChallenge(challenge)).signature, 'sig')
  assert.equal(calls.length, 6)
  assert.deepEqual(calls[0], { type: CASTALIA_WALLET_REQUEST, id: 'castalia-1', method: 'castalia.wallet.isAvailable', payload: {} })
  assert.deepEqual(calls[1], { type: CASTALIA_WALLET_REQUEST, id: 'castalia-2', method: 'castalia.wallet.openMembershipFlow', payload: {} })
  assert.deepEqual(calls[2], { type: CASTALIA_WALLET_REQUEST, id: 'castalia-3', method: 'castalia.wallet.getSubject', payload: {} })
  assert.deepEqual(calls[3], { type: CASTALIA_WALLET_REQUEST, id: 'castalia-4', method: 'castalia.wallet.getSubject', payload: {} })
  assert.deepEqual(calls[4], { type: CASTALIA_WALLET_REQUEST, id: 'castalia-5', method: 'castalia.wallet.getMembership', payload: {} })
  assert.deepEqual(calls[5], { type: CASTALIA_WALLET_REQUEST, id: 'castalia-6', method: 'castalia.wallet.signChallenge', payload: challenge })
})

test('Chrome-owned membership flow forwards only an exact verified membership summary', () => {
  assert.deepEqual(normalizeMembershipFlowReady({
    type: 'CASTALIA_MEMBERSHIP_FLOW_READY',
    membership: ZENITH_MEMBERSHIP,
  }), ZENITH_MEMBERSHIP)
  assert.equal(normalizeMembershipFlowReady({
    type: 'CASTALIA_MEMBERSHIP_FLOW_READY',
    membership: { ...ZENITH_MEMBERSHIP, status: 'pending' },
  }), null)
  assert.equal(normalizeMembershipFlowReady({
    type: 'CASTALIA_MEMBERSHIP_FLOW_READY',
    membership: { ...ZENITH_MEMBERSHIP, membershipId: 'not-a-membership-id' },
  }), null)
  assert.equal(normalizeMembershipFlowReady({
    type: 'CASTALIA_MEMBERSHIP_FLOW_READY',
    membership: { ...ZENITH_MEMBERSHIP, applicationState: 'approved' },
  }), null)
})

test('provider install name is stable', () => {
  assert.equal(CASTALIA_WALLET_PROVIDER, 'castaliaWallet')
})

test('current Castalia Web status contract collapses transport denial to locked', async () => {
  const provider = createCastaliaWalletProvider(async () => {
    throw new Error('Wallet not set up or locked for this session')
  })
  assert.deepEqual(await provider.getStatus(), { state: 'locked' })
})

test('provider implements current Castalia Web onboarding contract over the canonical signer', async () => {
  const calls: Array<{ method: string; payload: unknown }> = []
  const provider = createCastaliaWalletProvider(async (request) => {
    calls.push(request)
    if (request.method === 'castalia.wallet.getSubject') {
      return {
        subjectId: 'did:castalia:dev:1',
        publicKey: 'pub',
        dreggOwnerPublicKey: '64'.repeat(32),
        walletKind: 'castalia-dregg',
      }
    }
    return {
      subject: {
        subjectId: 'did:castalia:dev:1',
        publicKey: 'pub',
        dreggOwnerPublicKey: '64'.repeat(32),
        walletKind: 'castalia-dregg',
      },
      challenge: request.payload,
      signature: 'sig',
      signatureAlgorithm: 'node-ed25519',
    }
  })

  assert.equal(provider.kind, 'castalia.wallet-provider')
  assert.equal(provider.version, '1')
  assert.equal(provider.membershipJoinProtocol, 'castalia.zenith-membership.v3')
  assert.deepEqual(await provider.getStatus(), {
    state: 'ready',
    publicIdentity: 'did:castalia:dev:1',
  })

  const presentation = await provider.createAuthenticationPresentation({
    version: 'castalia.wallet-onboarding.v1',
    requestId: 'request-1',
    origin: 'https://app.example',
    audience: 'castalia-web',
    operation: 'authenticate',
    nonce: 'nonce-1',
    issuedAtMs: 1_904_006_400_000,
    expiresAtMs: 1_904_006_460_000,
  })
  assert.equal(presentation.format, 'castalia.wallet-presentation.v1')
  assert.equal(JSON.parse(presentation.payload).signature, 'sig')
  assert.deepEqual(calls.map(({ method }) => method), [
    'castalia.wallet.getSubject',
    'castalia.wallet.signChallenge',
  ])
  assert.deepEqual(calls[1]?.payload, {
    domain: 'castalia-wallet',
    version: 1,
    nonce: 'nonce-1',
    origin: 'https://app.example',
    audience: 'castalia-web',
    operation: 'authenticate',
    issuedAt: '2030-05-03T02:40:00.000Z',
    expiresAt: '2030-05-03T02:41:00.000Z',
  })
})

test('content script normalizes only Castalia request envelopes and computes origin', () => {
  const normalized = normalizePageMessage({
    message: {
      type: CASTALIA_WALLET_REQUEST,
      id: 'request-1',
      method: 'castalia.wallet.signChallenge',
      payload: { origin: 'https://evil.example' },
    },
    sourceOrigin: 'https://app.example',
  })

  assert.deepEqual(normalized, {
    id: 'request-1',
    method: 'castalia.wallet.signChallenge',
    payload: { origin: 'https://evil.example' },
    computedOrigin: 'https://app.example',
  })
})

test('content script ignores non-Castalia envelopes', () => {
  assert.equal(normalizePageMessage({ message: { type: 'other' }, sourceOrigin: 'https://app.example' }), null)
})

test('content script response envelope is distinct from request envelope', () => {
  assert.equal(CASTALIA_WALLET_RESPONSE, 'castalia:wallet:response')
})
