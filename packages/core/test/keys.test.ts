import assert from 'node:assert/strict'
import test from 'node:test'
import { buildChallengePayload } from '../src/challenge.ts'
import {
  assertCanSign,
  createDevWalletKeyPair,
  signChallengeWithDevKey,
  verifyChallengeSignature,
} from '../src/keys.ts'

const challenge = buildChallengePayload({
  nonce: 'nonce-123',
  origin: 'http://localhost:5173',
  audience: 'zenith-review-sdk',
  operation: 'castalia.wallet.signChallenge',
  issuedAt: '2026-05-28T20:00:00.000Z',
  expiresAt: '2026-05-28T20:05:00.000Z',
})

test('createDevWalletKeyPair creates a disposable key pair without secret export by default', () => {
  const keyPair = createDevWalletKeyPair()

  assert.equal(keyPair.kind, 'disposable-dev')
  assert.match(keyPair.publicKey, /^-----BEGIN PUBLIC KEY-----/)
  assert.equal(keyPair.privateKeyExtractable, false)
})

test('signChallengeWithDevKey signs and verifies a challenge', () => {
  const keyPair = createDevWalletKeyPair()
  const signature = signChallengeWithDevKey(keyPair, challenge)

  assert.equal(verifyChallengeSignature({
    publicKey: keyPair.publicKey,
    challenge,
    signature,
  }), true)
})

test('verifyChallengeSignature rejects tampered challenge data', () => {
  const keyPair = createDevWalletKeyPair()
  const signature = signChallengeWithDevKey(keyPair, challenge)

  const tampered = { ...challenge, nonce: 'other-nonce' }

  assert.equal(verifyChallengeSignature({
    publicKey: keyPair.publicKey,
    challenge: tampered,
    signature,
  }), false)
})

test('public key bytes cannot be used as a valid signing result', () => {
  const keyPair = createDevWalletKeyPair()

  assert.equal(verifyChallengeSignature({
    publicKey: keyPair.publicKey,
    challenge,
    signature: Buffer.from(keyPair.publicKey).toString('base64'),
  }), false)
})

test('assertCanSign rejects setup incomplete state', () => {
  assert.throws(() => assertCanSign({ setupComplete: false, unlocked: true }), /setup/)
})

test('assertCanSign rejects locked state', () => {
  assert.throws(() => assertCanSign({ setupComplete: true, unlocked: false }), /locked/)
})

test('assertCanSign accepts setup complete and unlocked state', () => {
  assert.doesNotThrow(() => assertCanSign({ setupComplete: true, unlocked: true }))
})
