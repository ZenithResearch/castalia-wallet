import assert from 'node:assert/strict'
import test from 'node:test'
import {
  buildChallengePayload,
  validateChallengePayload,
  type ChallengePayloadInput,
} from '../src/challenge.ts'

const baseInput: ChallengePayloadInput = {
  nonce: 'nonce-123',
  origin: 'http://localhost:5173',
  audience: 'zenith-review-sdk',
  operation: 'castalia.wallet.signChallenge',
  issuedAt: '2026-05-28T20:00:00.000Z',
  expiresAt: '2026-05-28T20:05:00.000Z',
}

test('buildChallengePayload preserves checkpoint A challenge fields', () => {
  const payload = buildChallengePayload(baseInput)

  assert.equal(payload.domain, 'castalia-wallet')
  assert.equal(payload.version, 1)
  assert.equal(payload.nonce, 'nonce-123')
  assert.equal(payload.origin, 'http://localhost:5173')
  assert.equal(payload.audience, 'zenith-review-sdk')
  assert.equal(payload.operation, 'castalia.wallet.signChallenge')
  assert.equal(payload.issuedAt, '2026-05-28T20:00:00.000Z')
  assert.equal(payload.expiresAt, '2026-05-28T20:05:00.000Z')
})

test('validateChallengePayload accepts a live well-formed payload', () => {
  const payload = buildChallengePayload(baseInput)

  assert.doesNotThrow(() => validateChallengePayload(payload, {
    now: '2026-05-28T20:01:00.000Z',
    expectedOrigin: 'http://localhost:5173',
    expectedAudience: 'zenith-review-sdk',
  }))
})

test('validateChallengePayload rejects missing nonce', () => {
  const payload = { ...buildChallengePayload(baseInput), nonce: '' }

  assert.throws(() => validateChallengePayload(payload, {
    now: '2026-05-28T20:01:00.000Z',
    expectedOrigin: 'http://localhost:5173',
    expectedAudience: 'zenith-review-sdk',
  }), /nonce/)
})

test('validateChallengePayload rejects expired challenges', () => {
  const payload = buildChallengePayload(baseInput)

  assert.throws(() => validateChallengePayload(payload, {
    now: '2026-05-28T20:06:00.000Z',
    expectedOrigin: 'http://localhost:5173',
    expectedAudience: 'zenith-review-sdk',
  }), /expired/)
})

test('validateChallengePayload rejects origin confusion', () => {
  const payload = buildChallengePayload(baseInput)

  assert.throws(() => validateChallengePayload(payload, {
    now: '2026-05-28T20:01:00.000Z',
    expectedOrigin: 'https://evil.example',
    expectedAudience: 'zenith-review-sdk',
  }), /origin/)
})

test('validateChallengePayload rejects audience confusion', () => {
  const payload = buildChallengePayload(baseInput)

  assert.throws(() => validateChallengePayload(payload, {
    now: '2026-05-28T20:01:00.000Z',
    expectedOrigin: 'http://localhost:5173',
    expectedAudience: 'other-sdk',
  }), /audience/)
})
