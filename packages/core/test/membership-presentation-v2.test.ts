import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import {
  canonicalMemberApplicationBytes,
  canonicalMembershipEnrollmentChallengeBytes,
  commitMemberApplication,
  parseMembershipPresentationV2,
  verifyMembershipPresentationV2,
} from '../src/membership-presentation-v2.ts'

const vectorUrl = new URL('../../../docs/vectors/castalia-wallet-membership-presentation-v2.vector.json', import.meta.url)
const vectorBytes = readFileSync(vectorUrl)
const vector = JSON.parse(vectorBytes.toString('utf8'))

test('vector checksum and checked-in one-field tamper artifacts are authoritative', async () => {
  const sidecar = readFileSync(new URL('./castalia-wallet-membership-presentation-v2.vector.json.sha256', vectorUrl), 'utf8').trim()
  assert.equal(sidecar.split(/\s+/)[0], createHash('sha256').update(vectorBytes).digest('hex'))
  assert.deepEqual(vector.tamperedCases.map((entry: any) => entry.name), [
    'challenge-audience-one-field-tamper',
    'application-membership-class-one-field-tamper',
  ])
  for (const entry of vector.tamperedCases) {
    await assert.rejects(() => verifyMembershipPresentationV2(entry.presentation, entry.application, {
      expectedOrigin: vector.challenge.origin,
      expectedAudience: vector.challenge.audience,
      nowMs: vector.challenge.issuedAt,
    }), entry.name)
  }
})

test('reproduces the independent v2 application and challenge bytes', () => {
  assert.equal(Buffer.from(canonicalMemberApplicationBytes(vector.application)).toString('hex'), vector.expected.applicationTranscriptHex)
  assert.equal(commitMemberApplication(vector.application), vector.expected.applicationCommitment)
  const bytes = canonicalMembershipEnrollmentChallengeBytes(vector.challenge, vector.application)
  assert.equal(Buffer.from(bytes).toString('hex'), vector.expected.challengeTranscriptHex)
  const domain = new TextEncoder().encode('castalia/wallet-membership-enrollment/v2')
  assert.equal(bytes[domain.length], 0, 'domain separator must be one literal NUL byte')
})

test('strict presentation parsing and verification reject every trusted-field mutation', async () => {
  const presentation = parseMembershipPresentationV2(JSON.stringify(vector.presentation))
  await verifyMembershipPresentationV2(presentation, vector.application, {
    expectedOrigin: vector.challenge.origin,
    expectedAudience: vector.challenge.audience,
    nowMs: vector.challenge.issuedAt,
  })
  for (const field of ['challengeId','nonce','origin','audience','operation','ownerPublicKey','applicationCommitment','signatureSuite','issuedAt','expiresAt']) {
    const tampered = structuredClone(vector.presentation)
    const value = tampered.challenge[field]
    tampered.challenge[field] = typeof value === 'number' ? value + 1 : `${value}x`
    await assert.rejects(() => verifyMembershipPresentationV2(tampered, vector.application, {
      expectedOrigin: vector.challenge.origin,
      expectedAudience: vector.challenge.audience,
      nowMs: vector.challenge.issuedAt,
    }))
  }
  assert.throws(() => parseMembershipPresentationV2(JSON.stringify({ ...vector.presentation, unknown: true })))
  assert.throws(() => parseMembershipPresentationV2(
    JSON.stringify(vector.presentation).replace(
      '"schema":"castalia.wallet-membership-presentation.v2"',
      '"schema":"castalia.wallet-membership-presentation.v2","schema":"castalia.wallet-membership-presentation.v2"',
    ),
  ))
  for (const origin of ['https://castalia.example/', 'https://castalia.example.', 'https://[0:0::1]']) {
    const tampered = structuredClone(vector.presentation)
    tampered.challenge.origin = origin
    await assert.rejects(() => verifyMembershipPresentationV2(tampered, vector.application, {
      expectedOrigin: origin,
      expectedAudience: vector.challenge.audience,
      nowMs: vector.challenge.issuedAt,
    }))
  }
})
