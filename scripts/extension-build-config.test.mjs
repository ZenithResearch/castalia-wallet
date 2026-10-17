import assert from 'node:assert/strict'
import test from 'node:test'
import {
  FIXTURE_ZENITH_ISSUER_KEY_ID,
  FIXTURE_ZENITH_ISSUER_PUBLIC_KEY,
  normalizeZenithIssuerKeyId,
  normalizeZenithIssuerPublicKey,
  normalizeZenithMembershipIssuerUrl,
  productionZenithMembershipConfig,
  zenithIssuerHostPermission,
} from './extension-build-config.mjs'

test('normalizes exact HTTPS and loopback Zenith issuer origins', () => {
  assert.equal(
    normalizeZenithMembershipIssuerUrl('https://membership.zenith-research.ca/'),
    'https://membership.zenith-research.ca',
  )
  assert.equal(
    normalizeZenithMembershipIssuerUrl('http://127.0.0.1:3002'),
    'http://127.0.0.1:3002',
  )
})

test('rejects ambiguous or insecure Zenith issuer configuration', () => {
  for (const value of [
    'http://membership.zenith-research.ca',
    'https://user:secret@membership.zenith-research.ca',
    'https://membership.zenith-research.ca/api',
    'https://membership.zenith-research.ca?network=other',
    'https://membership.zenith-research.ca/#fragment',
  ]) assert.throws(() => normalizeZenithMembershipIssuerUrl(value))
  assert.throws(() => normalizeZenithIssuerKeyId('UPPERCASE'))
  assert.throws(() => normalizeZenithIssuerPublicKey('not-a-key'))
})

test('production packaging requires HTTPS, exact trust, and grants one origin', () => {
  const config = productionZenithMembershipConfig({
    issuerUrl: 'https://membership.zenith-research.ca',
    issuerKeyId: 'zenith-membership-issuer-2026-01',
    issuerPublicKey: '11'.repeat(32),
  })
  assert.deepEqual(config, {
    issuerUrl: 'https://membership.zenith-research.ca',
    issuerKeyId: 'zenith-membership-issuer-2026-01',
    issuerPublicKey: '11'.repeat(32),
  })
  assert.equal(
    zenithIssuerHostPermission(config.issuerUrl),
    'https://membership.zenith-research.ca/*',
  )
  assert.throws(() => productionZenithMembershipConfig({
    ...config,
    issuerUrl: 'http://127.0.0.1:3002',
  }))
  assert.throws(() => productionZenithMembershipConfig({
    ...config,
    issuerKeyId: FIXTURE_ZENITH_ISSUER_KEY_ID,
    issuerPublicKey: FIXTURE_ZENITH_ISSUER_PUBLIC_KEY,
  }), /test fixture/)
})
