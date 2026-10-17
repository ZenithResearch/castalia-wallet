import assert from 'node:assert/strict'
import test from 'node:test'
import { validateProviderRequest } from '../src/bridge.ts'

test('allows provider availability without origin approval', () => {
  const result = validateProviderRequest({
    method: 'castalia.wallet.isAvailable',
    payload: {},
    computedOrigin: 'https://unknown.example',
    pageSuppliedOrigin: 'https://evil.example',
    walletSetupComplete: false,
    walletUnlocked: false,
    approvedOrigins: new Set(),
  })

  assert.equal(result.ok, true)
})

test('rejects unknown methods', () => {
  const result = validateProviderRequest({
    method: 'castalia.wallet.exportPrivateKey',
    payload: {},
    computedOrigin: 'https://app.example',
    walletSetupComplete: true,
    walletUnlocked: true,
    approvedOrigins: new Set(['https://app.example']),
  })

  assert.equal(result.ok, false)
  assert.match(result.error, /unknown method/)
})

test('ignores page supplied origin when checking approval', () => {
  const result = validateProviderRequest({
    method: 'castalia.wallet.signChallenge',
    payload: { nonce: 'n' },
    computedOrigin: 'https://evil.example',
    pageSuppliedOrigin: 'https://app.example',
    walletSetupComplete: true,
    walletUnlocked: true,
    approvedOrigins: new Set(['https://app.example']),
  })

  assert.equal(result.ok, false)
  assert.match(result.error, /origin not approved/)
})

test('requires setup before signing', () => {
  const result = validateProviderRequest({
    method: 'castalia.wallet.signChallenge',
    payload: { nonce: 'n' },
    computedOrigin: 'https://app.example',
    walletSetupComplete: false,
    walletUnlocked: true,
    approvedOrigins: new Set(['https://app.example']),
  })

  assert.equal(result.ok, false)
  assert.match(result.error, /setup/)
})

test('requires unlocked wallet before signing', () => {
  const result = validateProviderRequest({
    method: 'castalia.wallet.signChallenge',
    payload: { nonce: 'n' },
    computedOrigin: 'https://app.example',
    walletSetupComplete: true,
    walletUnlocked: false,
    approvedOrigins: new Set(['https://app.example']),
  })

  assert.equal(result.ok, false)
  assert.match(result.error, /locked/)
})

test('fails closed for proof and private paths', () => {
  for (const method of ['castalia.wallet.requestCapability', 'castalia.wallet.privateRpc']) {
    const result = validateProviderRequest({
      method,
      payload: {},
      computedOrigin: 'https://app.example',
      walletSetupComplete: true,
      walletUnlocked: true,
      approvedOrigins: new Set(['https://app.example']),
    })

    assert.equal(result.ok, false)
    assert.match(result.error, /unsupported/)
  }
})

test('gates privacy revealing reads behind origin approval', () => {
  for (const method of ['castalia.wallet.getMembership', 'castalia.wallet.listCapabilities', 'castalia.wallet.federationStatus', 'castalia.wallet.storageQuota']) {
    const result = validateProviderRequest({
      method,
      payload: {},
      computedOrigin: 'https://unknown.example',
      walletSetupComplete: true,
      walletUnlocked: true,
      approvedOrigins: new Set(),
    })

    assert.equal(result.ok, false)
    assert.match(result.error, /origin not approved/)
  }
})
