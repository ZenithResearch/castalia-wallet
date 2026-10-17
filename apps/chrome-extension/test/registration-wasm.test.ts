import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { createRegistrationManifest, registrationManifestDigest, verifySignedRegistration, PERSON_CLASS } from '@castalia/filesystem/registration'
import { initSync, WasmWallet } from '../src/generated/castalia-wallet-core/bindings.js'
import { CASTALIA_WALLET_CORE_WASM } from '../src/generated/castalia-wallet-core/wasm-bytes.js'
import { createRegistrationHandler } from '../src/registration.ts'
initSync({ module: CASTALIA_WALLET_CORE_WASM })
test('actual WASM restored custody signs registration without altering identity or recovery bytes', async () => {
  const fixture = JSON.parse(readFileSync(new URL('../../../docs/contracts/castalia-wallet-custody-v1.vector.json', import.meta.url), 'utf8'))
  const wallet = new WasmWallet()
  try {
    wallet.unlock(new TextEncoder().encode(JSON.stringify(fixture.container)), fixture.inputs.passphraseUnicode)
    const key = wallet.publicKey(), origin = 'https://castalia.example'
    const manifest = await createRegistrationManifest({ entityClass: PERSON_CLASS, creatorMemberKey: key, genesisNonce: '00'.repeat(32), initialWorkspaceId: '01'.repeat(32), displayName: 'Personal' })
    const request = { manifest, consent: { requestId: 'actual-wasm-registration', origin, audience: origin, nonce: '02'.repeat(32), issuedAtMs: 1_000, expiresAtMs: 61_000, manifestDigest: await registrationManifestDigest(manifest) } }
    const handler = createRegistrationHandler({ runCustody: async fn => fn(), getState: async () => ({ memberKey: key, approvedOrigins: new Set([origin]), signBytes: async bytes => Buffer.from(wallet.sign(bytes)).toString('base64') }), epoch: () => 1, nowMs: () => 2_000, currentOrigin: async () => origin, isCurrent: () => true, verifyMembership: async () => {}, reserve: async () => {}, confirm: async () => true })
    const result = await handler(request, origin)
    assert.equal((await verifySignedRegistration(result)).signerMemberKey, key)
    assert.equal(wallet.publicKey(), key)
    wallet.lock(); await assert.rejects(handler(request, origin))
    wallet.unlock(new TextEncoder().encode(JSON.stringify(fixture.container)), fixture.inputs.passphraseUnicode)
    assert.equal(wallet.publicKey(), key)
  } finally { wallet.lock(); wallet.free() }
})
