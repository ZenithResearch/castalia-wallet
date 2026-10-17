import assert from 'node:assert/strict'
import test from 'node:test'
import { generateKeyPairSync, sign } from 'node:crypto'
import { createRegistrationManifest, registrationManifestDigest, verifySignedRegistration, ORGANIZATION_CLASS } from '@castalia/filesystem/registration'
import { createRegistrationHandler, createRegistrationReplayStore } from '../src/registration.ts'

async function fixture(mode: 'legacy-v1'|'proposal-v2' = 'legacy-v1', verifyMembership = async () => {}) {
  const keys = generateKeyPairSync('ed25519')
  const key = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
  const manifest = await createRegistrationManifest({ entityClass: ORGANIZATION_CLASS, creatorMemberKey: key, genesisNonce: '01'.repeat(32), initialWorkspaceId: '02'.repeat(32), displayName: 'New Organization' })
  const request = { manifest, consent: { requestId: 'registration-request-1', origin: 'https://castalia.example', audience: 'https://castalia.example', nonce: '03'.repeat(32), issuedAtMs: 1_000, expiresAtMs: 61_000, manifestDigest: await registrationManifestDigest(manifest) } }
  let epoch = 1, current = true, now = 2_000, approved = true, unlocked = true, signs = 0, confirms = 0
  let onConfirm = async () => {}, onState = async () => {}, onReserve = async () => {}, onTab = async () => {}, onSign = async () => {}
  const state = { memberKey: key, approvedOrigins: new Set([request.consent.origin]), signBytes: async (bytes: Uint8Array) => { signs++; const result = sign(null, bytes, keys.privateKey).toString('base64'); await onSign(); return result } }
  const stored: Record<string, unknown> = {}
  const replay = createRegistrationReplayStore({ get: async () => structuredClone(stored.value), set: async value => { stored.value = structuredClone(value) } })
  const handler = createRegistrationHandler({
    runCustody: async operation => operation(), getState: async () => { await onState(); return unlocked ? state : null }, epoch: () => epoch, nowMs: () => now,
    currentOrigin: async () => { await onTab(); return request.consent.origin }, isCurrent: () => current,
    verifyMembership, reserve: async (consent, owner) => { await replay.reserve(consent, owner, now); await onReserve() },
    confirm: async summary => { confirms++; assert.equal(summary.manifest.displayName, 'New Organization'); await onConfirm(); return approved },
  }, mode)
  return { request, handler, stored, key, replay, stats: () => ({ signs, confirms }), set: (values: any) => { if ('epoch' in values) epoch = values.epoch; if ('current' in values) current = values.current; if ('now' in values) now = values.now; if ('approved' in values) approved = values.approved; if ('unlocked' in values) unlocked = values.unlocked; if (values.onConfirm) onConfirm = values.onConfirm; if (values.onState) onState = values.onState; if (values.onReserve) onReserve = values.onReserve; if (values.onTab) onTab = values.onTab; if (values.onSign) onSign = values.onSign; if (values.revoke) state.approvedOrigins.clear() } }
}

test('registration signs shared canonical bytes with existing Ed25519 custody', async () => {
  const f = await fixture(); const proof = await f.handler(f.request, f.request.consent.origin)
  assert.equal((await verifySignedRegistration(proof)).signerMemberKey, f.key)
  assert.deepEqual(f.stats(), { signs: 1, confirms: 1 })
  await assert.rejects(f.handler(f.request, f.request.consent.origin), /replay/)
})

test('registration rejects sender origin, audience, digest and creator substitution before confirmation', async () => {
  for (const change of [ (r: any) => { r.consent.origin = 'https://evil.example' }, (r: any) => { r.consent.audience = 'https://evil.example' }, (r: any) => { r.consent.manifestDigest = '00'.repeat(32) }, (r: any) => { r.manifest.controllerMemberKey = '00'.repeat(32) } ]) {
    const f = await fixture(); const r = structuredClone(f.request); change(r)
    await assert.rejects(f.handler(r, f.request.consent.origin)); assert.equal(f.stats().signs, 0); assert.equal(f.stats().confirms, 0)
  }
})

for (const scenario of ['denied', 'expired', 'locked', 'epoch', 'disposed', 'revoked']) test(`registration rejects ${scenario} after confirmation`, async () => {
  const f = await fixture()
  f.set({ onConfirm: async () => { f.set(scenario === 'denied' ? { approved: false } : scenario === 'expired' ? { now: 61_000 } : scenario === 'locked' ? { unlocked: false } : scenario === 'epoch' ? { epoch: 2 } : scenario === 'disposed' ? { current: false } : { revoke: true }) } })
  await assert.rejects(f.handler(f.request, f.request.consent.origin)); assert.equal(f.stats().signs, 0)
  f.set({ approved: true, now: 2_000, unlocked: true, current: true })
  await assert.rejects(f.handler(f.request, f.request.consent.origin))
})

for (const boundary of ['onState', 'onReserve', 'onTab']) test(`registration rechecks epoch after ${boundary}`, async () => {
  const f = await fixture(); f.set({ [boundary]: async () => f.set({ epoch: 2 }) })
  await assert.rejects(f.handler(f.request, f.request.consent.origin)); assert.equal(f.stats().signs, 0)
})

test('registration withholds result if disposal occurs during asynchronous signing', async () => {
  const f = await fixture(); f.set({ onSign: async () => f.set({ current: false }) })
  await assert.rejects(f.handler(f.request, f.request.consent.origin)); assert.equal(f.stats().signs, 1)
})

test('consent replay storage survives handler restart, rejects nonce reuse and fails before signing on storage failure', async () => {
  const f = await fixture(); await f.handler(f.request, f.request.consent.origin)
  const second = createRegistrationReplayStore({ get: async () => f.stored.value, set: async () => {} })
  await assert.rejects(second.reserve(f.request.consent, f.key, 2_000), /replay/)
  await assert.rejects(second.reserve({ ...f.request.consent, requestId: 'registration-request-2' }, f.key, 2_000), /replay/)
  const broken = createRegistrationReplayStore({ get: async () => undefined, set: async () => { throw new Error('quota') } })
  await assert.rejects(broken.reserve(f.request.consent, f.key, 2_000), /quota/)
})

test('concurrent consent reservations admit exactly one and quota/clock rollback fail closed', async () => {
  const f = await fixture(); const results = await Promise.allSettled([f.replay.reserve(f.request.consent, f.key, 2_000), f.replay.reserve(f.request.consent, f.key, 2_000)])
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1)
  await assert.rejects(f.replay.reserve({ ...f.request.consent, requestId: 'another-request-id', nonce: '04'.repeat(32) }, f.key, 1_999), /clock/)
  for (let i = 1; i < 256; i++) await f.replay.reserve({ ...f.request.consent, requestId: `registration-request-${i + 1}`, nonce: i.toString(16).padStart(64, '0') }, f.key, 2_000)
  await assert.rejects(f.replay.reserve({ ...f.request.consent, requestId: 'registration-request-999', nonce: 'ff'.repeat(32) }, f.key, 2_000), /capacity/)
})

test('registration snapshots caller input before human confirmation', async () => {
  const f = await fixture(); const original = structuredClone(f.request.manifest)
  f.set({ onConfirm: async () => { (f.request.manifest as any) = { ...original, displayName: 'Swapped name', controllerMemberKey: 'aa'.repeat(32) }; f.request.consent.manifestDigest = 'ff'.repeat(32) } })
  assert.deepEqual((await f.handler(f.request, f.request.consent.origin)).manifest, original)
})

test('corrupt replay state fails closed', async () => {
  const f = await fixture()
  for (const value of [null, { version: 2, observedAtMs: 0, records: [] }, { version: 1, observedAtMs: 0, records: [null] }]) {
    const replay = createRegistrationReplayStore({ get: async () => value, set: async () => { assert.fail('corrupt state must not be overwritten') } })
    await assert.rejects(replay.reserve(f.request.consent, f.key, 2_000), /Invalid/)
  }
})

 test('v2 signs the same manifest without assigning receiving-service eligibility to Wallet',async()=>{const deny=async()=>{throw Error('local eligibility is not receiver policy')};const legacy=await fixture('legacy-v1',deny);await assert.rejects(legacy.handler(legacy.request,legacy.request.consent.origin),/eligibility/);const neutral=await fixture('proposal-v2',deny);const signed=await neutral.handler(neutral.request,neutral.request.consent.origin);assert.deepEqual(signed.manifest,neutral.request.manifest);assert.equal((await verifySignedRegistration(signed)).signerMemberKey,neutral.key)})
