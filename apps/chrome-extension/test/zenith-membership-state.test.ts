import assert from 'node:assert/strict'
import test from 'node:test'
import type { ZenithMembershipCredentialV3 } from '@castalia-wallet/zenith-membership'
import {
  ZENITH_MEMBERSHIP_STORAGE_KEY,
  createZenithMembershipState,
} from '../src/state/zenith-membership-state.ts'

const CREDENTIAL = {
  schema: 'castalia.zenith-membership-credential.v3',
  version: 3,
  membershipId: 'b2409aad97015e17749442377f14acd6ccd9ce804661738e4aa7e860d554d8a9',
  ownerPublicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  status: 'active',
  issuerId: 'zenith-research',
  issuerKeyId: 'zenith-membership-issuer-fixture-ed25519-1',
  signatureSuite: 'Ed25519',
  issuerSignature: 'b4Sf_uSYTxfhQUaF_Arq44IxYNByxKsrUOgmXCB4dEYbfAlJ6to50ZeY_qBbvZYibHO6A4JrIERZ1DBDxSkRBA',
} as const satisfies ZenithMembershipCredentialV3

function harness(initial: Record<string, unknown> = {}) {
  const values = new Map(Object.entries(initial))
  const state = createZenithMembershipState({
    async get(key) { return { [key]: values.get(key) } },
    async set(input) {
      for (const [key, value] of Object.entries(input)) values.set(key, value)
    },
    async remove(key) { values.delete(key) },
  })
  return { state, values }
}

test('persists the exact public v3 credential under its versioned storage key', async () => {
  const { state, values } = harness({ 'castalia-permissionless-membership-v2': { preserved: true } })
  await state.set(CREDENTIAL)
  assert.deepEqual(await state.get(), CREDENTIAL)
  assert.deepEqual(values.get(ZENITH_MEMBERSHIP_STORAGE_KEY), CREDENTIAL)
  assert.deepEqual(values.get('castalia-permissionless-membership-v2'), { preserved: true })
})

test('rejects unknown fields and treats corrupt persisted membership as absent', async () => {
  const { state } = harness({
    [ZENITH_MEMBERSHIP_STORAGE_KEY]: { ...CREDENTIAL, role: 'administrator' },
  })
  assert.equal(await state.get(), null)
  await assert.rejects(
    () => state.set({ ...CREDENTIAL, issuerSignature: 'not-a-signature' }),
    /invalid Zenith membership credential/,
  )
})

test('clears only the v3 public credential', async () => {
  const { state, values } = harness({
    [ZENITH_MEMBERSHIP_STORAGE_KEY]: CREDENTIAL,
    'castalia-permissionless-membership-v2': { preserved: true },
  })
  await state.clear()
  assert.equal(values.has(ZENITH_MEMBERSHIP_STORAGE_KEY), false)
  assert.equal(values.has('castalia-permissionless-membership-v2'), true)
})
