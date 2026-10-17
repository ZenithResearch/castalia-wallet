import type { PermissionlessMembershipBindingV2 } from '@castalia-wallet/dregg-adapter'

declare const chrome: any

const STORAGE_KEY = 'castalia-permissionless-membership-v2'
const HEX_32 = /^[0-9a-f]{64}$/

function validatedBinding(value: unknown): PermissionlessMembershipBindingV2 | null {
  if (!value || typeof value !== 'object') return null
  const binding = value as Partial<PermissionlessMembershipBindingV2>
  if (
    binding.version !== 2
    || typeof binding.nodeUrl !== 'string'
    || typeof binding.cellId !== 'string' || !HEX_32.test(binding.cellId)
    || typeof binding.ownerPublicKey !== 'string' || !HEX_32.test(binding.ownerPublicKey)
    || typeof binding.factoryId !== 'string' || !HEX_32.test(binding.factoryId)
    || typeof binding.programId !== 'string' || !HEX_32.test(binding.programId)
    || typeof binding.stateCommitment !== 'string' || !HEX_32.test(binding.stateCommitment)
    || (binding.receiptHash !== null
      && (typeof binding.receiptHash !== 'string' || !HEX_32.test(binding.receiptHash)))
  ) return null
  return structuredClone(binding as PermissionlessMembershipBindingV2)
}

export const membershipState = {
  async get(): Promise<PermissionlessMembershipBindingV2 | null> {
    const result = await chrome.storage.local.get(STORAGE_KEY)
    return validatedBinding(result[STORAGE_KEY])
  },

  async set(binding: PermissionlessMembershipBindingV2): Promise<void> {
    const valid = validatedBinding(binding)
    if (!valid) throw new Error('Refusing to persist an invalid membership binding')
    await chrome.storage.local.set({ [STORAGE_KEY]: valid })
  },

  async clear(): Promise<void> {
    await chrome.storage.local.remove(STORAGE_KEY)
  },
}
