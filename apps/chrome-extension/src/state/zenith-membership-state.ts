import {
  parseZenithMembershipCredential,
  type ZenithMembershipCredentialV3,
} from '@castalia-wallet/zenith-membership'

declare const chrome: any

export const ZENITH_MEMBERSHIP_STORAGE_KEY = 'castalia-zenith-membership-v3'

export type MembershipStorageArea = {
  get(key: string): Promise<Record<string, unknown>>
  set(values: Record<string, unknown>): Promise<void>
  remove(key: string): Promise<void>
}

export function createZenithMembershipState(storage: MembershipStorageArea) {
  return {
    async get(): Promise<ZenithMembershipCredentialV3 | null> {
      const result = await storage.get(ZENITH_MEMBERSHIP_STORAGE_KEY)
      try {
        return parseZenithMembershipCredential(result[ZENITH_MEMBERSHIP_STORAGE_KEY])
      } catch {
        return null
      }
    },

    async set(credential: ZenithMembershipCredentialV3): Promise<void> {
      let valid: ZenithMembershipCredentialV3
      try {
        valid = parseZenithMembershipCredential(credential)
      } catch {
        throw new Error('Refusing to persist an invalid Zenith membership credential')
      }
      await storage.set({ [ZENITH_MEMBERSHIP_STORAGE_KEY]: valid })
    },

    async clear(): Promise<void> {
      await storage.remove(ZENITH_MEMBERSHIP_STORAGE_KEY)
    },
  }
}

export const zenithMembershipState = {
  get: () => createZenithMembershipState(chrome.storage.local).get(),
  set: (credential: ZenithMembershipCredentialV3) =>
    createZenithMembershipState(chrome.storage.local).set(credential),
  clear: () => createZenithMembershipState(chrome.storage.local).clear(),
}
