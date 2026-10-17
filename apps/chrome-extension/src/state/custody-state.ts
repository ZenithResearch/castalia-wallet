export const CUSTODY_STORAGE_KEY = 'castalia-encrypted-custody-v1'
export const MAX_CUSTODY_RECORD_BYTES = 1_048_576

export type LocalStorageArea = {
  get(key: string): Promise<Record<string, unknown>>
  set(values: Record<string, unknown>): Promise<void>
  remove(key: string): Promise<void>
}

export type CustodyEngine = {
  create(passphrase: string, createdAt: number): string
  unlock(record: string, passphrase: string): string
  exportRandomized(passphrase: string): string
  lock(): void
  publicKey(): string
}

export type CustodyState = {
  setupComplete: boolean
  unlocked: boolean
  publicKey: string | null
}

type StoredCustody = {
  encryptedRecord: string
  publicKey: string
}

export function createCustodyStateManager(storage: LocalStorageArea, core: CustodyEngine) {
  let unlocked = false
  let operationTail: Promise<void> = Promise.resolve()

  function exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const result = operationTail.then(operation, operation)
    operationTail = result.then(() => undefined, () => undefined)
    return result
  }

  async function stored(): Promise<StoredCustody | null> {
    const result = await storage.get(CUSTODY_STORAGE_KEY)
    const candidate = result[CUSTODY_STORAGE_KEY]
    if (!candidate || typeof candidate !== 'object') return null
    const record = candidate as Partial<StoredCustody>
    if (typeof record.encryptedRecord !== 'string' || !/^[0-9a-f]{64}$/.test(record.publicKey ?? '')) {
      return null
    }
    return record as StoredCustody
  }

  async function state(): Promise<CustodyState> {
    const record = await stored()
    return {
      setupComplete: record !== null,
      unlocked: record !== null && unlocked,
      publicKey: record?.publicKey ?? null,
    }
  }

  return {
    getState(): Promise<CustodyState> {
      return exclusive(state)
    },

    create(passphrase: string, createdAt: number): Promise<CustodyState> {
      return exclusive(async () => {
        if (await stored()) throw new Error('replacement_confirmation_required')
        core.lock()
        unlocked = false
        try {
          const encryptedRecord = core.create(passphrase, createdAt)
          const publicKey = core.publicKey()
          await storage.set({ [CUSTODY_STORAGE_KEY]: { encryptedRecord, publicKey } })
          unlocked = true
          return state()
        } catch (error) {
          core.lock()
          unlocked = false
          throw error
        }
      })
    },

    unlock(passphrase: string): Promise<CustodyState> {
      return exclusive(async () => {
        const record = await stored()
        if (!record) throw new Error('wallet_not_setup')
        core.lock()
        unlocked = false
        try {
          const publicKey = core.unlock(record.encryptedRecord, passphrase)
          if (publicKey !== record.publicKey) throw new Error('invalid_wallet_file')
          unlocked = true
          return state()
        } catch (error) {
          core.lock()
          unlocked = false
          throw error
        }
      })
    },

    lock(): Promise<void> {
      return exclusive(async () => {
        core.lock()
        unlocked = false
      })
    },

    clearSensitiveMemoryForReload(): Promise<void> {
      return exclusive(async () => {
        core.lock()
        unlocked = false
      })
    },

    exportEncrypted(passphrase: string): Promise<string> {
      return exclusive(async () => {
        if (!unlocked || !(await stored())) throw new Error('invalid_wallet_file')
        try {
          return core.exportRandomized(passphrase)
        } catch {
          throw new Error('invalid_wallet_file')
        }
      })
    },

    importEncrypted(
      encryptedRecord: string,
      passphrase: string,
      options: { replaceExisting: boolean },
    ): Promise<{ publicKey: string; replaced: boolean; state: CustodyState }> {
      return exclusive(async () => {
        if (new TextEncoder().encode(encryptedRecord).byteLength > MAX_CUSTODY_RECORD_BYTES) {
          throw new Error('invalid_wallet_file')
        }
        const existing = await stored()
        if (existing && !options.replaceExisting) throw new Error('replacement_confirmation_required')
        core.lock()
        unlocked = false
        try {
          const publicKey = core.unlock(encryptedRecord, passphrase)
          await storage.set({ [CUSTODY_STORAGE_KEY]: { encryptedRecord, publicKey } })
          core.lock()
          unlocked = false
          return { publicKey, replaced: existing !== null, state: await state() }
        } catch {
          core.lock()
          unlocked = false
          throw new Error('invalid_wallet_file')
        }
      })
    },
  }
}
