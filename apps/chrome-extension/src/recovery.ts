export type RecoveryBackend = {
  exportEncrypted(passphrase: string): Promise<string>
  importEncrypted(
    record: string,
    passphrase: string,
    options: { replaceExisting: boolean },
  ): Promise<{ publicKey: string; replaced: boolean }>
}

export function createRecoveryManager(backend: RecoveryBackend) {
  return {
    async exportWallet(passphrase: string): Promise<{ filename: string; contents: string }> {
      try {
        return {
          filename: `Castalia-Recovery-${Date.now()}.castalia-recovery`,
          contents: await backend.exportEncrypted(passphrase),
        }
      } catch {
        throw new Error('invalid_wallet_file')
      }
    },

    async importWallet(
      contents: string,
      passphrase: string,
      options: { replaceExisting: boolean },
    ): Promise<{ publicKey: string; replaced: boolean }> {
      return backend.importEncrypted(contents, passphrase, options)
    },
  }
}
