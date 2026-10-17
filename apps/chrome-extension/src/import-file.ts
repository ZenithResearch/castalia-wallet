export const MAX_WALLET_IMPORT_BYTES = 1_048_576
export const RECOVERY_FILE_EXTENSION = '.castalia-recovery'
export const LEGACY_RECOVERY_FILE_EXTENSION = '.castalia-wallet'

export type WalletImportFile = {
  name: string
  size: number
  text(): Promise<string>
}

export async function readWalletImportFile(file: WalletImportFile): Promise<string> {
  const name = file.name.toLowerCase()
  if (
    !name.endsWith(RECOVERY_FILE_EXTENSION)
    && !name.endsWith(LEGACY_RECOVERY_FILE_EXTENSION)
  ) throw new Error('invalid_wallet_file')
  if (file.size > MAX_WALLET_IMPORT_BYTES) throw new Error('invalid_wallet_file')
  return file.text()
}
