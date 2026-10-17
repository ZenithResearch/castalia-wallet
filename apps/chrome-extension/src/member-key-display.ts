export type PublicMemberKeyState = {
  setupComplete: boolean
  publicKey: string | null
}

export type PublicMemberKeyCopyResult = 'copied' | 'failed' | 'unavailable'

export function publicMemberKeyForDisplay(state: PublicMemberKeyState): string | null {
  if (!state.setupComplete || !state.publicKey || !/^[0-9a-f]{64}$/.test(state.publicKey)) {
    return null
  }
  return state.publicKey
}

export async function copyPublicMemberKey(
  publicKey: string,
  writeClipboard: (value: string) => Promise<void>,
  fallbackCopy: (value: string) => boolean,
): Promise<PublicMemberKeyCopyResult> {
  const canonical = publicMemberKeyForDisplay({ setupComplete: true, publicKey })
  if (!canonical) return 'unavailable'

  try {
    await writeClipboard(canonical)
    return 'copied'
  } catch {
    try {
      return fallbackCopy(canonical) ? 'copied' : 'failed'
    } catch {
      return 'failed'
    }
  }
}
