type Summary = {
  origin: string
  memberKeyFingerprint: string
  issuedAt: number
  expiresAt: number
}

declare const chrome: any

const requestId = new URL(location.href).searchParams.get('request')
const approve = document.getElementById('approve') as HTMLButtonElement
const deny = document.getElementById('deny') as HTMLButtonElement
const status = document.getElementById('status')!

function setText(id: string, value: string) {
  document.getElementById(id)!.textContent = value
}

function send(message: unknown): Promise<any> {
  return new Promise((resolve, reject) => chrome.runtime.sendMessage(message, (response: any) => {
    if (chrome.runtime.lastError || !response?.ok) {
      reject(new Error(response?.error ?? chrome.runtime.lastError?.message ?? 'confirmation unavailable'))
    } else resolve(response)
  }))
}

async function decide(approved: boolean) {
  approve.disabled = true
  deny.disabled = true
  try {
    await send({ type: 'RESOLVE_MEMBERSHIP_CONFIRMATION', requestId, approved })
    status.textContent = approved ? 'Proof approved.' : 'Proof denied.'
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : 'Confirmation unavailable.'
  }
}

approve.addEventListener('click', () => void decide(true))
deny.addEventListener('click', () => void decide(false))

void (async () => {
  if (!requestId) {
    status.textContent = 'Confirmation request is missing.'
    return
  }
  try {
    const { summary } = await send({ type: 'GET_MEMBERSHIP_CONFIRMATION', requestId }) as { summary: Summary }
    setText('origin', summary.origin)
    setText('fingerprint', summary.memberKeyFingerprint)
    setText('issued-at', new Date(summary.issuedAt).toLocaleString())
    setText('expires-at', new Date(summary.expiresAt).toLocaleString())
    approve.disabled = false
    deny.disabled = false
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : 'Confirmation unavailable.'
  }
})()
