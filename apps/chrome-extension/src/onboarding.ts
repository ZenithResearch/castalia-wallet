declare const chrome: any

type CustodyState = {
  setupComplete: boolean
  unlocked: boolean
  publicKey: string | null
}

type Mode = 'create' | 'unlock' | 'continue'

function requestIdFromLocation(): string {
  const params = new URLSearchParams(window.location.search)
  const requestId = params.get('request')
  if (params.size !== 1 || !requestId) throw new Error('Membership flow request is invalid.')
  return requestId
}

const continueButton = document.getElementById('continue') as HTMLButtonElement
const closeButton = document.getElementById('close') as HTMLButtonElement
const status = document.getElementById('status') as HTMLParagraphElement
const embeddingOriginElement = document.getElementById('embedding-origin') as HTMLElement
const passphraseField = document.getElementById('passphrase-field') as HTMLDivElement
const passphraseInput = document.getElementById('passphrase') as HTMLInputElement
let mode: Mode = 'create'
let embeddingOrigin: string | null = null
const requestId = requestIdFromLocation()

function send<T>(message: Record<string, unknown>): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response: { ok?: boolean; error?: string } & T | undefined) => {
      const error = chrome.runtime.lastError?.message ?? response?.error
      if (error || !response?.ok) reject(new Error(error ?? 'Wallet operation failed.'))
      else resolve(response)
    })
  })
}

function showState(state: CustodyState): void {
  continueButton.disabled = false
  if (!state.setupComplete) {
    mode = 'create'
    passphraseField.hidden = false
    passphraseInput.autocomplete = 'new-password'
    status.textContent = 'Choose a passphrase to create your durable Dregg-hybrid Member Key.'
    continueButton.textContent = 'Create wallet and join'
    return
  }
  if (!state.unlocked) {
    mode = 'unlock'
    passphraseField.hidden = false
    passphraseInput.autocomplete = 'current-password'
    status.textContent = 'Unlock your existing Member Key to join Castalia.'
    continueButton.textContent = 'Unlock wallet and join'
    return
  }
  mode = 'continue'
  passphraseField.hidden = true
  status.textContent = 'Your Ed25519 + ML-DSA-65 Member Key is ready. Continue to request Zenith-signed membership.'
  continueButton.textContent = 'Join Castalia'
}

closeButton.addEventListener('click', () => {
  window.close()
})

continueButton.addEventListener('click', () => {
  void (async () => {
    continueButton.disabled = true
    try {
      if (mode !== 'continue') {
        const passphrase = passphraseInput.value
        if (passphrase.length === 0) throw new Error('Enter your wallet passphrase.')
        status.textContent = mode === 'create' ? 'Creating your Dregg-hybrid Member Key…' : 'Unlocking your Dregg-hybrid Member Key…'
        await send(mode === 'create'
          ? { type: 'CUSTODY_CREATE', passphrase }
          : { type: 'CUSTODY_UNLOCK', passphrase })
        passphraseInput.value = ''
      }
      status.textContent = 'Member Key ready. Requesting your signed membership from Zenith…'
      await send({
        type: 'BEGIN_MEMBERSHIP_FLOW',
        requestId,
        expectedOrigin: embeddingOrigin,
      })
      status.textContent = 'Wallet ready. Zenith-signed membership verified and saved.'
      continueButton.hidden = true
      window.setTimeout(() => {
        window.close()
      }, 500)
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : 'Wallet setup failed.'
      continueButton.disabled = false
    }
  })()
})

void send<{ state: CustodyState; embeddingOrigin?: string }>({
  type: 'CUSTODY_GET_STATE',
  requestId,
})
  .then(response => {
    if (!response.embeddingOrigin) {
      throw new Error('The site requesting wallet access could not be identified.')
    }
    embeddingOrigin = response.embeddingOrigin
    embeddingOriginElement.textContent = embeddingOrigin
    showState(response.state)
  })
  .catch(error => {
    status.textContent = error instanceof Error ? error.message : 'Wallet state is unavailable.'
  })
