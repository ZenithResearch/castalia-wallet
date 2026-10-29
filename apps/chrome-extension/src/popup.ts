import { observeCustodyPanel } from './custody-panel-state.js'
import { readWalletImportFile } from './import-file.js'
import { copyPublicMemberKey, publicMemberKeyForDisplay } from './member-key-display.js'

declare const chrome: any

type WalletState = {
  setupComplete: boolean
  unlocked: boolean
  publicKey: string | null
}

type ChainAccount = {
  networkId: string
  address: string
}

const root = document.getElementById('app')!
let state: WalletState = { setupComplete: false, unlocked: false, publicKey: null }
let chainAccounts: ChainAccount[] = []
let pendingImport: string | null = null
let custodyAvailable = false

function send<T>(message: unknown): Promise<T> {
  return new Promise((resolve, reject) => chrome.runtime.sendMessage(message, (response: any) => {
    if (chrome.runtime.lastError || !response?.ok) {
      reject(new Error(response?.error ?? chrome.runtime.lastError?.message ?? 'operation_failed'))
    } else {
      resolve(response)
    }
  }))
}

const custodyPanel=observeCustodyPanel(chrome.runtime,{
  snapshot(value){state=value.state;chainAccounts=value.chainAccounts;custodyAvailable=true;render()},
  unavailable(){state={...state,unlocked:false};chainAccounts=[];custodyAvailable=false;render()},
})
async function refresh(){custodyPanel.refresh()}
window.addEventListener('focus',()=>void refresh())
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')void refresh()})
window.addEventListener('pagehide',()=>custodyPanel.dispose(),{once:true})

function accountName(networkId: string): string {
  if (networkId === 'cardano:mainnet') return 'Cardano · Preview'
  if (networkId === 'eip155:1') return 'Ethereum · Preview'
  if (networkId === 'eip155:4663') return 'Robinhood Chain · Preview'
  if (networkId === 'solana:mainnet-beta') return 'Solana · Preview'
  return `${networkId} · Preview`
}

function render() {
  const title = !custodyAvailable ? 'Check Wallet' : !state.setupComplete ? 'Create wallet' : state.unlocked ? 'Wallet ready' : 'Wallet locked'
  const publicMemberKey = publicMemberKeyForDisplay(state)
  root.innerHTML = `
    <section class="wallet">
      <main class="wallet-main">
        <section><p class="eyebrow">Castalia</p><h1 class="state-title">${title}</h1>
          <p class="state-copy">Encrypted Dregg-hybrid identity custody. One recovery seed restores both Ed25519 and ML-DSA-65 keys. Reload or background suspension locks this wallet without erasing its identity.</p>
        </section>
        ${!custodyAvailable ? '<p class="state-copy" role="status">Wallet status is unavailable. Check Wallet to read its current lock state.</p><button id="check-wallet" class="primary-action">Check Wallet</button>' : ''}
        ${custodyAvailable && !state.setupComplete ? `
          <form id="create-form" class="advanced-content">
            <label>Passphrase<input id="create-passphrase" type="password" autocomplete="new-password" required /></label>
            <button class="primary-action">Create wallet</button>
          </form>` : ''}
        ${custodyAvailable && state.setupComplete && !state.unlocked ? `
          <form id="unlock-form" class="advanced-content">
            <label>Passphrase<input id="unlock-passphrase" type="password" autocomplete="current-password" required /></label>
            <button class="primary-action">Unlock</button>
          </form>` : ''}
        ${state.setupComplete ? `<p class="eyebrow">Identity ${state.publicKey?.slice(0, 12)}…</p>` : ''}
        ${publicMemberKey ? `
          <section class="public-member-key" aria-labelledby="public-member-key-label">
            <label id="public-member-key-label" for="public-member-key">Public Member Key</label>
            <input id="public-member-key" value="${publicMemberKey}" readonly spellcheck="false" />
            <button id="copy-public-member-key" class="text-action" type="button">Copy public Member Key</button>
            <p id="copy-public-member-key-status" class="copy-status" role="status" aria-live="polite"></p>
          </section>` : ''}
        ${state.unlocked ? '<button id="holder-grants" class="text-action">Saved grants &amp; backup</button><button id="wallet-identities" class="text-action">Wallet identities &amp; Castaway</button>' : ''}
        ${state.unlocked && chainAccounts.length ? `<section class="account-list" aria-labelledby="account-list-title"><p class="eyebrow" id="account-list-title">Preview accounts</p>${chainAccounts.map(account => `<div><strong>${accountName(account.networkId)}</strong><code>${account.address}</code></div>`).join('')}<p class="account-warning"><strong>Do not fund yet.</strong> The recovery root is stable, but balances and transaction signing are not enabled.</p></section>` : ''}
        ${state.unlocked ? '<button id="providers" class="text-action">Providers and memberships</button>' : ''}
        ${state.unlocked ? '<button id="connect-site" class="text-action">Connect this site</button>' : ''}
        <details class="advanced" ${pendingImport ? 'open' : ''}><summary>Recovery</summary><div class="advanced-content">
          <p class="state-copy">A .castalia-recovery file is another copy of signing authority. It is not membership or admission.</p>
          ${state.unlocked ? '<button id="export" class="text-action">Export recovery file</button>' : ''}
          <label class="text-action">Import recovery file<input id="import" type="file" accept=".castalia-recovery,.castalia-wallet" /></label>
          <label id="replacement-confirm-row" ${pendingImport ? '' : 'hidden'}><input id="replacement-confirm" type="checkbox" /> Replace the existing identity</label>
          <button id="confirm-import" class="text-action" ${pendingImport ? '' : 'hidden'}>Import encrypted recovery file</button>
          ${state.unlocked ? '<button id="lock" class="text-action">Lock wallet</button>' : ''}
        </div></details>
      </main>
      <footer class="session-note">Private keys and passphrases remain inside the extension-owned service worker. The recovery file restores the identity and preview chain accounts.</footer>
    </section>`
  wire()
}

function passphrase(id: string): string {
  const input = document.getElementById(id) as HTMLInputElement
  const value = input.value
  input.value = ''
  return value
}

function wire() {
  document.getElementById('check-wallet')?.addEventListener('click',()=>void refresh())
  document.getElementById('copy-public-member-key')?.addEventListener('click', async () => {
    const field = document.getElementById('public-member-key') as HTMLInputElement | null
    const status = document.getElementById('copy-public-member-key-status')
    if (!field || !status) return

    const result = await copyPublicMemberKey(
      field.value,
      navigator.clipboard?.writeText
        ? value => navigator.clipboard.writeText(value)
        : async () => { throw new Error('clipboard_unavailable') },
      value => {
        if (field.value !== value) return false
        field.focus()
        field.select()
        field.setSelectionRange(0, value.length)
        return document.execCommand('copy')
      },
    )
    status.textContent = result === 'copied'
      ? 'Public Member Key copied.'
      : 'Copy unavailable. Select the public key and copy it manually.'
  })
  document.getElementById('create-form')?.addEventListener('submit', async event => {
    event.preventDefault()
    await send({ type: 'CUSTODY_CREATE', passphrase: passphrase('create-passphrase') })
    await refresh()
  })
  document.getElementById('unlock-form')?.addEventListener('submit', async event => {
    event.preventDefault()
    await send({ type: 'CUSTODY_UNLOCK', passphrase: passphrase('unlock-passphrase') })
    await refresh()
  })
  document.getElementById('providers')?.addEventListener('click', () => { void chrome.tabs.create({url:chrome.runtime.getURL('src/provider-settings.html')}) })
  document.getElementById('lock')?.addEventListener('click', async () => {
    await send({ type: 'CUSTODY_LOCK' })
    await refresh()
  })
  document.getElementById('connect-site')?.addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (tab?.url) await send({ type: 'APPROVE_ORIGIN', origin: new URL(tab.url).origin })
  })
  document.getElementById('export')?.addEventListener('click', async () => {
    const phrase = prompt('Passphrase for this encrypted recovery file')
    if (!phrase) return
    const result = await send<{ filename: string; contents: string }>({ type: 'CUSTODY_EXPORT', passphrase: phrase })
    const anchor = document.createElement('a')
    anchor.href = URL.createObjectURL(new Blob([result.contents], { type: 'application/json' }))
    anchor.download = result.filename
    anchor.click()
    URL.revokeObjectURL(anchor.href)
  })
  document.getElementById('import')?.addEventListener('change', async event => {
    const file = (event.target as HTMLInputElement).files?.[0]
    pendingImport = null
    if (!file) return render()
    try {
      pendingImport = await readWalletImportFile(file)
    } catch {
      ;(event.target as HTMLInputElement).value = ''
    }
    render()
  })
  document.getElementById('wallet-identities')?.addEventListener('click', () => { void chrome.tabs.create({url:chrome.runtime.getURL('src/wallet-identities.html')}) })
  document.getElementById('confirm-import')?.addEventListener('click', async () => {
    if (!pendingImport) return
    const phrase = prompt('Passphrase for this encrypted recovery file')
    if (!phrase) return
    const replaceExisting = (document.getElementById('replacement-confirm') as HTMLInputElement).checked
    await send({ type: 'CUSTODY_IMPORT', contents: pendingImport, passphrase: phrase, replaceExisting })
    pendingImport = null
    await refresh()
  })
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => void refresh(), { once: true })
} else {
  void refresh()
}

document.addEventListener("click",event=>{if((event.target as HTMLElement)?.id==="holder-grants")void chrome.tabs.create({url:chrome.runtime.getURL("src/holder-grants.html")})})
