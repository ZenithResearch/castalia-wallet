import type { RegistrationConfirmationSummary } from './registration.js'
declare const chrome: any
const requestId = new URL(location.href).searchParams.get('request')
const approve = document.getElementById('approve') as HTMLButtonElement
const deny = document.getElementById('deny') as HTMLButtonElement
const status = document.getElementById('status')!
const setText = (id: string, value: string) => { document.getElementById(id)!.textContent = value }
function send(message: unknown): Promise<any> {
  return new Promise((resolve, reject) => chrome.runtime.sendMessage(message, (response: any) => {
    if (chrome.runtime.lastError || !response?.ok) reject(new Error(response?.error ?? chrome.runtime.lastError?.message ?? 'Confirmation unavailable'))
    else resolve(response)
  }))
}
async function decide(approved: boolean) {
  approve.disabled = true; deny.disabled = true
  try { await send({ type: 'RESOLVE_REGISTRATION_CONFIRMATION', requestId, approved }); status.textContent = approved ? 'Proposal signature approved.' : 'Proposal signature denied.' }
  catch (error) { status.textContent = error instanceof Error ? error.message : 'Confirmation unavailable.' }
}
approve.addEventListener('click', () => void decide(true))
deny.addEventListener('click', () => void decide(false))
void (async () => {
  if (!requestId) { status.textContent = 'Confirmation request is missing.'; return }
  try {
    const { summary: s } = await send({ type: 'GET_REGISTRATION_CONFIRMATION', requestId }) as { summary: RegistrationConfirmationSummary }
    const m = s.manifest
    for (const [id, value] of Object.entries({ origin: s.origin, action: m.revision === 0 ? 'Create entity with one namespace and creator as initial controller' : `Propose revision ${m.revision}; receiver must verify current controller`, 'entity-class': m.entityClass, name: m.displayName, entity: m.entityRef, namespace: m.namespaceId, workspace: m.initialWorkspaceId, creator: m.creatorMemberKey, controller: m.controllerMemberKey, signer: s.signerMemberKey, previous: m.previousManifestDigest ?? '(genesis)', digest: s.manifestDigest, expires: new Date(s.expiresAt * 1_000).toLocaleString() })) setText(id, value)
    approve.disabled = false; deny.disabled = false
  } catch (error) { status.textContent = error instanceof Error ? error.message : 'Confirmation unavailable.' }
})()
