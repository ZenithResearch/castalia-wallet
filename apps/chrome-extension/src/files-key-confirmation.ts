import type { FilesConfirmationSummary } from './files-key-handler.js'
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
  try { await send({ type: 'RESOLVE_FILES_KEY_CONFIRMATION', requestId, approved }); status.textContent = approved ? 'Files request approved.' : 'Files request denied.' }
  catch (error) { status.textContent = error instanceof Error ? error.message : 'Confirmation unavailable.' }
}
approve.addEventListener('click', () => void decide(true))
deny.addEventListener('click', () => void decide(false))
void (async () => {
  if (!requestId) { status.textContent = 'Confirmation request is missing.'; return }
  try {
    const { summary: s } = await send({ type: 'GET_FILES_KEY_CONFIRMATION', requestId }) as { summary: FilesConfirmationSummary }
    const action = s.operation === 'wrap' ? 'Protect the key for this encrypted revision' : s.operation === 'unwrap' ? 'Release this revision’s data key to the requesting site' : 'Authenticate to the selected Files service'
    for (const [id, value] of Object.entries({ origin: s.origin, action, audience: s.audience, member: s.memberKey,
      account: s.binding?.storageAccountId ?? 'Service authentication', namespace: s.binding?.namespaceId ?? '—', workspace: s.binding?.workspaceId ?? '—',
      submission: s.binding?.submissionId ?? '—', revision: s.binding?.revisionId ?? '—', digest: s.requestDigest, expires: new Date(s.expiresAt * 1000).toLocaleString() })) setText(id, value)
    approve.disabled = false; deny.disabled = false
  } catch (error) { status.textContent = error instanceof Error ? error.message : 'Confirmation unavailable.' }
})()
