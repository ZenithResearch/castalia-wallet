declare const chrome: any;
const get = (id: string) => document.getElementById(id)!;
let busy = false, token: string | null = null, generation = 0;
const send = (message: unknown): Promise<any> => new Promise((resolve, reject) => chrome.runtime.sendMessage(message, (r: any) => chrome.runtime.lastError || !r?.ok ? reject(Error(r?.error ?? 'Unlock Wallet and refresh.')) : resolve(r)));
async function run(work: () => Promise<void>) { if (busy)
    return; busy = true; for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>('button')))
    b.disabled = true; try {
    await work();
}
catch {
    get('notice').textContent = 'This operation could not finish. Unlock the same Wallet and check the selected file. Your saved grants were preserved.';
}
finally {
    busy = false;
    for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>('button')))
        b.disabled = false;
} }
function display(target: HTMLElement, records: any[]) { target.replaceChildren(); for (const record of records) {
    const c = record.grant ?? record, a = document.createElement('article'), h = document.createElement('h2'), expiry = document.createElement('p'), details = document.createElement('pre');
    h.textContent = c.service;
    expiry.textContent = c.validity.mode === 'until_revoked' ? 'Until revoked' : `Grant expires ${new Date(c.validity.not_after * 1000).toLocaleString()}`;
    details.textContent = JSON.stringify(c.permissions, null, 2);
    a.append(h, expiry, details);
    target.append(a);
} if (!records.length)
    target.textContent = 'No reusable grants saved. Connect to a service and choose Save grant in Wallet.'; }
async function refresh() { const r = await send({ type: 'HOLDER_GRANTS_LIST' }); display(get('grants'), r.grants); }
get('refresh').onclick = () => void run(refresh);
get('export').onclick = () => void run(async () => { const before = generation, r = await send({ type: 'HOLDER_GRANTS_EXPORT' }); if (before !== generation)
    return; const u = URL.createObjectURL(new Blob([r.file], { type: 'application/json' })); const a = document.createElement('a'); a.href = u; a.download = 'castalia-grant-backup.json'; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000); get('notice').textContent = 'Encrypted grant backup download requested.'; });
get('import').onsubmit = e => { e.preventDefault(); const file = (get('file') as HTMLInputElement).files?.[0]; void run(async () => { if (!file || file.size > 1048576)
    throw Error('file_too_large'); const before = generation, r = await send({ type: 'HOLDER_GRANTS_REVIEW', file: await file.text() }); if (before !== generation)
    return; token = r.token; display(get('preview'), r.grants); get('review').hidden = false; }); };
get('confirm').onclick = () => { const t = token; if (!t)
    return; token = null; void run(async () => { await send({ type: 'HOLDER_GRANTS_CONFIRM', token: t }); get('review').hidden = true; await refresh(); get('notice').textContent = 'Saved grants restored. The service still checks their current status.'; }); };
get('cancel').onclick = () => { token = null; get('review').hidden = true; void send({ type: 'HOLDER_GRANTS_CANCEL' }).catch(() => { }); };
chrome.runtime.onMessage.addListener((m: any) => { if (m?.type === 'HOLDER_GRANTS_INVALIDATED') {
    generation++;
    token = null;
    get('review').hidden = true;
    get('grants').replaceChildren();
    get('preview').replaceChildren();
    get('notice').textContent = 'Wallet changed or locked. Unlock and refresh.';
} return false; });
window.addEventListener('pagehide', () => { generation++; token = null; void send({ type: 'HOLDER_GRANTS_CANCEL' }).catch(() => { }); });
void run(refresh);
export {};
