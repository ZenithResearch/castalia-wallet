import {displayGrants} from './holder-grants-view.js';
declare const chrome: any;
const get = (id: string) => document.getElementById(id)!;
let busy = false, token: string | null = null, generation = 0, forgetToken: string | null = null;
let removeTrigger:HTMLButtonElement|null=null;
const send = (message: unknown): Promise<any> => new Promise((resolve, reject) => chrome.runtime.sendMessage(message, (r: any) => chrome.runtime.lastError || !r?.ok ? reject(Error(r?.error ?? 'Unlock Wallet and refresh.')) : resolve(r)));
async function run(work: () => Promise<void>) { if (busy)
    return; busy = true; for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>('button')))
    b.disabled = true; try {
    await work();
}
catch {
    get('notice').textContent = 'Could not confirm this operation. Unlock the same Wallet and refresh to check the current saved grants.';
}
finally {
    busy = false;
    for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>('button')))
        b.disabled = false;
} }
async function refresh() { const before=generation,r = await send({ type: 'HOLDER_GRANTS_LIST' });if(before!==generation)return;
    displayGrants(get('grants'), r.grants,(service,trigger)=>void run(async()=>{
        const before=generation,result=await send({type:'HOLDER_GRANTS_FORGET_REVIEW',service});if(before!==generation)return;
        forgetToken=result.token;removeTrigger=trigger;displayGrants(get('forget-preview'),[{grant:result.grant}]);get('forget-review').hidden=false;get('forget-review').focus();
    }));
    get('grant-count').textContent=`${r.grants.length} saved service${r.grants.length===1?'':'s'}`;
}
get('forget-confirm').onclick=()=>{const reviewed=forgetToken;if(!reviewed)return;forgetToken=null;get('forget-review').hidden=true;void run(async()=>{await send({type:'HOLDER_GRANTS_FORGET_CONFIRM',token:reviewed});get('forget-review').hidden=true;await refresh();get('notice').textContent='Saved grant forgotten locally. Server approval and already-issued credentials are unchanged.';});};
get('forget-cancel').onclick=()=>{forgetToken=null;get('forget-review').hidden=true;get('forget-preview').replaceChildren();removeTrigger?.focus();removeTrigger=null;void send({type:'HOLDER_GRANTS_FORGET_CANCEL'}).catch(()=>{});};
get('refresh').onclick = () => void run(refresh);
get('export').onclick = () => void run(async () => { const before = generation, r = await send({ type: 'HOLDER_GRANTS_EXPORT' }); if (before !== generation)
    return; const u = URL.createObjectURL(new Blob([r.file], { type: 'application/json' })); const a = document.createElement('a'); a.href = u; a.download = 'castalia-grant-backup.json'; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000); get('notice').textContent = 'Encrypted grant backup download requested.'; });
get('import').onsubmit = e => { e.preventDefault(); const file = (get('file') as HTMLInputElement).files?.[0]; void run(async () => { if (!file || file.size > 1048576)
    throw Error('file_too_large'); const before = generation, r = await send({ type: 'HOLDER_GRANTS_REVIEW', file: await file.text() }); if (before !== generation)
    return; token = r.token; displayGrants(get('preview'), r.grants); get('review').hidden = false; }); };
get('confirm').onclick = () => { const t = token; if (!t)
    return; token = null; void run(async () => { await send({ type: 'HOLDER_GRANTS_CONFIRM', token: t }); get('review').hidden = true; await refresh(); get('notice').textContent = 'Saved grants restored. The service still checks their current status.'; }); };
get('cancel').onclick = () => { token = null; get('review').hidden = true; void send({ type: 'HOLDER_GRANTS_CANCEL' }).catch(() => { }); };
chrome.runtime.onMessage.addListener((m: any) => { if (m?.type === 'HOLDER_GRANTS_INVALIDATED') {
    generation++;
    token = null; forgetToken=null;removeTrigger=null; get('forget-review').hidden=true; get('forget-preview').replaceChildren();
    get('review').hidden = true;
    get('grants').replaceChildren();get('grant-count').textContent='Refresh required';
    get('preview').replaceChildren();
    get('notice').textContent = 'Wallet changed or locked. Unlock and refresh.';
} return false; });
window.addEventListener('pagehide', () => { generation++; token = null;forgetToken=null;void send({type:'HOLDER_GRANTS_FORGET_CANCEL'}).catch(()=>{}); void send({ type: 'HOLDER_GRANTS_CANCEL' }).catch(() => { }); });
void run(refresh);
export {};
