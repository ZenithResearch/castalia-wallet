import { createOperationConfirmationBroker } from './operation-confirmation-broker.js'
import { createCredentialPresentationHandler, type CredentialSummary, type PreparedCredential } from './credential-presentation.js'
type Custody = {
  run<T>(f:()=>Promise<T>):Promise<T>; state():Promise<{memberKey:string;approvedOrigins:ReadonlySet<string>}|null>;
  epoch():number; onChange(f:()=>void):()=>void;
  prepare(raw:Uint8Array,caller:{kind:'browser';id:string}):PreparedCredential | Promise<PreparedCredential>;
}
function originOf(value:unknown):string {
 if(typeof value!=='string')throw new Error('invalid_caller')
 const url=new URL(value)
 if(url.protocol!=='https:' && !(url.protocol==='http:' && ['localhost','127.0.0.1','[::1]'].includes(url.hostname)))throw new Error('invalid_caller')
 return url.origin
}
export function installCredentialPresentationRuntime(chrome:any,custody:Custody) {
 const pageUrl=chrome.runtime.getURL('src/credential-presentation-confirmation.html')
 const broker=createOperationConfirmationBroker<CredentialSummary & {expiresAt:number}>({
  confirmationUrl:id=>`${pageUrl}?request=${encodeURIComponent(id)}`,
  createWindow:async url=>{const w=await chrome.windows.create({url,type:'popup',width:620,height:820,focused:true});if(typeof w?.id!=='number')throw new Error('confirmation_unavailable');return w.id},
  closeWindow:id=>chrome.windows.remove(id),addWindowRemovedListener:f=>chrome.windows.onRemoved.addListener(f),removeWindowRemovedListener:f=>chrome.windows.onRemoved.removeListener(f),
  setTimeout:(f,ms)=>globalThis.setTimeout(f,ms),clearTimeout:id=>globalThis.clearTimeout(id as ReturnType<typeof setTimeout>),randomId:()=>crypto.randomUUID(),nowMs:Date.now,
 })
 const active=new Set<{tabId:number;cancel():void}>()
 const invalidate=()=>{for(const entry of [...active])entry.cancel()}
 custody.onChange(invalidate)
 chrome.tabs.onUpdated.addListener((id:number,change:any)=>{if(change.url!==undefined||change.status==='loading')for(const entry of [...active])if(entry.tabId===id)entry.cancel()})
 chrome.tabs.onRemoved.addListener((id:number)=>{for(const entry of [...active])if(entry.tabId===id)entry.cancel()})
 chrome.runtime.onMessage.addListener((message:any,sender:any,respond:(v:unknown)=>void)=>{
  if(!['GET_CREDENTIAL_PRESENTATION_CONFIRMATION','RESOLVE_CREDENTIAL_PRESENTATION_CONFIRMATION'].includes(message?.type))return false
  try{
   if(sender?.id!==chrome.runtime.id || typeof message.requestId!=='string' || sender?.url!==`${pageUrl}?request=${encodeURIComponent(message.requestId)}`)throw new Error('invalid_confirmation_sender')
   if(message.type==='GET_CREDENTIAL_PRESENTATION_CONFIRMATION') {const p=broker.claimPending(message.requestId);if(!p)throw new Error('confirmation_unavailable');respond({ok:true,summary:p.summary})}
   else {if(!broker.resolve(message.requestId,message.approved===true))throw new Error('confirmation_unavailable');respond({ok:true})}
  }catch(e){respond({ok:false,error:e instanceof Error?e.message:'confirmation_unavailable'})}return false
 })
 chrome.runtime.onConnect.addListener((port:any)=>{
  if(port.name!=='castalia-credential-presentation-v2')return
  let live=true,used=false;let timer:ReturnType<typeof setTimeout>|undefined
  const sender=port.sender,tabId=sender?.tab?.id,documentUrl=sender?.url
  const owner={tabId,cancel(){if(!live)return;live=false;clearTimeout(timer);broker.cancelForOwner(owner);active.delete(owner);try{port.disconnect()}catch{}}}
  const fail=(error:unknown)=>{try{port.postMessage({ok:false,error:error instanceof Error?error.message:'presentation_failed'})}catch{}owner.cancel()}
  let origin:string
  try{
   if(active.size>=32||sender?.id!==chrome.runtime.id||sender.frameId!==0||!Number.isInteger(tabId)||typeof sender.documentId!=='string'||sender.documentLifecycle && sender.documentLifecycle!=='active'||documentUrl!==sender.tab.url)throw new Error('invalid_document')
   origin=originOf(documentUrl)
  }catch(e){fail(e);return}
  active.add(owner);timer=setTimeout(()=>owner.cancel(),125000);port.onDisconnect.addListener(()=>owner.cancel())
  const handler=createCredentialPresentationHandler({
   run:f=>custody.run(f),state:custody.state,epoch:custody.epoch,current:()=>live,
   currentOrigin:async()=>{const url=(await chrome.tabs.get(tabId))?.url;if(url!==documentUrl)throw new Error('presentation_context_changed');return originOf(url)},
   prepare:custody.prepare,
   reserve:async(digest,expires)=>{
    const key='castalia-credential-presentations-v2',now=Math.floor(Date.now()/1000)
    const saved=(await chrome.storage.session.get(key))[key]??[]
    if(!Array.isArray(saved)||saved.some((x:any)=>typeof x?.digest!=='string'||!Number.isSafeInteger(x?.expires)))throw new Error('invalid_replay_state')
    const retained=saved.filter((x:any)=>x.expires>now)
    if(retained.some((x:any)=>x.digest===digest))throw new Error('credential_replay')
    if(retained.length>=4096)throw new Error('approval_capacity')
    await chrome.storage.session.set({[key]:[...retained,{digest,expires}]})
   },
   confirm:summary=>broker.confirm({summary,tabId,owner}),
  })
  port.onMessage.addListener((payload:unknown)=>{
   if(used||!live){fail(new Error('credential_replay'));return}used=true
   void handler(payload,origin).then(result=>{try{if(live)port.postMessage({ok:true,result})}finally{owner.cancel()}},fail)
  })
 })
 return {invalidate}
}
