import {isWalletIdentityPage} from './wallet-identities-store.js';
import type {createHolderGrantsStore} from './holder-grants-store.js';
type D={run<T>(f:()=>Promise<T>):Promise<T>;state():Promise<{owner:string}|null>;epoch():number;now():number;randomId():string;onChange(f:()=>void):unknown;store:ReturnType<typeof createHolderGrantsStore>};
/** Internal extension UI only. No public provider method, signing or revocation. */
export function installHolderGrantForgetRuntime(chrome:any,d:D){
 let pending:{token:string;owner:string;epoch:number;documentId:string;expires:number;prepared:Awaited<ReturnType<D['store']['reviewForget']>>}|null=null;
 d.onChange(()=>{pending=null;});
 chrome.runtime.onMessage.addListener((message:any,sender:any,respond:(v:any)=>void)=>{
  if(!['HOLDER_GRANTS_FORGET_REVIEW','HOLDER_GRANTS_FORGET_CONFIRM','HOLDER_GRANTS_FORGET_CANCEL'].includes(message?.type))return false;
  void d.run(async()=>{
   if(!isWalletIdentityPage(sender,chrome.runtime.id,chrome.runtime.getURL('src/holder-grants.html'))||sender.frameId!==0||typeof sender.documentId!=='string'||!sender.documentId||sender.documentId.length>128)throw Error('wallet_ui_required');
   const keys=message.type==='HOLDER_GRANTS_FORGET_REVIEW'?['service','type']:message.type==='HOLDER_GRANTS_FORGET_CONFIRM'?['token','type']:['type'];
   if(Object.keys(message).sort().join(',')!==keys.sort().join(','))throw Error('invalid_request');
   if(message.type==='HOLDER_GRANTS_FORGET_CANCEL'){if(pending?.documentId===sender.documentId)pending=null;return {};}
   const state=await d.state();if(!state)throw Error('wallet_locked');
   if(message.type==='HOLDER_GRANTS_FORGET_REVIEW'){
    pending=null;const epoch=d.epoch(),prepared=await d.store.reviewForget(message.service);
    if(epoch!==d.epoch()||prepared.owner!==state.owner)throw Error('wallet_changed_or_locked');
    const token=d.randomId();pending={token,owner:state.owner,epoch,documentId:sender.documentId,expires:d.now()+120000,prepared};
    return {token,service:prepared.service,grant:prepared.grant};
   }
   const p=pending;pending=null;
   if(!p||message.token!==p.token||p.owner!==state.owner||p.epoch!==d.epoch()||p.documentId!==sender.documentId||d.now()>=p.expires)throw Error('grant_review_expired');
   await d.store.forget(p.prepared);return {};
  }).then(value=>respond({ok:true,...value}),error=>respond({ok:false,error:error instanceof Error?error.message:'grant_operation_failed'}));return true;
 });
}
