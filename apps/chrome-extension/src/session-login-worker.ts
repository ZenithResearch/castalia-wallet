/** Private popup-lifetime signer. This script is not web-accessible. */
import { initSync, WasmWallet, servicePresentationContext } from './generated/castalia-wallet-core/bindings.js';
import { CASTALIA_WALLET_CORE_WASM } from './generated/castalia-wallet-core/wasm-bytes.js';
import { createProviderProfileStore } from '@castalia-wallet/provider-types';
import { createSessionLoginSigner, type LoginSnapshot } from './session-login-signer.js';
import { loginError } from './session-login-errors.js';
const worker=globalThis as any;
initSync({module:CASTALIA_WALLET_CORE_WASM});
let core:WasmWallet|null=null, signer:ReturnType<typeof createSessionLoginSigner>|null=null;
const waiting=new Map<string,{resolve(v:any):void;reject(e:unknown):void;timer:any}>();
const randomId=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('');
const host=(method:string,value?:unknown)=>new Promise<any>((resolve,reject)=>{
  if(waiting.size>=4){reject(Error('session_login_busy'));return;}
  const id=randomId();const timer=setTimeout(()=>{waiting.delete(id);reject(Error('session_login_context_changed'));},10000);
  waiting.set(id,{resolve,reject,timer});worker.postMessage({kind:'host',id,method,value});
});
let permit:{leaseId:string;expiresAtMs:number}|null=null;
const assertCritical=()=>{if(!permit||!/^[a-f0-9]{32}$/.test(permit.leaseId)||!Number.isSafeInteger(permit.expiresAtMs)||Date.now()>=permit.expiresAtMs||permit.expiresAtMs>Date.now()+20000)throw Error('session_login_context_changed');};
const critical=async()=>{assertCritical();await host('critical',{leaseId:permit!.leaseId});assertCritical();};
let tail=Promise.resolve();
worker.onmessage=(event:any)=>{
  const m=event.data;
  if(m?.kind==='host_result'){
    const w=waiting.get(m.id);if(!w)return;waiting.delete(m.id);clearTimeout(w.timer);
    if(m.ok)w.resolve(m.value);else w.reject(Object.assign(new Error(m.error?.code??'session_login_failed'),m.error));return;
  }
  if(m?.kind!=='command'||typeof m.id!=='string')return;
  const run=async()=>{
    if(m.operation==='initialize'){
      if(signer||!m.value||typeof m.value.origin!=='string'||!Number.isSafeInteger(m.value.deadline)||m.value.deadline>Math.floor(Date.now()/1000)+300)throw Error('invalid_session_login_request');
      core=new WasmWallet();signer=createSessionLoginSigner({core,servicePresentationContext,
        origin:m.value.origin,deadline:m.value.deadline,now:()=>Math.floor(Date.now()/1000),randomId,
        critical,assertCritical,beforeSessionDispatch:async()=>{await critical();await host('beforeSessionDispatch',{leaseId:permit!.leaseId});},snapshot:()=>host('snapshot'),guard:()=>host('guard'),journal:value=>host('journal',value),
        accessRecord:()=>host('accessRecord'),saveAccessRecord:value=>host('saveAccessRecord',value),fetchImpl:fetch,
        enrollmentState:()=>host('enrollmentState'),clearEnrollment:()=>host('clearEnrollment'),journalEnrollment:value=>host('journalEnrollment',value),saveGrants:(record,expectedRevision)=>host('saveGrants',{record,expectedRevision}),
        pins:async(snapshot:LoginSnapshot)=>createProviderProfileStore({read:async()=>snapshot.profiles,
          write:async()=>{throw Error('read only signer');},randomId,
          digest:async()=>{throw Error('not a membership operation');},verifyMembership:async()=>{throw Error('not a membership operation');},
        }).presentationPins(),
      });return null;
    }
    if(!signer)throw Error('session_login_context_changed');
    switch(m.operation){
      case 'unlock':return signer.unlock(m.value);
      case 'prepare':return signer.prepare(m.value.request,m.value.ttlSeconds);
      case 'proof':return signer.proof(m.value);
      case 'approve':return signer.approve();
      case 'refreshTrust':return signer.refreshTrust();
      case 'prepareAccess':return signer.prepareAccess(m.value===true);
      case 'approveAccess':return signer.approveAccess();
      case 'prepareGrant':return signer.prepareGrant();
      case 'obtainGrant':return signer.obtainGrant();
      case 'recoverGrant':return signer.recoverGrant();
      case 'saveGrant':return signer.saveGrant();
      case 'dispose':signer.dispose();signer=null;core?.free();core=null;return null;
      default:throw Error('invalid_session_login_request');
    }
  };
  const bounded=async()=>{
    const needs=['approve','approveAccess','obtainGrant','recoverGrant','saveGrant'].includes(m.operation);
    if(needs){permit=m.permit;assertCritical();}
    else if(m.permit!==undefined)throw Error('invalid_session_login_request');
    try{return await run();}finally{permit=null;}
  };
  const operation=tail.then(bounded,bounded);tail=operation.then(()=>{},()=>{});
  void operation.then(value=>worker.postMessage({kind:'result',id:m.id,ok:true,value}),error=>worker.postMessage({kind:'result',id:m.id,ok:false,error:loginError(error,'request')}));
};
