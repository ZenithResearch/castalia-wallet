import { createProviderProfileStore, parseProviderProfile, providerProfileBytes } from '@castalia-wallet/provider-types';
import { CUSTODY_STORAGE_KEY } from './state/custody-state.js';
import { SESSION_LOGIN_LAUNCHES, SESSION_LOGIN_INVALIDATION } from './session-login-broker.js';
import { loginError, loginFailure } from './session-login-errors.js';
import type { LoginSnapshot } from './session-login-signer.js';
import {createSessionLoginPermit} from './session-login-permit.js';
import {readLoginSnapshot,loginSnapshotDigest} from './session-login-storage.js';
const PROFILES='castalia-provider-profiles-v1',INSTALLATION='castalia-read-installation-v1',JOURNAL='castalia-session-login-recovery-v1',ACCESS='castalia-session-login-access-recovery-v1';
const randomId=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('');
const stable=(v:any):string=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(stable).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+stable(v[k])).join(',')+'}';
/** Extension-owned host. Only encrypted records enter the private Worker.
 * No private Worker command is exposed to the browser page. */
export async function createSessionLoginPopupHost(chrome:any,id:string,makeWorker:()=>Worker,onState:(v:any)=>void) {
  if(!/^[a-f0-9]{32}$/.test(id))throw loginFailure('invalid_session_login_request','request');
  const own=await chrome.windows.getCurrent();let entry:any;
  // Public launch routing may commit just after the popup document loads.
  for(let n=0;n<40;n++){
    entry=(await chrome.storage.session.get(SESSION_LOGIN_LAUNCHES))[SESSION_LOGIN_LAUNCHES]?.[id];
    if(entry?.windowId===own.id)break;
    await new Promise(r=>setTimeout(r,50));
  }
  if(!entry||entry.windowId!==own.id||entry.loginId!==id||entry.deadlineMs<=Date.now())throw loginFailure('session_login_expired','request');
  const claim=await chrome.runtime.sendMessage({type:'SESSION_LOGIN_CLAIM',loginId:id});
  if(!claim?.ok)throw Object.assign(new Error('session_login_context_changed'),claim?.error);
  let disposed=false,approving=false,ownTrust=false,ownGrant=false,request:any=null,completion:any=null;
  let readyResolve:()=>void;const connected=new Promise<void>(r=>{readyResolve=r;});
  const port=chrome.tabs.connect(entry.tabId,{name:'castalia-session-login-v1',documentId:entry.documentId,frameId:0});
  const privateWorker=makeWorker();const jobs=new Map<string,{resolve(v:any):void;reject(e:any):void;timer:any}>();
  const guards=new Map<string,{resolve():void;reject(e:any):void;timer:any}>();
  const command=(operation:string,value?:unknown,permit?:{leaseId:string;expiresAtMs:number})=>new Promise<any>((resolve,reject)=>{
    if(disposed||jobs.size>=4){reject(loginFailure('session_login_context_changed','request',approving));return;}
    const job=randomId(),timer=setTimeout(()=>{jobs.delete(job);dispose(loginFailure('session_login_expired','request',approving));reject(loginFailure('session_login_expired','request',approving));},25000);
    jobs.set(job,{resolve,reject,timer});privateWorker.postMessage({kind:'command',id:job,operation,value,permit});
  });
  const signal=(message:any)=>{if(!disposed)port.postMessage(message);};
  const dispose=(error?:unknown)=>{
    if(disposed)return;
    if(error)try{signal({kind:'failed',error:loginError(error,'request',approving)});}catch{}
    disposed=true;clearTimeout(deadline);privateWorker.terminate();
    chrome.storage.onChanged.removeListener(changed);
    for(const w of [...jobs.values(),...guards.values()]){clearTimeout(w.timer);w.reject(loginFailure('session_login_context_changed','request',approving));}
    jobs.clear();guards.clear();try{port.disconnect();}catch{}
    void chrome.runtime.sendMessage({type:'SESSION_LOGIN_CLOSE',loginId:id}).catch(()=>{});
  };
  const snapshot=():Promise<LoginSnapshot>=>readLoginSnapshot(chrome);
  const guard=async()=>{
    if(disposed||Date.now()>=entry.deadlineMs)throw loginFailure('session_login_expired','request');
    const tab=await chrome.tabs.get(entry.tabId);
    if(tab?.status==='loading'||typeof tab?.url!=='string'||tab.url.split('#',1)[0]!==entry.url.split('#',1)[0])throw loginFailure('session_login_context_changed','request');
    await new Promise<void>((resolve,reject)=>{
      const nonce=randomId(),timer=setTimeout(()=>{guards.delete(nonce);reject(loginFailure('session_login_context_changed','request'));},2000);
      guards.set(nonce,{resolve,reject,timer});signal({kind:'guard',nonce});
    });
    if(disposed)throw loginFailure('session_login_context_changed','request');
    return snapshot();
  };
  const permit=createSessionLoginPermit(chrome,id,async()=>loginSnapshotDigest(await guard()),()=>dispose(loginFailure('session_login_context_changed','authorization',approving)));
  const criticalCommand=(operation:string)=>permit.run(token=>command(operation,undefined,token));
  const journal=async(value:any)=>navigator.locks.request('castalia-login-session-journal',async()=>{
    const fields=['schema','origin','service','request_id','challenge_id','session_public_key','session_installation_id','expires_at'];
    if(!value||Object.keys(value).sort().join(',')!==fields.sort().join(',')||
      value.schema!=='castalia.session-login-recovery.v1'||value.origin!==entry.origin||value.service!==request.service||
      !['request_id','challenge_id','session_installation_id'].every(k=>typeof value[k]==='string'&&/^[a-f0-9]{32}$/.test(value[k]))||
      !/^[a-f0-9]{64}$/.test(value.session_public_key)||!Number.isSafeInteger(value.expires_at)||value.expires_at>Math.floor(Date.now()/1000)+3600)throw loginFailure('invalid_holder_session','authorization');
    const stored=(await chrome.storage.session.get(JOURNAL))[JOURNAL]??{};
    const records:Record<string,any>={};for(const [key,v]of Object.entries(stored) as Array<[string,any]>)if(v?.expires_at>Math.floor(Date.now()/1000))records[key]=v;
    if(Object.keys(records).length>=8&&!records[id])throw loginFailure('session_login_busy','authorization');
    if(records[id]&&stable(records[id])!==stable(value))throw loginFailure('session_login_context_changed','authorization');
    records[id]=structuredClone(value);await chrome.storage.session.set({[JOURNAL]:records});
  });
  const accessRecord=async(value?:any)=>navigator.locks.request('castalia-login-access-journal',async()=>{
    const s=await guard();if(!s.custody)throw loginFailure('wallet_not_setup','access');
    const key=stable([entry.request.service,s.custody.publicKey,s.installation]);
    const records=(await chrome.storage.session.get(ACCESS))[ACCESS]??{};
    if(value===undefined)return records[key]??null;
    if(!value||Object.keys(value).sort().join(',')!=='action,installation_id,intent,request_id,schema,subject_public_key'||
      value.schema!==entry.request.access_request?.request_schema||value.action!=='submit'||value.subject_public_key!==s.custody.publicKey||
      value.installation_id!==s.installation||value.intent!==null||typeof value.request_id!=='string'||!/^[a-f0-9]{32}$/.test(value.request_id))throw loginFailure('invalid_session_login_request','access');
    if(records[key]&&stable(records[key])!==stable(value)||!records[key]&&Object.keys(records).length>=8)throw loginFailure('session_login_busy','access');
    records[key]=value;await chrome.storage.session.set({[ACCESS]:records});return null;
  });
  let acknowledgeUncertain=false;
  const ENROLLMENT='castalia-session-login-enrollment-recovery-v1';
  const enrollmentState=async()=>{
    if(acknowledgeUncertain)return {count:0};
    const s=await guard(),records=(await chrome.storage.session.get(ENROLLMENT))[ENROLLMENT]??{};
    const matching=Object.values(records).filter((v:any)=>v?.service===request.service&&v.holder_public_key===s.custody?.publicKey&&v.installation_id===s.installation);
    return {count:matching.length};
  };
  const clearEnrollment=async()=>navigator.locks.request('castalia-login-enrollment-journal',async()=>{const records=(await chrome.storage.session.get(ENROLLMENT))[ENROLLMENT]??{};delete records[id];await chrome.storage.session.set({[ENROLLMENT]:records});});
  const journalEnrollment=async(value:any)=>navigator.locks.request('castalia-login-enrollment-journal',async()=>{
    const s=await guard();
    if(!value||Object.keys(value).sort().join(',')!=='challenge_digest,expires_at,holder_public_key,installation_id,origin,request_id,schema,service'||
      value.schema!=='castalia.session-login-enrollment-recovery.v1'||value.service!==request.service||value.origin!==entry.origin||
      value.holder_public_key!==s.custody?.publicKey||value.installation_id!==s.installation||
      typeof value.request_id!=='string'||!/^[a-f0-9]{32}$/.test(value.request_id)||typeof value.challenge_digest!=='string'||!/^[a-f0-9]{64}$/.test(value.challenge_digest)||
      !Number.isSafeInteger(value.expires_at)||value.expires_at>Math.floor(Date.now()/1000)+120)throw loginFailure('invalid_session_login_request','enrollment');
    const key=ENROLLMENT;
    const stored=(await chrome.storage.session.get(key))[key]??{},records:Record<string,any>={};
    for(const [k,v]of Object.entries(stored))records[k]=v; // Challenge expiry does not prove issuance failed.
    if(Object.keys(records).length>=8&&!records[id])throw loginFailure('session_login_busy','enrollment');
    if(records[id]&&stable(records[id])!==stable(value))throw loginFailure('session_login_context_changed','enrollment');
    records[id]=value;await chrome.storage.session.set({[key]:records});
  });
  const saveGrants=async(value:any)=>{
    if(!value||Object.keys(value).sort().join(',')!=='expectedRevision,record')throw loginFailure('invalid_session_login_request','save_grant');
    const before=await guard();if(!before.custody)throw loginFailure('wallet_not_setup','save_grant');
    const input={owner:before.custody.publicKey,expectedRevision:value.expectedRevision,expectedSnapshot:await loginSnapshotDigest(before),record:value.record};
    ownGrant=true;
    try{const result=await chrome.runtime.sendMessage({type:'SESSION_LOGIN_SAVE_GRANTS',loginId:id,leaseId:permit.current().leaseId,input});if(!result?.ok)throw Object.assign(new Error('session_login_context_changed'),result?.error);return snapshot();}
    finally{ownGrant=false;}
  };
  const changed=(changes:any,area:string)=>{
    if(area!=='local')return;
    const relevant=Object.keys(changes).some(k=>k===CUSTODY_STORAGE_KEY||k===INSTALLATION||k===SESSION_LOGIN_INVALIDATION||k.startsWith('castalia-holder-grants-v1:')&&!ownGrant||k===PROFILES&&!ownTrust);
    if(relevant){dispose(loginFailure('session_login_context_changed','request'));onState({stage:'failed',message:'Wallet, trust or grants changed. Start a new login.'});}
  };
  chrome.storage.onChanged.addListener(changed);
  const deadline=setTimeout(()=>{dispose(loginFailure('session_login_expired','request'));onState({stage:'failed',message:'This login has expired. Start again from the application.'});},Math.max(0,entry.deadlineMs-Date.now()));
  port.onDisconnect.addListener(()=>{dispose();onState({stage:'closed'});});
  port.onMessage.addListener((m:any)=>{
    if(disposed)return;
    if(m?.kind==='context'&&m.loginId===id&&stable(m.request)===stable(entry.request)&&!request){request=m.request;readyResolve();return;}
    if(m?.kind==='guarded'){
      const g=guards.get(m.nonce);if(g){guards.delete(m.nonce);clearTimeout(g.timer);g.resolve();}return;
    }
    if(m?.kind==='complete'&&request&&!completion){
      completion=m.request;
      void command('proof',completion).then(({summary})=>onState({stage:'review',summary}),error=>{dispose(error);onState({stage:'failed',error:loginError(error,'possession')});});return;
    }
    dispose(loginFailure('invalid_session_login_request','request'));
  });
  privateWorker.onmessage=(event:MessageEvent)=>{
    const m=event.data;
    if(m?.kind==='result'){
      const w=jobs.get(m.id);if(!w)return;jobs.delete(m.id);clearTimeout(w.timer);
      if(m.ok)w.resolve(m.value);else w.reject(Object.assign(new Error(m.error?.code??'session_login_failed'),m.error));return;
    }
    if(m?.kind==='host'){
      const execute=async()=>{
        if(disposed)throw loginFailure('session_login_context_changed','request',approving);
        if(m.method==='critical')return permit.check(m.value?.leaseId);
        if(m.method==='beforeSessionDispatch'){permit.check(m.value?.leaseId);approving=true;return null;}
        if(m.method==='snapshot')return snapshot();
        if(m.method==='guard')return guard();
        if(m.method==='journal')return journal(m.value);
        if(m.method==='accessRecord')return accessRecord();
        if(m.method==='saveAccessRecord')return accessRecord(m.value);
        if(m.method==='enrollmentState')return enrollmentState();
        if(m.method==='clearEnrollment')return clearEnrollment();
        if(m.method==='journalEnrollment')return journalEnrollment(m.value);
        if(m.method==='saveGrants')return saveGrants(m.value);
        throw loginFailure('invalid_session_login_request','request');
      };
      void execute().then(value=>{if(!disposed)privateWorker.postMessage({kind:'host_result',id:m.id,ok:true,value});},error=>{if(!disposed)privateWorker.postMessage({kind:'host_result',id:m.id,ok:false,error:loginError(error,'request',false)});});
    }
  };
  privateWorker.onerror=()=>{dispose(loginFailure('session_login_failed','request'));onState({stage:'failed',message:'The Wallet signer stopped. Return to the application.'});};
  try{
    await Promise.race([connected,new Promise((_,reject)=>setTimeout(()=>reject(loginFailure('session_login_context_changed','request')),2500))]);
    await guard();await command('initialize',{origin:entry.origin,deadline:Math.floor(entry.deadlineMs/1000)});
  }catch(error){dispose(error);throw error;}
  let candidate:ReturnType<typeof parseProviderProfile>|null;
  try{
    const profile=entry.request.profile===undefined?null:parseProviderProfile(entry.request.profile);
    candidate=profile?parseProviderProfile({...profile,membership:null}):null;
    if(candidate&&(candidate.origins.length!==1||candidate.origins[0]!==entry.origin))throw loginFailure('issuer_setup_required','provider');
  }catch(error){dispose(error);throw error;}
  const trusted=async()=>{
    if(!candidate)return true;
    const s=await snapshot();return (s.profiles as any)?.profiles?.some((p:any)=>p.active&&providerProfileBytes(p.profile)===providerProfileBytes(candidate))===true;
  };
  const prepare=async(ttlSeconds?:number)=>{
    onState({stage:'preparing'});
    try{const result=await command('prepare',{request,ttlSeconds});if(result.options){onState({stage:'lifetime',options:result.options,grantDescriptor:request.grant_acquisition,canForget:true});return;}signal({kind:'prepared',result:{schema:'castalia.session-login-prepared.v1',loginId:id,challenge:result.challenge}});onState({stage:'waiting_proof'});}
    catch(error){
      const e=loginError(error,'challenge');
      if(['grant_not_saved','holder_session_parent_unsupported'].includes(e.code)||request.grant_acquisition&&['invalid_holder_session','session_login_failed','read_approval_expired'].includes(e.code))onState({stage:'access_required',descriptor:request.access_request,grantDescriptor:request.grant_acquisition,canForget:e.code!=='grant_not_saved',error:e.code==='grant_not_saved'?undefined:e});
      else {dispose(error);onState({stage:'failed',error:e});}
    }
  };
  return {
    origin:entry.origin,profile:candidate,
    async unlock(passphrase:string){
      onState({stage:'unlocking'});
      try{await command('unlock',passphrase);if(!await trusted())onState({stage:'provider',profile:candidate});else await prepare();}
      catch(error){onState({stage:'unlock',error:loginError(error,'unlock')});}
    },
    async trust(){
      ownTrust=true;
      try{await guard();const result=await chrome.runtime.sendMessage({type:'SESSION_LOGIN_TRUST',loginId:id});if(!result?.ok)throw result?.error;
        await command('refreshTrust');ownTrust=false;await prepare();
      }catch(error){ownTrust=false;dispose(error);onState({stage:'failed',error:loginError(error,'provider')});}
    },
    async approve(){
      onState({stage:'opening'});
      try{const result=await criticalCommand('approve');approving=false;signal({kind:'opened',result});dispose();onState({stage:'done'});}
      catch(error){const e=loginError(error,'authorization');approving=false;dispose(e);onState({stage:'failed',error:e});}
    },
    async chooseLifetime(seconds:number){await prepare(seconds);},
    async requestAccess(sendOriginal=false){
      onState({stage:'preparing'});
      try{const value=await command('prepareAccess',sendOriginal);onState({stage:'access_review',...value,descriptor:request.access_request});}
      catch(error){onState({stage:'access_required',descriptor:request.access_request,grantDescriptor:request.grant_acquisition,error:loginError(error,'access')});}
    },
    async confirmRequest(){
      onState({stage:'preparing'});
      try{const result=await criticalCommand('approveAccess');onState({stage:'access_pending',result,descriptor:request.access_request,grantDescriptor:request.grant_acquisition});}
      catch(error){onState({stage:'access_pending',descriptor:request.access_request,grantDescriptor:request.grant_acquisition,error:loginError(error,'access')});}
    },
    async acknowledgeEnrollment(){acknowledgeUncertain=true;await this.prepareGrant();},
    async reviewForget(){
      onState({stage:'preparing'});
      try{const result=await command('reviewForget');onState({stage:'forget_review',...result});}
      catch(error){dispose(error);onState({stage:'failed',error:loginError(error,'save_grant')});}
    },
    async cancelForget(){await command('cancelForget');await prepare();},
    async forget(){
      onState({stage:'opening'});
      try{await criticalCommand('forget');await prepare();}
      catch(error){dispose(error);onState({stage:'failed',error:loginError(error,'save_grant')});}
    },
    async prepareGrant(){
      onState({stage:'preparing'});
      try{const result=await command('prepareGrant');onState({stage:result.uncertain?'grant_uncertain':'grant_review',...result});}
      catch(error){onState({stage:'access_required',descriptor:request.access_request,grantDescriptor:request.grant_acquisition,error:loginError(error,'enrollment')});}
    },
    async obtainGrant(){
      onState({stage:'opening'});
      try{const result=await criticalCommand('obtainGrant');onState({stage:'save_grant',...result});}
      catch(error){onState({stage:'grant_recovery',error:loginError(error,'enrollment')});}
    },
    async recoverGrant(){
      onState({stage:'preparing'});
      try{const result=await criticalCommand('recoverGrant');onState({stage:'save_grant',...result});}
      catch(error){onState({stage:'grant_recovery',error:loginError(error,'enrollment')});}
    },
    async saveGrant(){
      onState({stage:'opening'});
      try{await criticalCommand('saveGrant');await prepare();}
      catch(error){dispose(error);onState({stage:'failed',error:loginError(error,'save_grant')});}
    },
    cancel(){dispose(loginFailure('session_login_cancelled','consent'));onState({stage:'closed'});},
    dispose,
  };
}
