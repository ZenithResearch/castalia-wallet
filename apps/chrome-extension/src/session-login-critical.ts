import {SESSION_LOGIN_LAUNCHES,verifyLoginOwner} from './session-login-broker.js';
import {readLoginSnapshot,loginSnapshotDigest} from './session-login-storage.js';
import {loginError,loginFailure} from './session-login-errors.js';
import type {createCustodyOperationQueue} from './custody-operation-queue.js';
export const LOGIN_CRITICAL_CLEANUP='castalia-session-login-critical-cleanup-v1';
type Row={schema:'castalia.session-login-critical-cleanup.v1';loginId:string;leaseId:string;popupDocumentId:string;windowId:number;documentUrl:string;expiresAtMs:number};
type Active={row:Row;port:any;resolve():void;timer:any;finishing?:Promise<void>;jobs:number;idle:Array<()=>void>;subtail:Promise<unknown>};
/** No key, authorization or approval is stored here. Persisted rows can ONLY
 * cause fencing after a crash. A permit exists solely in the current FIFO. */
export function installSessionLoginCritical(chrome:any,queue:ReturnType<typeof createCustodyOperationQueue>,options:{timeoutMs?:number}={}){
  const duration=Math.min(options.timeoutMs??20000,20000);
  let active:Active|null=null,blocked=false,recovering:Promise<void>|null=null;
  const failure=()=>loginFailure('session_login_context_changed','authorization');
  const block=()=>{blocked=true;const denied=Promise.reject(failure());queue.setBarrier(denied);};
  const rows=async():Promise<Record<string,Row>>=>{
    const value=(await chrome.storage.session.get(LOGIN_CRITICAL_CLEANUP))[LOGIN_CRITICAL_CLEANUP]??{};
    if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).length>8)throw failure();
    for(const [id,row]of Object.entries(value) as Array<[string,any]>){
      if(!/^[a-f0-9]{32}$/.test(id)||!row||Object.keys(row).sort().join(',')!=='documentUrl,expiresAtMs,leaseId,loginId,popupDocumentId,schema,windowId'||
        row.schema!=='castalia.session-login-critical-cleanup.v1'||row.leaseId!==id||!/^[a-f0-9]{32}$/.test(row.loginId)||
        typeof row.popupDocumentId!=='string'||!row.popupDocumentId||row.popupDocumentId.length>128||!Number.isInteger(row.windowId)||
        row.documentUrl!==chrome.runtime.getURL('src/session-login.html')+'?login='+row.loginId||!Number.isSafeInteger(row.expiresAtMs))throw failure();
    }
    return value;
  };
  const remove=async(id:string)=>{const value=await rows();delete value[id];await chrome.storage.session.set({[LOGIN_CRITICAL_CLEANUP]:value});};
  const fence=async(row:Pick<Row,'popupDocumentId'|'windowId'|'documentUrl'>)=>{
    const contexts=await chrome.runtime.getContexts({documentIds:[row.popupDocumentId]});
    if(!Array.isArray(contexts))throw failure();
    if(!contexts.length)return; // The old document and its dedicated Worker are gone.
    if(contexts.length!==1||contexts[0].documentId!==row.popupDocumentId||contexts[0].documentUrl!==row.documentUrl||contexts[0].windowId!==row.windowId||contexts[0].frameId!==0)throw failure();
    // Never close a reused window ID or another document. Browser removal
    // terminates the owner document's dedicated Worker before queue release.
    try{await chrome.windows.remove(row.windowId);}catch{}
    for(let n=0;n<10;n++){
      const remaining=await chrome.runtime.getContexts({documentIds:[row.popupDocumentId]});
      if(!Array.isArray(remaining))throw failure();
      if(!remaining.length)return;
      await new Promise(resolve=>setTimeout(resolve,20));
    }
    throw failure();
  };
  const finish=(a:Active,normal:boolean):Promise<void>=>{
    if(a.finishing)return a.finishing;
    a.finishing=(async()=>{
      clearTimeout(a.timer);
      try{
        if(!normal)await fence(a.row);
        if(a.jobs)await new Promise<void>(resolve=>a.idle.push(resolve));
        await remove(a.row.leaseId);
        if(active===a)active=null;
        try{a.port.postMessage({kind:'released',leaseId:a.row.leaseId});}catch{}
        a.resolve();
      }catch{block();throw failure();}
    })();void a.finishing.catch(()=>{});return a.finishing;
  };
  const recover=():Promise<void>=>{
    if(recovering)return recovering;
    recovering=(async()=>{
      try{
        // Recovery must not bypass an in-flight accepted storage job. Fence
        // first, prevent new sub-jobs, drain, then remove crash evidence.
        const previous=active;
        if(previous){clearTimeout(previous.timer);previous.finishing??=Promise.resolve();}
        const pending=await rows();
        for(const row of Object.values(pending))await fence(row);
        if(previous?.jobs)await new Promise<void>(resolve=>previous.idle.push(resolve));
        for(const row of Object.values(pending))await remove(row.leaseId);
        if(previous){if(active===previous)active=null;previous.resolve();}
        blocked=false;
      }catch{block();throw failure();}
      finally{recovering=null;}
    })();return recovering;
  };
  chrome.windows.onRemoved?.addListener(()=>{if(blocked&&!recovering)queue.setBarrier(recover());});
  chrome.runtime.onConnect.addListener((port:any)=>{
    if(port.name!=='castalia-session-login-critical-v1')return;
    let used=false,disconnected=false,owned:Active|null=null;
    port.onDisconnect.addListener(()=>{disconnected=true;if(owned)void finish(owned,false).catch(()=>{});});
    port.onMessage.addListener((message:any)=>{
      if(used){
        if(owned&&message?.kind==='complete'&&Object.keys(message).sort().join(',')==='kind,leaseId,phase_closed'&&message.leaseId===owned.row.leaseId&&message.phase_closed===true)
          void finish(owned,true).catch(()=>{});
        return;
      }
      used=true;
      const operation=async()=>{
        if(disconnected||blocked||active||!message||Object.keys(message).sort().join(',')!=='expectedSnapshot,kind,leaseId,loginId'||message.kind!=='acquire'||
          typeof message.loginId!=='string'||!/^[a-f0-9]{32}$/.test(message.loginId)||typeof message.leaseId!=='string'||!/^[a-f0-9]{32}$/.test(message.leaseId)||
          typeof message.expectedSnapshot!=='string'||!/^[a-f0-9]{64}$/.test(message.expectedSnapshot))throw failure();
        const entries=(await chrome.storage.session.get(SESSION_LOGIN_LAUNCHES))[SESSION_LOGIN_LAUNCHES]??{},entry=entries[message.loginId],sender=port.sender;
        if(!entry||sender?.id!==chrome.runtime.id||sender.documentId!==entry.popupDocumentId||sender.url!==chrome.runtime.getURL('src/session-login.html')+'?login='+message.loginId)throw failure();
        await verifyLoginOwner(chrome,entry,sender.documentId);
        if(disconnected||await loginSnapshotDigest(await readLoginSnapshot(chrome))!==message.expectedSnapshot)throw failure();
        const row:Row={schema:'castalia.session-login-critical-cleanup.v1',loginId:message.loginId,leaseId:message.leaseId,
          popupDocumentId:sender.documentId,windowId:entry.windowId,documentUrl:sender.url,expiresAtMs:Date.now()+duration};
        const saved=await rows();if(saved[row.leaseId]||Object.keys(saved).length>=8)throw failure();saved[row.leaseId]=row;
        await chrome.storage.session.set({[LOGIN_CRITICAL_CLEANUP]:saved});
        if(disconnected){try{await fence(row);await remove(row.leaseId);}catch{block();}throw failure();}
        await new Promise<void>(resolve=>{
          const a:Active={row,port,resolve,timer:null,jobs:0,idle:[],subtail:Promise.resolve()};active=owned=a;
          a.timer=setTimeout(()=>void finish(a,false).catch(()=>{}),duration);
          try{port.postMessage({kind:'granted',leaseId:row.leaseId,expiresAtMs:row.expiresAtMs});}catch{void finish(a,false).catch(()=>{});}
        });
      };
      void queue.run(operation).catch(error=>{try{port.postMessage({kind:'failed',error:loginError(error,'authorization')});}catch{}});
    });
  });
  return {
    recover,
    async within(owner:any,operation:()=>Promise<void>){
      const a=active;
      if(!a||a.finishing||blocked||a.row.leaseId!==owner.leaseId||a.row.popupDocumentId!==owner.popupDocumentId||a.row.loginId!==owner.entry.loginId||Date.now()>=a.row.expiresAtMs)throw failure();
      a.jobs++;
      const run=async()=>{
        if(active!==a||a.finishing||Date.now()>=a.row.expiresAtMs)throw failure();
        await verifyLoginOwner(chrome,owner.entry,owner.popupDocumentId);
        if(a.finishing||Date.now()>=a.row.expiresAtMs)throw failure();
        await operation();
      };
      const job=a.subtail.then(run,run);a.subtail=job.then(()=>{},()=>{});
      try{await job;}finally{a.jobs--;if(!a.jobs)for(const resolve of a.idle.splice(0))resolve();}
    },
    async fenceReviews(){
      const entries=(await chrome.storage.session.get(SESSION_LOGIN_LAUNCHES))[SESSION_LOGIN_LAUNCHES]??{};
      try{for(const entry of Object.values(entries) as any[]){
        if(entry.popupDocumentId)await fence({popupDocumentId:entry.popupDocumentId,windowId:entry.windowId,documentUrl:chrome.runtime.getURL('src/session-login.html')+'?login='+entry.loginId});
      }}catch{block();throw failure();}
    },
  };
}
