import { parseProviderProfile, parseSessionLoginRequest, SESSION_LOGIN_CEREMONY_MS } from '@castalia-wallet/provider-types';
import { loginError, loginFailure } from './session-login-errors.js';
export {SESSION_LOGIN_INVALIDATION} from './session-login-storage.js';
export const SESSION_LOGIN_LAUNCHES = 'castalia-session-login-launches-v1';
/** Enabled only after exact packaged browser/receiver qualification. */
export const SESSION_LOGIN_QUALIFIED = true;
export async function verifyLoginOwner(chrome:any,entry:any,popupDocumentId:string){
  if(entry.deadlineMs<=Date.now())throw loginFailure('session_login_expired','request');
  const url=chrome.runtime.getURL('src/session-login.html')+'?login='+entry.loginId;
  const contexts=await chrome.runtime.getContexts({documentIds:[popupDocumentId],documentUrls:[url],windowIds:[entry.windowId],frameIds:[0]});
  if(contexts.length!==1||contexts[0].documentId!==popupDocumentId||contexts[0].documentUrl!==url||contexts[0].windowId!==entry.windowId)throw loginFailure('session_login_context_changed','request');
  const nonce=Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('');
  const response=await Promise.race([chrome.tabs.sendMessage(entry.tabId,{type:'SESSION_LOGIN_DOCUMENT_GUARD',loginId:entry.loginId,nonce},{documentId:entry.documentId,frameId:0}),
    new Promise((_,reject)=>setTimeout(()=>reject(loginFailure('session_login_context_changed','request')),2000))]);
  if(response?.alive!==true||response.nonce!==nonce)throw loginFailure('session_login_context_changed','request');
}
/** Public routing metadata only. No custody, approval decision or authorization
 * is persisted here. Popup/content own the live ceremony after launch. */
export function installSessionLoginLauncher(chrome:any, now=Date.now, deps?:{trust(profile:unknown,owner?:any):Promise<unknown>;installation?():Promise<string>;saveGrants?(input:any,owner:any):Promise<void>}) {
  let tail=Promise.resolve();
  chrome.runtime.onMessage.addListener((message:any,sender:any,respond:(v:any)=>void)=>{
    if(!['SESSION_LOGIN_LAUNCH','SESSION_LOGIN_CLAIM','SESSION_LOGIN_TRUST','SESSION_LOGIN_CLOSE','SESSION_LOGIN_SAVE_GRANTS'].includes(message?.type))return false;
    const operation=async()=>{
      if(message.type!=='SESSION_LOGIN_LAUNCH'){
        const launches=(await chrome.storage.session.get(SESSION_LOGIN_LAUNCHES))[SESSION_LOGIN_LAUNCHES]??{};
        const e=launches[message.loginId];
        const expected=chrome.runtime.getURL('src/session-login.html')+'?login='+message.loginId;
        const keys=message.type==='SESSION_LOGIN_SAVE_GRANTS'?'input,leaseId,loginId,type':'loginId,type';
        if(Object.keys(message).sort().join(',')!==keys||!e||
          sender?.id!==chrome.runtime.id||sender.frameId!==undefined&&sender.frameId!==0||
          typeof sender.documentId!=='string'||!sender.documentId||sender.url!==expected)throw loginFailure('issuer_setup_required','provider');
        if(message.type==='SESSION_LOGIN_CLAIM'){
          if(e.deadlineMs<=now()||typeof chrome.runtime.getContexts!=='function'||e.popupDocumentId&&e.popupDocumentId!==sender.documentId)throw loginFailure('session_login_context_changed','request');
          const contexts=await chrome.runtime.getContexts({documentIds:[sender.documentId],documentUrls:[expected],windowIds:[e.windowId],frameIds:[0]});
          if(contexts.length!==1||contexts[0].windowId!==e.windowId||contexts[0].documentUrl!==expected||contexts[0].documentId!==sender.documentId||contexts[0].frameId!==0)throw loginFailure('session_login_context_changed','request');
          e.popupDocumentId=sender.documentId;await chrome.storage.session.set({[SESSION_LOGIN_LAUNCHES]:launches});return {ok:true};
        }
        if(e.popupDocumentId!==sender.documentId)throw loginFailure('session_login_context_changed','request');
        if(message.type==='SESSION_LOGIN_CLOSE'){delete launches[message.loginId];await chrome.storage.session.set({[SESSION_LOGIN_LAUNCHES]:launches});return {ok:true};}
        if(!deps||e.deadlineMs<=now())throw loginFailure('issuer_setup_required','provider');
        if(message.type==='SESSION_LOGIN_SAVE_GRANTS'){
          if(!deps.saveGrants||typeof message.leaseId!=='string'||!/^[a-f0-9]{32}$/.test(message.leaseId)||!message.input||Object.keys(message.input).sort().join(',')!=='expectedRevision,expectedSnapshot,owner,record')throw loginFailure('invalid_session_login_request','save_grant');
          await deps.saveGrants(message.input,{entry:structuredClone(e),popupDocumentId:sender.documentId,leaseId:message.leaseId});return {ok:true};
        }
        const candidate=parseProviderProfile(e.request.profile);
        if(candidate.origins.length!==1||candidate.origins[0]!==e.origin||!candidate.presentations.length)throw loginFailure('issuer_setup_required','provider');
        // This login only asks to trust presentation issuers. It does not join,
        // activate or import a membership from an application proposal.
        return {ok:true,profile:await deps.trust(parseProviderProfile({...candidate,membership:null}),{entry:structuredClone(e),popupDocumentId:sender.documentId})};
      }
      const request=parseSessionLoginRequest(message.request);
      if(Object.keys(message).sort().join(',')!=='loginId,request,type'||request.operation!=='open_session_login'||
        typeof message.loginId!=='string'||!/^[a-f0-9]{32}$/.test(message.loginId)||
        sender?.id!==chrome.runtime.id||sender.frameId!==0||!Number.isInteger(sender.tab?.id)||
        typeof sender.documentId!=='string'||!sender.documentId||
        sender.documentLifecycle&&sender.documentLifecycle!=='active'||request.loginId!==undefined&&request.loginId!==message.loginId)throw loginFailure('invalid_session_login_request','request');
      const url=new URL(sender.url),tab=await chrome.tabs.get(sender.tab.id);
      if(url.protocol!=='https:'||url.username||url.password||
        typeof tab?.url!=='string'||tab.status==='loading'||
        tab.url.split('#',1)[0]!==sender.url.split('#',1)[0]||
        sender.tab.url.split('#',1)[0]!==sender.url.split('#',1)[0])throw loginFailure('session_login_context_changed','request');
      const stored=(await chrome.storage.session.get(SESSION_LOGIN_LAUNCHES))[SESSION_LOGIN_LAUNCHES]??{};
      if(!stored||Object.getPrototypeOf(stored)!==Object.prototype||Object.keys(stored).length>8)throw loginFailure('session_login_busy','request');
      const launches:Record<string,any>={};
      // A closing document can lose its cleanup acknowledgement. Check actual
      // windows before retaining its non-authority routing entry. API failure
      // stays a failure; it must not be interpreted as a closed window.
      const windows=Object.keys(stored).length?await chrome.windows.getAll():[];
      if(!Array.isArray(windows)||windows.some((w:any)=>!Number.isInteger(w?.id)))throw loginFailure('session_login_context_changed','request');
      for(const [id,v]of Object.entries(stored) as Array<[string,any]>){
        if(v?.deadlineMs<=now())continue;
        if(Number.isInteger(v?.windowId)&&!windows.some((w:any)=>w.id===v.windowId))continue;
        launches[id]=v;
      }
      if(Object.keys(launches).length>=8||launches[message.loginId]||Object.values(launches).some(v=>v.tabId===sender.tab.id&&v.documentId===sender.documentId))throw loginFailure('session_login_busy','request');
      const entry={loginId:message.loginId,request,tabId:sender.tab.id,documentId:sender.documentId,
        origin:url.origin,url:sender.url,deadlineMs:now()+SESSION_LOGIN_CEREMONY_MS,windowId:null as number|null};
      launches[message.loginId]=entry;
      await deps?.installation?.();
      await chrome.storage.session.set({[SESSION_LOGIN_LAUNCHES]:launches});
      try{
        const window=await chrome.windows.create({url:chrome.runtime.getURL('src/session-login.html')+'?login='+message.loginId,type:'popup',width:560,height:760,focused:true});
        if(!Number.isInteger(window?.id))throw loginFailure('session_login_failed','request');
        entry.windowId=window.id;
        await chrome.storage.session.set({[SESSION_LOGIN_LAUNCHES]:launches});
        return {ok:true};
      }catch(error){delete launches[message.loginId];await chrome.storage.session.set({[SESSION_LOGIN_LAUNCHES]:launches});throw error;}
    };
    // Private save runs inside a held custody lease. Do not leave it behind a
    // different popup's trust operation waiting on that same global queue.
    const independent=['SESSION_LOGIN_TRUST','SESSION_LOGIN_SAVE_GRANTS'].includes(message.type);
    const result=independent?operation():tail.then(operation,operation);if(!independent)tail=result.then(()=>{},()=>{});
    void result.then(respond,error=>respond({ok:false,error:loginError(error,'request')}));
    return true;
  });
}
