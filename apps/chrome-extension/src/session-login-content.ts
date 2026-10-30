import { parseSessionLoginRequest, SESSION_LOGIN_CEREMONY_MS } from '@castalia-wallet/provider-types';
import { loginError, loginFailure } from './session-login-errors.js';
const plain = (v:any) => !!v && Object.getPrototypeOf(v) === Object.prototype;
const exact = (v:any, keys:string[]) => plain(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
/** Content-script memory owns the original document and both RPC replies.
 * The background worker only launches the popup, never holds this channel. */
export function createSessionLoginContent(chrome:any, page:Window, randomId=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('')) {
  let current: {id:string;request:any;reply:((value:any)=>void)|null;port:any;prepared:boolean;completing:boolean;timer:any}|null = null;
  const close = (error?:unknown) => {
    const c=current;if(!c)return;current=null;clearTimeout(c.timer);
    if(error&&c.reply)c.reply({ok:false,error:loginError(error,'request',c.completing)});
    try{c.port?.disconnect();}catch{}
  };
  page.addEventListener('pagehide',()=>close(loginFailure('session_login_context_changed','request')),{once:true});
  chrome.runtime.onMessage?.addListener((message:any,sender:any,respond:(v:any)=>void)=>{
    if(message?.type!=='SESSION_LOGIN_DOCUMENT_GUARD')return false;
    if(sender?.id===chrome.runtime.id&&typeof message.nonce==='string'&&/^[a-f0-9]{32}$/.test(message.nonce))
      respond({alive:current?.id===message.loginId,nonce:message.nonce});
    return false;
  });
  chrome.runtime.onConnect.addListener((port:any)=>{
    if(port.name!=='castalia-session-login-v1')return;
    const c=current;
    if(!c||c.port||port.sender?.id!==chrome.runtime.id||
      port.sender?.url!==chrome.runtime.getURL('src/session-login.html')+'?login='+c.id||
      port.sender.frameId!==undefined&&port.sender.frameId!==0){port.disconnect();return;}
    c.port=port;
    port.onDisconnect.addListener(()=>{if(current===c)close(loginFailure('session_login_cancelled','request'));});
    port.onMessage.addListener((message:any)=>{
      if(current!==c)return;
      try{
        if(new TextEncoder().encode(JSON.stringify(message)).length>131072)throw loginFailure('invalid_session_login_request','request');
        if(exact(message,['kind','nonce'])&&message.kind==='guard'&&typeof message.nonce==='string'&&/^[a-f0-9]{32}$/.test(message.nonce)){
          port.postMessage({kind:'guarded',nonce:message.nonce});return;
        }
        if(exact(message,['kind','result'])&&message.kind==='prepared'&&!c.prepared&&!c.completing&&
          exact(message.result,['schema','loginId','challenge'])&&message.result.schema==='castalia.session-login-prepared.v1'&&message.result.loginId===c.id&&plain(message.result.challenge)){
          c.prepared=true;const reply=c.reply;c.reply=null;reply?.({ok:true,result:structuredClone(message.result)});return;
        }
        if(exact(message,['kind','result'])&&message.kind==='opened'&&c.completing&&
          exact(message.result,['schema','credential'])&&message.result.schema==='castalia.holder-session-opened.v1'&&plain(message.result.credential)&&message.result.credential.claims?.schema==='secs.holder-session-credential.v1'){
          c.reply?.({ok:true,result:structuredClone(message.result)});c.reply=null;close();return;
        }
        if(exact(message,['kind','error'])&&message.kind==='failed'){
          c.reply?.({ok:false,error:loginError(message.error,'request')});c.reply=null;close();return;
        }
        throw loginFailure('invalid_session_login_request','request');
      }catch(error){close(error);}
    });
    port.postMessage({kind:'context',loginId:c.id,request:structuredClone(c.request)});
  });
  return { async handle(input:unknown, reply:(value:any)=>void, active:boolean) {
    let request;
    try { request=parseSessionLoginRequest(input); }
    catch(error){reply({ok:false,error:loginError(error,'request')});return;}
    if(request.operation==='cancel_session_login'){
      const c=current;
      if(!c||c.id!==request.loginId){reply({ok:false,error:loginError(loginFailure('session_login_context_changed','request'),'request')});return;}
      const dispatched=c.completing;
      close(loginFailure('session_login_cancelled','request'));
      reply({ok:true,result:{schema:'castalia.session-login-cancelled.v1',dispatched}});return;
    }
    if(request.operation==='complete_session_login'){
      const c=current;
      if(!c||!c.prepared||!c.port||c.id!==request.loginId){reply({ok:false,error:loginError(loginFailure('session_login_context_changed','possession'),'possession')});return;}
      if(c.completing){reply({ok:false,error:loginError(loginFailure('session_login_busy','possession'),'possession')});return;}
      c.completing=true;c.reply=reply;
      try{c.port.postMessage({kind:'complete',request});}catch(error){close(error);}
      return;
    }
    if(page.top!==page||!active){reply({ok:false,error:loginError(loginFailure('approval_required','request'),'request')});return;}
    if(current){reply({ok:false,error:loginError(loginFailure('session_login_busy','request'),'request')});return;}
    const id=request.loginId??randomId();
    const c={id,request,reply:reply as ((value:any)=>void)|null,port:null,prepared:false,completing:false,timer:null as any};current=c;
    c.timer=setTimeout(()=>{if(current===c)close(loginFailure('session_login_expired','request'));},SESSION_LOGIN_CEREMONY_MS);
    c.timer?.unref?.();
    try{
      const result=await chrome.runtime.sendMessage({type:'SESSION_LOGIN_LAUNCH',loginId:id,request});
      if(!result?.ok&&current===c)close(result?.error??loginFailure('session_login_failed','request'));
    }catch(error){if(current===c)close(error);}
  }};
}
