import assert from 'node:assert/strict';
import test from 'node:test';
import { createSessionLoginContent } from '../src/session-login-content.js';
const request={operation:'open_session_login',service:'service:example',session_public_key:'a'.repeat(64),session_installation_id:'b'.repeat(32),requested_ttl_seconds:900};
function fixture(){
 const replies:any[]=[],sent:any[]=[];let connect:any,closed=0;
 const chrome={runtime:{id:'extension',getURL:(p:string)=>'chrome-extension://extension/'+p,sendMessage:async(v:any)=>{sent.push(v);return {ok:true}},onConnect:{addListener:(f:any)=>{connect=f}}}};
 const events=new Map<string,any>();const page:any={location:{origin:'https://graph.example'},addEventListener:(k:string,f:any)=>events.set(k,f)};page.top=page;
 const bridge=createSessionLoginContent(chrome,page,()=> 'c'.repeat(32));
 const listeners:any={};const port:any={name:'castalia-session-login-v1',sender:{id:'extension',url:'chrome-extension://extension/src/session-login.html?login='+ 'c'.repeat(32)},onMessage:{addListener:(f:any)=>listeners.message=f},onDisconnect:{addListener:(f:any)=>listeners.disconnect=f},postMessage:(v:any)=>sent.push(v),disconnect:()=>{closed++}};
 return{bridge,replies,sent,port,events,connect:()=>connect(port),message:(v:any)=>listeners.message(v),reply:(v:any)=>replies.push(v),closed:()=>closed};
}
test('one gesture owns one popup; direct channel carries both phases without the service worker',async()=>{
 const f=fixture();await f.bridge.handle(request,f.reply,true);assert.equal(f.sent.length,1);f.connect();
 const challenge={schema:'secs.holder-session-challenge.v1'};
 f.message({kind:'prepared',result:{schema:'castalia.session-login-prepared.v1',loginId:'c'.repeat(32),challenge}});
 assert.equal(f.replies[0].ok,true);
 await f.bridge.handle({operation:'complete_session_login',loginId:'c'.repeat(32),challenge,session_signature:'d'.repeat(128)},f.reply,false);
 assert.equal(f.sent.filter(v=>v.type==='SESSION_LOGIN_LAUNCH').length,1);
 f.message({kind:'opened',result:{schema:'castalia.holder-session-opened.v1',credential:{claims:{schema:'secs.holder-session-credential.v1'}}}});
 assert.equal(f.replies[1].ok,true);assert.equal(f.closed(),1);
});
test('duplicate, forged-popup and non-gesture opens cannot acquire a ceremony',async()=>{
 const f=fixture();await f.bridge.handle(request,f.reply,false);assert.equal(f.replies.pop().error.code,'approval_required');assert.equal(f.sent.length,0);
 await f.bridge.handle(request,f.reply,true);await f.bridge.handle(request,f.reply,true);assert.equal(f.replies.pop().error.code,'session_login_busy');
 f.port.sender.url='chrome-extension://extension/src/popup.html';f.connect();assert.equal(f.closed(),1);
});
test('navigation cancels original context and post-completion disconnect is uncertain',async()=>{
 const f=fixture();await f.bridge.handle(request,f.reply,true);f.connect();const c={schema:'secs.holder-session-challenge.v1'};
 f.message({kind:'prepared',result:{schema:'castalia.session-login-prepared.v1',loginId:'c'.repeat(32),challenge:c}});
 await f.bridge.handle({operation:'complete_session_login',loginId:'c'.repeat(32),challenge:c,session_signature:'d'.repeat(128)},f.reply,false);
 f.events.get('pagehide')();assert.equal(f.replies[1].error.dispatched,true);assert.equal(f.replies[1].error.code,'holder_session_outcome_unknown');
});
test('page can cancel its own correlated attempt before preparation but not another attempt',async()=>{
 const f=fixture(),id='c'.repeat(32);await f.bridge.handle({...request,loginId:id},f.reply,true);f.connect();
 await f.bridge.handle({operation:'cancel_session_login',loginId:'f'.repeat(32)},f.reply,false);assert.equal(f.replies.pop().ok,false);assert.equal(f.closed(),0);
 await f.bridge.handle({operation:'cancel_session_login',loginId:id},f.reply,false);
 assert.equal(f.replies[0].error.dispatched,false);assert.deepEqual(f.replies[1].result,{schema:'castalia.session-login-cancelled.v1',dispatched:false});assert.equal(f.closed(),1);
});
