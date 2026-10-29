import assert from 'node:assert/strict';
import test from 'node:test';
import {installReadAccessRuntime} from '../src/read-access-runtime.js';
function event(){const listeners=new Set<(...args:any[])=>any>();return{addListener:(f:any)=>listeners.add(f),removeListener:(f:any)=>listeners.delete(f),emit:(...args:any[])=>{for(const f of [...listeners])f(...args);}};}
async function fixture(operation:'request'|'approve',lifetime=30,failOpen=false){
 let now=1_792_390_000_000,signs=0,disposals=0,epoch=1;
 const realNow=Date.now;Date.now=()=>now;
 const origin='https://graph.example',documentUrl=origin+'/monitor',windows:string[]=[],replies:any[]=[],changes=event();
 const chrome:any={runtime:{id:'test-wallet',getURL:(p:string)=>'chrome-extension://test-wallet/'+p,onConnect:event(),onMessage:event()},tabs:{get:async()=>({url:documentUrl}),onUpdated:event(),onRemoved:event()},windows:{create:async({url}:any)=>{windows.push(url);if(failOpen)throw Error('raw platform error');return{id:77};},remove:async()=>{},onRemoved:event()}};
 const expires=Math.floor(now/1000)+lifetime;
 const prepare=async()=>({summary:()=>({permissions:[],expires_at:expires+300,approval_expires_at:expires}),approve:()=>{signs++;return{challenge:{},signature:'test-only'};},accept:()=>({}),present:()=>({}),dispose:()=>{disposals++;}});
 installReadAccessRuntime(chrome,{run:async(f:any)=>f(),state:async()=>({memberKey:'a'.repeat(64),approvedOrigins:new Set([origin])}),epoch:()=>epoch,onChange:(f:any)=>changes.addListener(f),installation:async()=> 'b'.repeat(32),memberships:async()=>[],membership:async()=>({fixture:true}),prepare,prepareRequest:prepare});
 let disconnected=false;
 const port:any={name:'castalia-read-access-v1',sender:{id:chrome.runtime.id,frameId:0,documentId:'document',documentLifecycle:'active',url:documentUrl,tab:{id:1,url:documentUrl}},onMessage:event(),onDisconnect:event(),postMessage:(r:any)=>replies.push(r),disconnect:()=>{if(!disconnected){disconnected=true;port.onDisconnect.emit();}}};
 chrome.runtime.onConnect.emit(port);port.onMessage.emit({operation,challenge:{}});
 const flush=async()=>{for(let i=0;i<50;i++)await Promise.resolve();};await flush();
 const message=(type:string,approved?:boolean)=>{let result:any;chrome.runtime.onMessage.emit({type,requestId:new URL(windows[0]).searchParams.get('request'),approved},{id:chrome.runtime.id,url:windows[0]},(r:any)=>{result=r;});return result;};
 return{windows,replies,expires,message,flush,signs:()=>signs,disposals:()=>disposals,advance:(seconds:number)=>{now+=seconds*1000;},lock:()=>{epoch++;changes.emit();},cleanup:()=>{port.disconnect();Date.now=realNow;}};
}
for(const operation of ['approve','request'] as const){
 test(operation+' runtime opens a claimed Wallet dialog and signs only after explicit decision',async()=>{
  const f=await fixture(operation);try{assert.equal(f.windows.length,1);assert.equal(f.signs(),0);const claimed=f.message('GET_READ_ACCESS_CONFIRMATION');assert.equal(claimed.ok,true);assert.equal(claimed.summary.expiresAt,f.expires);assert.equal(f.message('RESOLVE_READ_ACCESS_CONFIRMATION',true).ok,true);await f.flush();assert.equal(f.signs(),1);assert.equal(f.replies[0].ok,true);}finally{f.cleanup();}
 });
 test(operation+' runtime respects the actual short approval deadline, not a second conversion to milliseconds',async()=>{
  const f=await fixture(operation);try{assert.equal(f.windows.length,1);f.advance(30);assert.equal(f.message('GET_READ_ACCESS_CONFIRMATION').ok,false);await f.flush();assert.equal(f.signs(),0);assert.equal(f.disposals(),1);}finally{f.cleanup();}
 });
 test(operation+' runtime cancels an open dialog when custody changes',async()=>{
  const f=await fixture(operation);try{assert.equal(f.windows.length,1);f.lock();await f.flush();assert.equal(f.message('RESOLVE_READ_ACCESS_CONFIRMATION',true).ok,false);assert.equal(f.signs(),0);}finally{f.cleanup();}
 });
}

test('read runtime reports a failed popup instead of pretending the user cancelled',async()=>{const f=await fixture('approve',30,true);try{await f.flush();assert.equal(f.signs(),0);assert.equal(f.replies[0]?.ok,false);assert.equal(f.replies[0]?.error,'approval_unavailable');assert.equal(f.disposals(),1);}finally{f.cleanup();}});

async function grantFixture() {
 const origin='https://graph.example', base=origin+'/monitor?view=work';
 let url=base+'#overview', epoch=1, presentations=0, now=Date.now();
 const realNow=Date.now;Date.now=()=>now;
 const notifications:any[]=[], ports:any[]=[], windows:string[]=[];
 const chrome:any={runtime:{id:'test-wallet',getURL:(p:string)=>'chrome-extension://test-wallet/'+p,onConnect:event(),onMessage:event()},tabs:{get:async()=>({url}),sendMessage:async(...args:any[])=>{notifications.push(args);},onUpdated:event(),onRemoved:event()},windows:{create:async({url}:any)=>{windows.push(url);return{id:77};},remove:async()=>{},onRemoved:event()}};
 const changes=event(), expires=Math.floor(Date.now()/1000)+60;
 installReadAccessRuntime(chrome,{run:async(f:any)=>f(),state:async()=>({memberKey:'a'.repeat(64),approvedOrigins:new Set([origin])}),epoch:()=>epoch,onChange:(f:any)=>changes.addListener(f),installation:async()=> 'b'.repeat(32),holderGrants:{prepare:async()=>({summary:{},expires}),activate:async()=>({expires_at:expires,stored:{},credential:{}}),present:async()=>({nonce:++presentations})}});
 const flush=async()=>{for(let i=0;i<80;i++)await Promise.resolve();};
 const open=(payload:any,documentId='document')=>{
  const replies:any[]=[];let disconnected=false;
  const port:any={name:'castalia-read-access-v1',sender:{id:chrome.runtime.id,frameId:0,documentId,documentLifecycle:'active',url,tab:{id:1,url}},onMessage:event(),onDisconnect:event(),postMessage:(r:any)=>replies.push(r),disconnect:()=>{if(!disconnected){disconnected=true;port.onDisconnect.emit();}}};
  ports.push(port);chrome.runtime.onConnect.emit(port);port.onMessage.emit(payload);return replies;
 };
 const accept=()=>{const confirmation=windows.at(-1)!;for(const type of ['GET_READ_ACCESS_CONFIRMATION','RESOLVE_READ_ACCESS_CONFIRMATION'])chrome.runtime.onMessage.emit({type,requestId:new URL(confirmation).searchParams.get('request'),approved:true},{id:chrome.runtime.id,url:confirmation},()=>{});};
 return{base,expires,open,accept,flush,notifications,presentations:()=>presentations,advance:(seconds:number)=>{now+=seconds*1000;},navigate:(next:string,status?:string)=>{url=next;chrome.tabs.onUpdated.emit(1,{url,...(status?{status}:{})});},lock:()=>{epoch++;changes.emit();},close:()=>chrome.tabs.onRemoved.emit(1),cleanup:()=>{ports.forEach(p=>p.disconnect());Date.now=realNow;}};
}

test('a fragment change during approval and subsequent reads retains the same document and fixed expiry',async()=>{
 const f=await grantFixture();try{
  const approved=f.open({operation:'use_grant',service:'graph'});await f.flush();
  f.navigate(f.base+'#topology','loading');f.accept();await f.flush();
  assert.equal(approved[0]?.ok,true);
  const {accessId,expires_at}=approved[0].result;assert.equal(expires_at,f.expires);
  for(const fragment of ['#topology','#overview','#topology']){
   f.navigate(f.base+fragment);const read=f.open({operation:'present_grant',accessId,call:{fixture:true}});await f.flush();assert.equal(read[0]?.ok,true);
  }
  assert.equal(f.presentations(),3);assert.equal(f.notifications.length,0);
  f.advance(59);f.navigate(f.base+'#overview');
  const last=f.open({operation:'present_grant',accessId,call:{fixture:true}});await f.flush();assert.equal(last[0]?.ok,true);
  f.advance(1);f.navigate(f.base+'#topology');
  const expired=f.open({operation:'present_grant',accessId,call:{fixture:true}});await f.flush();assert.equal(expired[0]?.ok,false);
  assert.equal(f.presentations(),4,'using the connection or changing views must never move its expiry');
 }finally{f.cleanup();}
});

for(const boundary of ['path','query','origin','reload','document','lock','close'] as const){
 test('read access is still invalidated at the '+boundary+' boundary',async()=>{
  const f=await grantFixture();try{
   const approved=f.open({operation:'use_grant',service:'graph'});await f.flush();f.accept();await f.flush();assert.equal(approved[0]?.ok,true);
   const accessId=approved[0].result.accessId;
   if(boundary==='path')f.navigate('https://graph.example/other');
   if(boundary==='query')f.navigate(f.base+'&private=1');
   if(boundary==='origin')f.navigate('https://other.example/monitor');
   if(boundary==='reload')f.navigate(f.base+'#overview','loading');
   if(boundary==='lock')f.lock();if(boundary==='close')f.close();
   const read=f.open({operation:'present_grant',accessId,call:{fixture:true}},boundary==='document'?'replacement':'document');await f.flush();
   assert.equal(read[0]?.ok,false);assert.equal(f.presentations(),0);
  }finally{f.cleanup();}
 });
}
