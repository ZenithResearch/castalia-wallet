import assert from 'node:assert/strict';
import test from 'node:test';
import {createReadAccessController} from '../src/read-access.js';

function fixture(){
 let now=1000,epoch=1,consents=0,activations=0,approved=true,afterConsent=()=>{};
 const challenge={schema:'secs.holder-session-challenge.v1',request_id:'d'.repeat(32),review_deadline:1030,expires_at:1060,permissions:[{operation:'fixture.read'}]};
 const context={origin:'https://graph.example',tabId:1,documentId:'one',current:()=>true,verify:async()=>{}};
 const controller=createReadAccessController({run:async f=>f(),state:async()=>({memberKey:'a'.repeat(64),approvedOrigins:new Set([context.origin])}),epoch:()=>epoch,installation:async()=>'b'.repeat(32),memberships:async()=>[],membership:async()=>({}),prepare:async()=>{throw Error('legacy signer must not be used')},confirm:async()=>{consents++;afterConsent();return approved},randomId:()=>'opaque-preparation',now:()=>now,holderSessions:{prepare:async()=>({challenge,summary:{permissions:challenge.permissions,expires_at:1060},privateRoot:'must-never-enter-page-result'}),activate:async()=>{activations++;return{credential:{claims:{schema:'secs.holder-session-credential.v1'}}}}}});
 const prepare={operation:'prepare_holder_session',service:'service:graph',session_public_key:'c'.repeat(64),session_installation_id:'e'.repeat(32),requested_ttl_seconds:60};
 const open=(p:any)=>({operation:'open_holder_session',preparationId:p.preparationId,challenge:p.challenge,session_signature:'f'.repeat(128)});
 return{controller,context,prepare,open,now:(value:number)=>{now=value},deny:()=>{approved=false},afterConsent:(f:()=>void)=>{afterConsent=f},lock:()=>{epoch++},counts:()=>({consents,activations})};
}
test('session preparation never returns parent authority and exchange waits for explicit Wallet approval',async()=>{
 const f=fixture(),p=await f.controller.handle(f.prepare,f.context);
 assert.deepEqual(Object.keys(p).sort(),['challenge','preparationId','schema']);assert.equal(JSON.stringify(p).includes('must-never'),false);assert.deepEqual(f.counts(),{consents:0,activations:0});
 const result=await f.controller.handle(f.open(p),f.context);assert.deepEqual(result,{schema:'castalia.holder-session-opened.v1',credential:{claims:{schema:'secs.holder-session-credential.v1'}}});assert.deepEqual(f.counts(),{consents:1,activations:1});
 await assert.rejects(f.controller.handle(f.open(p),f.context),/holder_session_preparation_required/);assert.equal(f.counts().activations,1);
});
test('denial never exchanges or changes a saved grant',async()=>{
 const f=fixture(),p=await f.controller.handle(f.prepare,f.context);f.deny();await assert.rejects(f.controller.handle(f.open(p),f.context),/approval_denied/);assert.equal(f.counts().activations,0);
});
test('concurrent open calls cannot exchange a preparation twice',async()=>{
 const f=fixture(),p=await f.controller.handle(f.prepare,f.context);
 const results=await Promise.allSettled([f.controller.handle(f.open(p),f.context),f.controller.handle(f.open(p),f.context)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(f.counts().activations,1);assert.equal(f.counts().consents,1);
});
for(const boundary of ['document','origin','challenge','expired','lock','invalidated','unknown'] as const){
 test('session exchange rejects the '+boundary+' boundary without signing',async()=>{
  const f=fixture(),p=await f.controller.handle(f.prepare,f.context),request=f.open(p),context={...f.context};
  if(boundary==='document')context.documentId='other';if(boundary==='origin')context.origin='https://other.example';
  if(boundary==='challenge')request.challenge={...request.challenge,expires_at:99999};
  if(boundary==='expired')f.afterConsent(()=>f.now(1030));if(boundary==='lock')f.afterConsent(f.lock);
  if(boundary==='invalidated')f.afterConsent(()=>f.controller.invalidate());
  if(boundary==='unknown')(request as any).parent_grant={};
  await assert.rejects(f.controller.handle(request,context));assert.equal(f.counts().activations,0);
 });
}
