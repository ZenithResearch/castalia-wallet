import test from 'node:test'
import assert from 'node:assert/strict'
import { buildFilesConsent, filesBase64url } from '../src/files-key-contract.js'
import { createFilesKeyHandler, createFilesReplayStore } from '../src/files-key-handler.js'
const origin='https://castalia.example', owner='ab'.repeat(32), now=Date.parse('2026-10-03T00:00:00.000Z')
const binding={schema:'castalia.files-key-binding.v1',ownerMemberKey:owner,serviceId:'11'.repeat(32),storageAccountId:'owned-account',namespaceId:'22'.repeat(32),workspaceId:'33'.repeat(32),submissionId:'44'.repeat(32),revisionId:'55'.repeat(32)}
const envelope={schema:'castalia.files-key-envelope.v1',binding,nonce:filesBase64url(new Uint8Array(12)),ciphertext:filesBase64url(new Uint8Array(48))}
async function fixture(){
 let epoch=0,time=now,live=true,actualOrigin=origin,approved=true,record,wrapCount=0,confirm=async()=>true,returnedKey
 const replay=createFilesReplayStore({get:async()=>record,set:async value=>{record=structuredClone(value)}})
 const state={memberKey:owner,get approvedOrigins(){return new Set(approved?[origin]:[])},wrap:async()=>{wrapCount++;return envelope},unwrap:async()=>{returnedKey=new Uint8Array(32).fill(8);return returnedKey},authenticate:async body=>({subject:{subjectId:owner,publicKey:owner,walletKind:'castalia-dregg',dreggOwnerPublicKey:owner},challenge:body.challenge,signature:filesBase64url(new Uint8Array(64)),signatureAlgorithm:'ed25519'})}
 const deps={runCustody:fn=>fn(),getState:async()=>state,epoch:()=>epoch,nowMs:()=>time,currentOrigin:async()=>actualOrigin,isCurrent:()=>live,reserve:(c,o)=>replay.reserve(c,o,time),confirm:s=>confirm(s)}
 const body={binding,key:filesBase64url(new Uint8Array(32).fill(7))},consent=await buildFilesConsent('wrap',body,origin,{nowMs:now})
 return {handler:createFilesKeyHandler(deps),request:{...body,consent},deps,state,replay,get returnedKey(){return returnedKey},get wrapCount(){return wrapCount},set confirm(fn){confirm=fn},set epoch(v){epoch=v},set time(v){time=v},set live(v){live=v},set origin(v){actualOrigin=v},set approved(v){approved=v}}
}
test('wrap confirms public scope only and consumed consent cannot replay',async()=>{
 const f=await fixture();f.confirm=async summary=>{assert.equal(summary.memberKey,owner);assert.equal(summary.binding.storageAccountId,'owned-account');assert.equal(Object.hasOwn(summary,'key'),false);return true}
 assert.deepEqual(await f.handler('wrap',f.request,origin),envelope);assert.equal(f.wrapCount,1)
 await assert.rejects(f.handler('wrap',f.request,origin),/replay/);assert.equal(f.wrapCount,1)
})
test('denial consumes consent without touching custody',async()=>{
 const f=await fixture();f.confirm=async()=>false
 await assert.rejects(f.handler('wrap',f.request,origin),/denied/)
 f.confirm=async()=>true;await assert.rejects(f.handler('wrap',f.request,origin),/replay/);assert.equal(f.wrapCount,0)
})
test('lock/disposal/navigation/revocation/expiry while approval pending prevent invocation',async()=>{
 for(const mutate of [f=>f.epoch=1,f=>f.live=false,f=>f.origin='https://other.example',f=>f.approved=false,f=>f.time=now+120_000,f=>f.time=now-1]){
  const f=await fixture();f.confirm=async()=>{mutate(f);return true}
  await assert.rejects(f.handler('wrap',f.request,origin));assert.equal(f.wrapCount,0)
 }
})
test('input mutation during confirmation cannot substitute approved binding',async()=>{
 const f=await fixture();f.confirm=async()=>{f.request.binding={...binding,revisionId:'66'.repeat(32)};return true}
 assert.equal((await f.handler('wrap',f.request,origin)).binding.revisionId,binding.revisionId)
})
test('owner mismatch and unknown fields fail before approval and custody',async()=>{
 const f=await fixture();f.confirm=async()=>{throw Error('must not confirm')}
 const body={...f.request,binding:{...binding,ownerMemberKey:'66'.repeat(32)}};delete body.consent
 const request={...body,consent:await buildFilesConsent('wrap',body,origin,{nowMs:now})}
 await assert.rejects(f.handler('wrap',request,origin),/owner/)
 await assert.rejects(f.handler('wrap',{...f.request,extra:1},origin));assert.equal(f.wrapCount,0)
})
test('unwrap zeroizes raw key buffer and drops result if lock raced completion',async()=>{
 const f=await fixture(),body={binding,envelope},request={...body,consent:await buildFilesConsent('unwrap',body,origin,{nowMs:now})}
 assert.deepEqual(await f.handler('unwrap',request,origin),{key:filesBase64url(new Uint8Array(32).fill(8))});assert.ok(f.returnedKey.every(b=>b===0))
 const g=await fixture();let secret;g.state.unwrap=async()=>{secret=new Uint8Array(32).fill(8);g.epoch=1;return secret}
 await assert.rejects(g.handler('unwrap',request,origin),/changed/);assert.ok(secret.every(b=>b===0))
})
test('authentication cannot outlive its server challenge during fresh consent',async()=>{
 const f=await fixture(),body={serviceKind:'index',serviceId:binding.serviceId,challenge:{audience:`castalia-files://index/${binding.serviceId}`,domain:'castalia-wallet',expiresAt:new Date(now+1000).toISOString(),issuedAt:new Date(now).toISOString(),nonce:'public-fixture-nonce',operation:'castalia.wallet.signChallenge',origin,version:1}}
 const request={...body,consent:await buildFilesConsent('authenticate',body,origin,{nowMs:now})}
 f.confirm=async()=>{f.time=now+1001;return true};await assert.rejects(f.handler('authenticate',request,origin),/expired/)
})
test('replay store fails closed on malformed storage, persistence failure and backwards clock',async()=>{
 const f=await fixture()
 await assert.rejects(createFilesReplayStore({get:async()=>({version:1}),set:async()=>{}}).reserve(f.request.consent,owner,now),/storage/)
 await assert.rejects(createFilesReplayStore({get:async()=>undefined,set:async()=>{throw Error('disk failure')}}).reserve(f.request.consent,owner,now),/disk failure/)
 let record;const replay=createFilesReplayStore({get:async()=>record,set:async v=>{record=v}})
 await replay.reserve(f.request.consent,owner,now+2)
 const next=await buildFilesConsent('wrap',{binding,key:f.request.key},origin,{nowMs:now});await assert.rejects(replay.reserve(next,owner,now+1),/backwards/)
})
