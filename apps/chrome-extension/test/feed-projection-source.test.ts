import assert from 'node:assert/strict'
import test from 'node:test'
import {encryptedSourceFixture,projections,deferred} from './feed-projection-fixture.js'

test('private source captures actual encrypted data, copies bytes and consumes exactly once without writes',async()=>{
 const f=encryptedSourceFixture();try{const before=JSON.stringify(f.disk),p=await f.store.captureFeedProjectionSource();assert.equal(p.owner,f.owner());assert.equal(p.epoch,f.epoch());assert.equal(p.revision,1)
 const copy=p.copySource();assert.deepEqual(JSON.parse(new TextDecoder().decode(copy)),JSON.parse(projections.cases[0].sourceRaw));copy.fill(0)
 let called=0;assert.equal(await p.consumeCurrent((raw:Uint8Array)=>{called++;assert.deepEqual(JSON.parse(new TextDecoder().decode(raw)),JSON.parse(projections.cases[0].sourceRaw));return true}),true)
 await assert.rejects(p.consumeCurrent(()=>true));assert.throws(()=>p.copySource());p.dispose();p.dispose();assert.equal(called,1);assert.equal(f.writes(),0);assert.equal(JSON.stringify(f.disk),before)
 }finally{f.dispose()}
})
for(const change of ['replaceCiphertext','editRevision','lock','switchOwner','cancel'] as const)test('source consumes and refuses '+change+' after capture',async()=>{
 const f=encryptedSourceFixture();try{const p=await f.store.captureFeedProjectionSource();if(change==='cancel')f.store.cancel();else f[change]();const before=JSON.stringify(f.disk);let called=0;await assert.rejects(p.consumeCurrent(()=>{called++;return true}));await assert.rejects(p.consumeCurrent(()=>true));assert.equal(called,0);assert.equal(f.writes(),0);assert.equal(JSON.stringify(f.disk),before)}finally{f.dispose()}
})
for(const action of ['cancel','epoch','dispose'] as const)test('source final post-await fence catches '+action,async()=>{
 const f=encryptedSourceFixture();try{const p=await f.store.captureFeedProjectionSource();f.onGet(()=>{if(action==='cancel')f.store.cancel();else if(action==='epoch')f.bump();else p.dispose()});let called=0;await assert.rejects(p.consumeCurrent(()=>{called++;return true}));assert.equal(called,0);assert.equal(f.writes(),0)}finally{f.dispose()}
})
test('cancellation as source capture finishes prevents an orphan source operation',async()=>{const f=encryptedSourceFixture();try{f.onGet(read=>{if(read===2)f.store.cancel()});await assert.rejects(f.store.captureFeedProjectionSource());assert.equal(f.writes(),0)}finally{f.dispose()}})
test('simultaneous consumption has one winner and disposal interrupts pending consumption',async()=>{const f=encryptedSourceFixture();try{const p=await f.store.captureFeedProjectionSource();let calls=0;const results=await Promise.allSettled([p.consumeCurrent(()=>{calls++;return true}),p.consumeCurrent(()=>{calls++;return true})]);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(calls,1)
 const q=await f.store.captureFeedProjectionSource(),entered=deferred<void>(),release=deferred<void>();f.onGet(async()=>{entered.resolve();await release.promise});const pending=q.consumeCurrent(()=>{calls++;return true});await entered.promise;q.dispose();release.resolve();await assert.rejects(pending);assert.equal(calls,1)
 }finally{f.dispose()}})
test('callback failure or dynamic thenable result is terminal, never awaited as delivery',async()=>{const f=encryptedSourceFixture();try{for(const callback of [()=>{throw Error('delivery failed')},()=>Promise.resolve(true)]){const p=await f.store.captureFeedProjectionSource();await assert.rejects(p.consumeCurrent(callback as any));await assert.rejects(p.consumeCurrent(()=>true))}assert.equal(f.writes(),0)}finally{f.dispose()}})
test('actual corrupt encrypted source rejects before capture and v3 rollout guards stay closed',async()=>{const f=encryptedSourceFixture();try{f.disk[f.key].ciphertext+='corrupt';await assert.rejects(f.store.captureFeedProjectionSource());f.seed();await assert.rejects(f.store.exportFile('long synthetic password'),/feed_writer_not_qualified/);assert.equal(f.writes(),0)}finally{f.dispose()}})
