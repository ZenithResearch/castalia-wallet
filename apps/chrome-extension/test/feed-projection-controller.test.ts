import assert from 'node:assert/strict'
import test from 'node:test'
import {WasmFeedProjectionV1} from '../src/generated/castalia-wallet-core/bindings.js'
import {createFeedProjectionController} from '../src/feed-projection-controller.js'
import {createCustodyOperationQueue} from '../src/custody-operation-queue.js'
import {createOperationConfirmationBroker} from '../src/operation-confirmation-broker.js'
import {encryptedSourceFixture,bytes,projections,deferred} from './feed-projection-fixture.js'

function harness(c=projections.cases[0]) {
 const f=encryptedSourceFixture();try{f.seed(c.sourceRaw)}catch(error){f.dispose();throw error}
 let now=1_000_000,live=true,setup=true,approved=true,supported=true,consent=true,held=false,confirms=0,requests=0
 let document={origin:c.origin,tabId:7,documentId:'synthetic-document-A'}
 const approvedOrigins=new Set<string>([c.origin]);const delivered:string[]=[];const queue=createCustodyOperationQueue()
 let reviewHook:((summary:any)=>void|Promise<void>)|undefined,stateHook:(()=>void|Promise<void>)|undefined,verifyHook:(()=>void|Promise<void>)|undefined,deliveryHook:(()=>boolean)|undefined
 const broker=createOperationConfirmationBroker<any>({confirmationUrl:id=>id,createWindow:async()=>42,closeWindow:async()=>{},addWindowRemovedListener:()=>{},removeWindowRemovedListener:()=>{},setTimeout:()=>1,clearTimeout:()=>{},randomId:()=>String(++requests),nowMs:()=>now})
 const deps={
  run:<T>(op:()=>Promise<T>)=>queue.run(async()=>{assert.equal(held,false);held=true;try{return await op()}finally{held=false}}),
  state:async()=>{await stateHook?.();return {setupComplete:setup,unlocked:f.unlocked(),memberKey:f.owner(),approvedOrigins:approved?approvedOrigins:new Set<string>()}},
  epoch:f.epoch,nowMs:()=>now,supportsDestination:()=>supported,source:()=>f.store.captureFeedProjectionSource(),
  confirmation:{confirm:async(input:any)=>{assert.equal(held,false);confirms++;const pending=broker.confirm(input);const claimed=broker.claimPending(String(requests));assert.ok(claimed);await reviewHook?.(claimed.summary);broker.resolve(String(requests),consent);return pending},cancelForOwner:broker.cancelForOwner},
 }
 const context={current:()=>live,verify:async()=>{await verifyHook?.();return {...document}},deliver:(raw:string)=>{assert.equal(held,true);if(deliveryHook)return deliveryHook();delivered.push(raw);return true}}
 const controller=createFeedProjectionController(deps)
 return {f,deps,context,controller,delivered,setTime:(time:number)=>{now=time},run:()=>controller.reviewAndDeliver(bytes(c.selectionRaw),context),confirms:()=>confirms,
  onReview:(hook:typeof reviewHook)=>{reviewHook=hook},onState:(hook:typeof stateHook)=>{stateHook=hook},onVerify:(hook:typeof verifyHook)=>{verifyHook=hook},onDelivery:(hook:typeof deliveryHook)=>{deliveryHook=hook},
  change:(kind:string)=>{if(kind==='lock')f.lock();else if(kind==='owner')f.switchOwner();else if(kind==='epoch')f.bump();else if(kind==='cancel')controller.invalidate();else if(kind==='disconnect')live=false;else if(kind==='origin')document={...document,origin:'https://other.example'};else if(kind==='document')document={...document,documentId:'synthetic-document-B'};else if(kind==='tab')document={...document,tabId:8};else if(kind==='revoke')approved=false;else if(kind==='unsupported')supported=false;else if(kind==='setup')setup=false;else if(kind==='expired')now+=120_000;else if(kind==='clock')now--;else if(kind==='ciphertext')f.replaceCiphertext();else if(kind==='revision')f.editRevision();else if(kind==='store_cancel')f.store.cancel();else if(kind==='deny')consent=false},dispose:()=>{controller.invalidate();f.dispose()}}
}

test('real encrypted source and WASM selected preview require explicit broker consent, deliver once inside FIFO, and never write',async()=>{
 const h=harness();try{const before=JSON.stringify(h.f.disk);h.onReview(summary=>{assert.equal(summary.kind,'selected_feeds');assert.equal(summary.origin,projections.cases[0].origin);assert.deepEqual(summary.section,projections.cases[0].expectedSection);assert.equal(h.delivered.length,0)})
 await h.run();assert.equal(h.confirms(),1);assert.equal(h.delivered.length,1);assert.deepEqual(JSON.parse(h.delivered[0]),projections.cases[0].expectedSection);await assert.rejects(h.run());assert.equal(h.delivered.length,1);assert.equal(h.f.writes(),0);assert.equal(JSON.stringify(h.f.disk),before)
 }finally{h.dispose()}
})
for(const change of ['lock','setup','revoke','unsupported'] as const)test('initial '+change+' denies before source read or privacy review',async()=>{const h=harness();try{h.change(change);await assert.rejects(h.run());assert.equal(h.f.reads(),0);assert.equal(h.confirms(),0);assert.equal(h.delivered.length,0)}finally{h.dispose()}})
for(const change of ['lock','owner','epoch','cancel','disconnect','origin','document','tab','revoke','unsupported','setup','expired','clock','ciphertext','revision','store_cancel','deny'] as const)test(change+' during consent prevents delivery and replay',async()=>{
 const h=harness();try{h.onReview(()=>h.change(change));await assert.rejects(h.run());assert.equal(h.delivered.length,0);assert.equal(h.f.writes(),0);await assert.rejects(h.run())}finally{h.dispose()}
})
for(const phase of ['initial','final'] as const)for(const boundary of ['state','verify','storage'] as const)test(phase+' '+boundary+' await cancellation cannot disclose or leave an approval',async()=>{
 const h=harness(),entered=deferred<void>(),release=deferred<void>();try{const pause=async()=>{entered.resolve();await release.promise};const hook=()=>{if(boundary==='state')h.onState(pause);else if(boundary==='verify')h.onVerify(pause);else h.f.onGet(pause)};if(phase==='initial')hook();else h.onReview(hook)
 const pending=h.run();await entered.promise;h.controller.invalidate();release.resolve();await assert.rejects(pending);assert.equal(h.delivered.length,0);assert.equal(h.confirms(),phase==='initial'?0:1);assert.equal(h.f.writes(),0)
 }finally{h.dispose()}
})
for(const change of ['epoch','store_cancel','unsupported','expired','disconnect'] as const)test('last storage-await final fence catches '+change,async()=>{const h=harness();try{h.onReview(()=>h.f.onGet(()=>h.change(change)));await assert.rejects(h.run());assert.equal(h.delivered.length,0)}finally{h.dispose()}})
test('selection bytes copied before async work; caller cannot alter the chosen set',async()=>{const h=harness();try{const selected=bytes(projections.cases[0].selectionRaw);const p=h.controller.reviewAndDeliver(selected,h.context);selected.fill(0);await p;assert.deepEqual(JSON.parse(h.delivered[0]),projections.cases[0].expectedSection)}finally{h.dispose()}})
for(const failure of ['throw','false','thenable'] as const)test('failed '+failure+' delivery remains consumed',async()=>{const h=harness();try{let attempts=0;h.onDelivery((()=>{attempts++;if(failure==='throw')throw Error('synthetic delivery failed');if(failure==='thenable')return Promise.resolve(true);return false}) as any);await assert.rejects(h.run());await assert.rejects(h.run());assert.equal(attempts,1);assert.equal(h.confirms(),1);assert.equal(h.f.writes(),0)}finally{h.dispose()}})
test('duplicate concurrent requests have one preparation and one delivery',async()=>{const h=harness();try{const results=await Promise.allSettled([h.run(),h.run()]);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(h.confirms(),1);assert.equal(h.delivered.length,1)}finally{h.dispose()}})
test('frozen46 vectors:42 controller cases and4 invalid sources refused by actual encrypted-store preflight',async()=>{
 const malformed=new Set(['raw-duplicate-source','escaped-duplicate-source','deep-source','lone-surrogate-source']);let controllerCases=0,sourceRefusals=0
 for(const c of projections.cases){if(malformed.has(c.id)){const f=encryptedSourceFixture();try{assert.equal(c.valid,false);assert.throws(()=>f.seed(c.sourceRaw));sourceRefusals++;assert.equal(f.writes(),0)}finally{f.dispose()}continue}
 const h=harness(c);try{controllerCases++;if(c.valid){await h.run();assert.deepEqual(JSON.parse(h.delivered[0]),c.expectedSection,c.id)}else{await assert.rejects(h.run(),undefined,c.id);assert.equal(h.delivered.length,0,c.id)}assert.equal(h.f.writes(),0,c.id)}finally{h.dispose()}}
 assert.equal(controllerCases,42);assert.equal(sourceRefusals,4)
})
test('source resealing after logically identical whitespace change still invalidates confirmation',async()=>{const h=harness();try{h.onReview(()=>h.f.seed(' '+projections.cases[0].sourceRaw));await assert.rejects(h.run(),/identities_changed/);assert.equal(h.delivered.length,0)}finally{h.dispose()}})


test('produced confirmation summary is deeply immutable before the broker copies it',async()=>{
 const h=harness();try{const confirm=h.deps.confirmation.confirm;let checked=false
 h.deps.confirmation.confirm=async input=>{const summary=input.summary;function frozen(value:any){if(value&&typeof value==='object'){assert.equal(Object.isFrozen(value),true);for(const child of Object.values(value))frozen(child)}}frozen(summary)
 assert.throws(()=>{summary.origin='https://other.example'},TypeError)
 assert.throws(()=>{summary.section.subscriptions[0].title='changed displayed source'},TypeError)
 assert.throws(()=>{summary.section.subscriptions[0].collectionIds.push('different-choice')},TypeError)
 assert.throws(()=>{summary.section.collections.pop()},TypeError)
 checked=true;return confirm(input)}
 await h.run();assert.equal(checked,true);assert.deepEqual(JSON.parse(h.delivered[0]),projections.cases[0].expectedSection)
 }finally{h.dispose()}
})
test('throwing broker cancellation cannot mask denial or leak controller capacity',async()=>{
 const h=harness();try{h.change('deny');const cancel=h.deps.confirmation.cancelForOwner;let calls=0
 h.deps.confirmation.cancelForOwner=owner=>{calls++;cancel(owner);throw Error('synthetic cancellation adapter failed')}
 for(let i=0;i<17;i++)await assert.rejects(h.controller.reviewAndDeliver(bytes(projections.cases[0].selectionRaw),{...h.context}),/approval_denied/)
 assert.equal(calls,17);assert.equal(h.confirms(),17);assert.equal(h.delivered.length,0)
 }finally{h.dispose()}
})
test('cancellation settles the controller even if the broker throws before resolving consent',async()=>{
 const h=harness(),entered=deferred<void>(),release=deferred<void>();try{h.onReview(async()=>{entered.resolve();await release.promise});const cancel=h.deps.confirmation.cancelForOwner
 h.deps.confirmation.cancelForOwner=()=>{throw Error('synthetic broker unavailable')}
 const pending=h.run();await entered.promise;assert.doesNotThrow(()=>h.controller.invalidate())
 await assert.rejects(pending,/approval_denied/);assert.equal(h.delivered.length,0)
 h.deps.confirmation.cancelForOwner=cancel
 }finally{release.resolve();h.dispose()}
})
test('throwing source disposal still releases controller and actual WASM handles without masking denial',async()=>{
 const h=harness();try{h.change('deny');const source=h.deps.source;let disposals=0
 h.deps.source=async()=>{const original=await source();return {...original,dispose(){disposals++;original.dispose();throw Error('synthetic source disposal failed')}}}
 for(let i=0;i<17;i++)await assert.rejects(h.controller.reviewAndDeliver(bytes(projections.cases[0].selectionRaw),{...h.context}),/approval_denied/)
 assert.equal(disposals,17);assert.equal(h.confirms(),17);assert.equal(h.delivered.length,0)
 }finally{h.dispose()}
})

test('throwing WASM disposal still frees each actual preparation and releases active capacity',async()=>{
 const h=harness(),proto=WasmFeedProjectionV1.prototype,dispose=proto.dispose,free=proto.free;let disposed=0,freed=0
 try{h.change('deny');proto.dispose=function(){disposed++;dispose.call(this);throw Error('synthetic WASM disposal failure')};proto.free=function(){freed++;free.call(this)}
 for(let i=0;i<17;i++)await assert.rejects(h.controller.reviewAndDeliver(bytes(projections.cases[0].selectionRaw),{...h.context}),/approval_denied/)
 assert.equal(disposed,17);assert.equal(freed,17);assert.equal(h.delivered.length,0)
 }finally{proto.dispose=dispose;proto.free=free;h.dispose()}
})

test('observed clock rollback above creation time refuses final delivery',async()=>{
 const h=harness();try{h.onReview(()=>{h.setTime(1_090_000);h.onState(()=>h.setTime(1_010_000))})
 await assert.rejects(h.run(),/feed_projection_expired/);assert.equal(h.confirms(),1);assert.equal(h.delivered.length,0)
 }finally{h.dispose()}
})

test('cancelled source-await and queued operations retain all sixteen slots until actual unwind',async()=>{
 const h=harness(),entered=deferred<void>(),release=deferred<void>();let pending:Promise<void>[]=[],extra:Promise<string>|undefined
 try{
 h.f.onGet(async()=>{entered.resolve();await release.promise})
 pending=Array.from({length:16},()=>h.controller.reviewAndDeliver(bytes(projections.cases[0].selectionRaw),{...h.context}));const outcomes=Promise.allSettled(pending)
 await entered.promise;h.controller.invalidate()
 extra=h.controller.reviewAndDeliver(bytes(projections.cases[0].selectionRaw),{...h.context}).then(()=> 'accepted',error=>String(error.message))
 assert.equal(await Promise.race([extra,new Promise<string>(resolve=>setImmediate(()=>resolve('incorrectly queued')))]),'feed_projection_capacity')
 assert.equal(h.confirms(),0);assert.equal(h.delivered.length,0)
 release.resolve();assert.equal((await outcomes).filter(result=>result.status==='rejected').length,16)
 h.f.onGet(undefined);await h.controller.reviewAndDeliver(bytes(projections.cases[0].selectionRaw),{...h.context})
 assert.equal(h.delivered.length,1);assert.equal(h.f.writes(),0)
 }finally{release.resolve();await Promise.allSettled(pending);await extra;h.dispose()}
})
