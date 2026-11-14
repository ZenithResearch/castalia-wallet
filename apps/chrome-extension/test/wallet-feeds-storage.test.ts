import assert from 'node:assert/strict'
import test from 'node:test'
import {readFileSync} from 'node:fs'
import {initSync,WasmWallet} from '../src/generated/castalia-wallet-core/bindings.js'
import {CASTALIA_WALLET_CORE_WASM} from '../src/generated/castalia-wallet-core/wasm-bytes.js'
import {createWalletIdentitiesStore} from '../src/wallet-identities-store.js'

initSync({module:CASTALIA_WALLET_CORE_WASM})
const encoder=new TextEncoder()
const vectors=JSON.parse(readFileSync(new URL('../../../contracts/feeds/v1/encrypted-v3.json',import.meta.url),'utf8'))
const populated=vectors.cases.find((v:any)=>v.id==='populated')
const empty=vectors.cases.find((v:any)=>v.id==='empty')
const conflict=vectors.cases.find((v:any)=>v.id==='conflicting-title')
const qualified=process.env.CASTALIA_TEST_QUALIFIED_EXTENSION_FEEDS==='1'
const storageKey='castalia-wallet-identities-v1:'+JSON.parse(populated.contentsRaw).sections.identity.subject.memberKey

function fixture(){
  let core:WasmWallet,unlocked=true,epoch=0,now=1000,writes=0,preflights=0,failWrite=false,rejectPreflight=false,expireOnRead=false
  let readsUntilInvalidation=0,invalidateOnRead:()=>void=()=>{}
  const disk:Record<string,unknown>={}
  function reopen(){core?.free();core=new WasmWallet();core.unlock(encoder.encode(vectors.inputs.custodyFile),vectors.inputs.custodyPassword);unlocked=true;epoch++}
  reopen()
  const owner=core!.publicKey()
  const dependencies={
    state:async()=>({unlocked,publicKey:owner}),epoch:()=>epoch,now:()=>now,
    storage:{get:async(key:string)=>{if(expireOnRead){now+=120_001;expireOnRead=false}if(readsUntilInvalidation&&!--readsUntilInvalidation)invalidateOnRead();return structuredClone({[key]:disk[key]})},set:async(values:Record<string,unknown>)=>{if(failWrite)throw Error('synthetic_atomic_write_failed');writes++;Object.assign(disk,structuredClone(values))}},
    chainAccounts:()=>JSON.parse(core.chainAccounts()),
    validateContents:(raw:string)=>core.validateCastawayDescriptors(raw),
    preflight:(raw:string)=>{preflights++;const size=core.preflightCastawayDescriptors(raw);if(rejectPreflight)throw Error('file_too_large');return size},
    validate:(raw:string)=>core.validateWalletIdentities(raw),merge:(a:string,b:string)=>core.mergeWalletIdentities(a,b),
    seal:(raw:string)=>core.sealIdentitySection(raw),open:(raw:string)=>core.openIdentitySection(encoder.encode(raw)),
    importFile:(raw:string,password:string)=>core.importCastaway(encoder.encode(raw),password),
    exportFile:(raw:string,password:string,now:number)=>core.exportCastaway(raw,password,BigInt(now)),
  }
  const store=()=>createWalletIdentitiesStore(dependencies)
  const seed=(raw=populated.contentsRaw)=>{disk[storageKey]={schema:'castalia.wallet-identity-storage.v1',revision:1,ciphertext:core.sealIdentitySection(raw)}}
  const contents=()=>JSON.parse(core.openIdentitySection(encoder.encode((disk[storageKey] as any).ciphertext)))
  const legacy=()=>{const v=JSON.parse(populated.contentsRaw);delete v.sections.feeds;v.version=2;v.schema='castalia.castaway-contents.v2';return core.exportCastaway(JSON.stringify(v),vectors.inputs.dataPassword,1n)}
  return {store,seed,disk,contents,legacy,reopen,owner,writes:()=>writes,preflights:()=>preflights,
    fail:()=>{failWrite=true},expire:()=>{now+=120_001},lock:()=>{core.lock();unlocked=false;epoch++},
    dispose:()=>core.free(),
    replaceSameRevision:()=>{const s=disk[storageKey] as any;s.ciphertext=core.sealIdentitySection(populated.contentsRaw)},
    rejectPreflight:()=>{rejectPreflight=true},
    expireOnRead:()=>{expireOnRead=true},
    invalidateAtRead:(reads:number,callback:()=>void,bumpEpoch=true)=>{readsUntilInvalidation=reads;invalidateOnRead=()=>{if(bumpEpoch)epoch++;callback()}},
  }
}

test('actual WASM encrypted storage survives restart, legacy imports and account edits without losing v3 feeds',async()=>{
  const f=fixture()
  try{
    f.seed();let s=f.store()
    assert.deepEqual((await s.read()).feeds,JSON.parse(populated.contentsRaw).sections.feeds)
    const p=await s.reviewImport(f.legacy(),vectors.inputs.dataPassword)
    assert.deepEqual(p.feeds.incoming,null)
    assert.deepEqual(p.feeds.preserved,JSON.parse(populated.contentsRaw).sections.feeds)
    assert.equal(f.writes(),0)
    await s.confirmImport(p.token)
    assert.equal(f.contents().version,3)
    assert.deepEqual(f.contents().sections.feeds,JSON.parse(populated.contentsRaw).sections.feeds)
    const read=await s.read();await s.saveIdentities({...read.identities,accounts:[]},read.revision)
    assert.equal(f.preflights(),3)
    assert.equal(f.contents().version,3)
    assert.deepEqual(f.contents().sections.feeds,JSON.parse(populated.contentsRaw).sections.feeds)
    assert.equal(JSON.stringify(f.disk).includes('Café'),false)
    f.reopen();s=f.store()
    assert.deepEqual((await s.read()).feeds,JSON.parse(populated.contentsRaw).sections.feeds)
    assert.deepEqual((await s.read()).identities.accounts,[])
    await assert.rejects(s.exportFile(vectors.inputs.dataPassword),/feed_writer_not_qualified/)
  }finally{f.dispose()}
})

test('stored empty v3 retains its version through identity edits and legacy import',async()=>{
  const f=fixture()
  try{f.seed(empty.contentsRaw);const s=f.store(),read=await s.read();await s.saveIdentities(read.identities,read.revision);const p=await s.reviewImport(f.legacy(),vectors.inputs.dataPassword);await s.confirmImport(p.token);assert.equal(f.contents().version,3);assert.deepEqual(f.contents().sections.feeds,JSON.parse(empty.contentsRaw).sections.feeds)}finally{f.dispose()}
})

test('exact encrypted snapshot, cancel, expiry, lock and failed atomic writes consume reviews without changing data',async()=>{
  for(const action of ['replaceSameRevision','expire','lock','cancel','fail'] as const){
    const f=fixture()
    try{f.seed();const s=f.store(),p=await s.reviewImport(f.legacy(),vectors.inputs.dataPassword);if(action==='cancel')s.cancel();else f[action]();const before=JSON.stringify(f.disk);await assert.rejects(s.confirmImport(p.token),action==='replaceSameRevision'?/identities_changed/:undefined);assert.equal(JSON.stringify(f.disk),before);assert.equal(f.writes(),0);await assert.rejects(s.confirmImport(p.token))}finally{f.dispose()}
  }
})

test('default extension import gate refuses actual encrypted v3 without invalidating saved data', {skip:qualified},async()=>{
  const f=fixture()
  try{f.seed();const s=f.store(),before=JSON.stringify(f.disk);await assert.rejects(s.reviewImport(populated.envelope,vectors.inputs.dataPassword),/feed_storage_not_qualified/);assert.equal(JSON.stringify(f.disk),before);assert.equal(f.writes(),0)}finally{f.dispose()}
})

test('qualified actual encrypted v3 imports are additive, reviewed exactly and persist across restart', {skip:!qualified},async()=>{
  const f=fixture()
  try{
    const s=f.store(),p=await s.reviewImport(populated.envelope,vectors.inputs.dataPassword)
    assert.deepEqual(p.feeds.incoming,JSON.parse(populated.contentsRaw).sections.feeds);assert.equal(p.feeds.preserved,null);assert.equal(f.writes(),0)
    // A caller cannot mutate the prepared encrypted candidate via its preview.
    p.feeds.incoming!.subscriptions[0].title='caller mutation'
    await s.confirmImport(p.token)
    assert.deepEqual(f.contents().sections.feeds,JSON.parse(populated.contentsRaw).sections.feeds)
    for(const vector of [populated,empty]){const p=await s.reviewImport(vector.envelope,vectors.inputs.dataPassword);await s.confirmImport(p.token);assert.deepEqual(f.contents().sections.feeds,JSON.parse(populated.contentsRaw).sections.feeds)}
    const before=JSON.stringify(f.disk);await assert.rejects(s.reviewImport(conflict.envelope,vectors.inputs.dataPassword),/feed_conflict/);assert.equal(JSON.stringify(f.disk),before)
    f.reopen();assert.deepEqual((await f.store().read()).feeds,JSON.parse(populated.contentsRaw).sections.feeds)
    await assert.rejects(s.exportFile(vectors.inputs.dataPassword),/feed_writer_not_qualified/)
  }finally{f.dispose()}
})

test('authenticated invalid v3 fixtures fail before a candidate or write', {skip:!qualified},async()=>{
  const f=fixture()
  try{f.seed();const s=f.store(),before=JSON.stringify(f.disk);for(const v of vectors.cases.filter((v:any)=>!v.valid)){await assert.rejects(s.reviewImport(v.envelope,vectors.inputs.dataPassword),undefined,v.id);assert.equal(JSON.stringify(f.disk),before);await assert.rejects(s.confirmImport('no review'))}assert.equal(f.writes(),0)}finally{f.dispose()}
})

test('a preflight refusal after the actual WASM size check prevents a feed-bearing account edit or import candidate',async()=>{
  const f=fixture()
  try{f.seed();const s=f.store(),before=JSON.stringify(f.disk),read=await s.read();f.rejectPreflight();await assert.rejects(s.saveIdentities(read.identities,read.revision),/file_too_large/);await assert.rejects(s.reviewImport(f.legacy(),vectors.inputs.dataPassword),/file_too_large/);assert.equal(f.preflights(),2);assert.equal(JSON.stringify(f.disk),before);assert.equal(f.writes(),0);await assert.rejects(s.confirmImport('no review'))}finally{f.dispose()}
})

test('confirmation rechecks actual whole-artifact preflight and consumes a refused candidate without writing',async()=>{
  const f=fixture()
  try{f.seed();const s=f.store(),p=await s.reviewImport(f.legacy(),vectors.inputs.dataPassword),before=JSON.stringify(f.disk);f.rejectPreflight();await assert.rejects(s.confirmImport(p.token),/file_too_large/);assert.equal(f.preflights(),2);assert.equal(JSON.stringify(f.disk),before);assert.equal(f.writes(),0);await assert.rejects(s.confirmImport(p.token))}finally{f.dispose()}
})

test('a review that expires while awaiting its storage fence cannot be committed',async()=>{
  const f=fixture()
  try{f.seed();const s=f.store(),p=await s.reviewImport(f.legacy(),vectors.inputs.dataPassword),before=JSON.stringify(f.disk);f.expireOnRead();await assert.rejects(s.confirmImport(p.token),/import_review_expired/);assert.equal(JSON.stringify(f.disk),before);assert.equal(f.writes(),0)}finally{f.dispose()}
})

for(const operation of ['review','edit','confirm'] as const){
  for(const bumpEpoch of [true,false])test(`${operation}: final storage fence cannot outlive synchronous ${bumpEpoch?'epoch invalidation plus cancel':'cancel alone'}`,async()=>{
    const f=fixture()
    try{
      f.seed();const s=f.store(),previous=await s.reviewImport(f.legacy(),vectors.inputs.dataPassword),before=JSON.stringify(f.disk)
      // Review/edit read the local snapshot, then its final exact-byte fence.
      // Confirm performs two exact-byte fences; only the last one invalidates.
      f.invalidateAtRead(2,()=>s.cancel(),bumpEpoch)
      if(operation==='review')await assert.rejects(s.reviewImport(f.legacy(),vectors.inputs.dataPassword),/wallet_changed_or_locked|import_review_expired/)
      if(operation==='edit')await assert.rejects(s.saveIdentities(JSON.parse(populated.contentsRaw).sections.walletIdentities,1),/wallet_changed_or_locked|import_review_expired/)
      if(operation==='confirm')await assert.rejects(s.confirmImport(previous.token),/wallet_changed_or_locked|import_review_expired/)
      assert.equal(f.writes(),0);assert.equal(JSON.stringify(f.disk),before)
      await assert.rejects(s.confirmImport(previous.token),/import_review_expired/)
    }finally{f.dispose()}
  })
}

test('v3 without wallet identities stays v3 when an account is added and removed',async()=>{
  const f=fixture()
  try{const contents=JSON.parse(populated.contentsRaw),accounts=contents.sections.walletIdentities;delete contents.sections.walletIdentities;f.seed(JSON.stringify(contents));const s=f.store(),read=await s.read();assert.deepEqual(read.identities.accounts,[]);await s.saveIdentities(accounts,read.revision);await s.saveIdentities({...accounts,accounts:[]},2);assert.equal(f.contents().version,3);assert.deepEqual(f.contents().sections.feeds,contents.sections.feeds)}finally{f.dispose()}
})

test('qualified additive imports validate combined source, collection and serialized section limits before any write', {skip:!qualified},async()=>{
  const uuid=(n:number)=>`${n.toString(16).padStart(8,'0')}-0000-4000-8000-000000000001`
  for(const limit of ['sources','collections','bytes','collection-conflict'] as const){
    const f=fixture()
    try{
      const contents=JSON.parse(populated.contentsRaw),feeds=contents.sections.feeds,source=structuredClone(feeds.subscriptions[0])
      if(limit==='sources'){
        feeds.subscriptions=Array.from({length:256},(_,i)=>({...source,id:uuid(i+1),collectionIds:[]}));feeds.collections=[]
      }else if(limit==='collections'){
        feeds.subscriptions=[];feeds.collections=Array.from({length:64},(_,i)=>({id:uuid(i+1),title:'Saved collection'}))
      }else if(limit==='collection-conflict')feeds.collections[0].title='A conflicting saved collection title'
      else{
        feeds.collections=[];feeds.subscriptions=Array.from({length:100},(_,i)=>({...source,id:uuid(i+1),title:'x'.repeat(512),url:'https://example.org/'+'x'.repeat(2028),collectionIds:[]}))
        let remove=encoder.encode(JSON.stringify(feeds)).length-262_100
        for(const record of feeds.subscriptions){const n=Math.min(remove,record.url.length-20);record.url=record.url.slice(0,record.url.length-n);remove-=n;if(!remove)break}
        assert.equal(encoder.encode(JSON.stringify(feeds)).length,262_100)
      }
      // Seeding encrypts actual validated-size data; read validates the complete
      // section first, proving this is a combined-candidate failure.
      f.seed(JSON.stringify(contents));const s=f.store();await s.read();const before=JSON.stringify(f.disk)
      // The public WASM descriptor adapter deliberately closes Rust validation
      // failures to invalid_wallet_file; this must differ from the rollout gate.
      const expected=limit==='collection-conflict'?'feed_conflict':'invalid_wallet_file'
      await assert.rejects(s.reviewImport(populated.envelope,vectors.inputs.dataPassword),(error:unknown)=>String(error).replace(/^Error: /,'')===expected)
      assert.equal(JSON.stringify(f.disk),before,limit);assert.equal(f.writes(),0,limit);await assert.rejects(s.confirmImport('no candidate'))
    }finally{f.dispose()}
  }
})

test('qualified empty v3 import persists required empty feeds and never enables the writer', {skip:!qualified},async()=>{
  const f=fixture()
  try{const s=f.store(),p=await s.reviewImport(empty.envelope,vectors.inputs.dataPassword);await s.confirmImport(p.token);assert.equal(f.contents().version,3);assert.deepEqual(f.contents().sections.feeds,JSON.parse(empty.contentsRaw).sections.feeds);f.reopen();assert.deepEqual((await f.store().read()).feeds,JSON.parse(empty.contentsRaw).sections.feeds);await assert.rejects(s.exportFile(vectors.inputs.dataPassword),/feed_writer_not_qualified/)}finally{f.dispose()}
})
