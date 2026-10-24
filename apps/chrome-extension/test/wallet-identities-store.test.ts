import {test} from 'node:test'
import assert from 'node:assert/strict'
import {createWalletIdentitiesStore,isWalletIdentityPage} from '../src/wallet-identities-store.js'

function fixture() {
  let owner='11'.repeat(32), unlocked=true, epoch=0, writes=0, now=1000
  const disk:Record<string,unknown>={}, sealed=new Map<string,string>()
  const empty=()=>({schema:'castalia.wallet-identities.v1',version:1,ownerMemberKey:owner,authority:'descriptor-only',accounts:[]})
  const ids=()=>({...empty(),accounts:[{accountId:'018d0000-0000-4000-8000-000000000001',kind:'matrix',label:'Chat',identifier:'@a:example.test',server:'https://example.test'}]})
  const store=createWalletIdentitiesStore({
    state:async()=>({unlocked,publicKey:owner}),epoch:()=>epoch,now:()=>now,
    storage:{get:async(key:string)=>({[key]:disk[key]}),set:async(values:Record<string,unknown>)=>{writes++;Object.assign(disk,structuredClone(values))}},
    chainAccounts:()=>({schema:'zenith.chain-accounts-section.v1',version:1,ownerMemberKey:owner,authority:'descriptor-only',recovery:'castalia.wallet-custody.v1',accounts:[]}),
    validateContents:(raw:string)=>raw,
    validate:(raw:string)=>{const v=JSON.parse(raw);if(v.ownerMemberKey!==owner)throw Error('wrong_owner');return JSON.stringify(v)},
    merge:(a:string,b:string)=>{const first=JSON.parse(a),second=JSON.parse(b);if(second.ownerMemberKey!==owner)throw Error('wrong_owner');return JSON.stringify({...first,accounts:[...first.accounts,...second.accounts.filter((x:any)=>!first.accounts.some((y:any)=>JSON.stringify(x)===JSON.stringify(y)))]})},
    seal:(raw:string)=>{const id='ciphertext-'+sealed.size;sealed.set(id,raw);return id},open:(v:string)=>{const raw=sealed.get(v);if(!raw)throw Error('invalid_ciphertext');return raw},
    importFile:(raw:string)=>raw,exportFile:(raw:string)=>raw,
  })
  const file=()=>JSON.stringify({schema:'castalia.castaway-contents.v2',version:2,sections:{identity:{subject:{memberKey:owner}},walletIdentities:ids()}})
  return {store,disk,file,ids,owner:()=>owner,writes:()=>writes,lock:()=>{unlocked=false;epoch++},unlock:()=>{unlocked=true;epoch++},switchOwner:()=>{owner='22'.repeat(32);epoch++},expire:()=>{now+=121_000}}
}
test('import preparation does not write; exact confirmation persists encrypted data once',async()=>{
  const f=fixture(),preview=await f.store.reviewImport(f.file(),'file password')
  assert.equal(f.writes(),0)
  await f.store.confirmImport(preview.token)
  assert.equal(f.writes(),1)
  assert.deepEqual((await f.store.read()).identities,f.ids())
  assert.equal(JSON.stringify(f.disk).includes('Chat'),false)
  await assert.rejects(f.store.confirmImport(preview.token))
  const exported=JSON.parse(await f.store.exportFile('file password'))
  assert.deepEqual(exported.sections.walletIdentities,f.ids())
})
test('lock, expiry, cancellation and another import invalidate pending writes',async()=>{
  for(const change of ['lock','expire','cancel'] as const){const f=fixture(),p=await f.store.reviewImport(f.file(),'password');if(change==='lock')f.lock();if(change==='expire')f.expire();if(change==='cancel')f.store.cancel();await assert.rejects(f.store.confirmImport(p.token));assert.equal(f.writes(),0)}
  const f=fixture(),first=await f.store.reviewImport(f.file(),'password'),second=await f.store.reviewImport(f.file(),'password')
  await assert.rejects(f.store.confirmImport(first.token));assert.equal(f.writes(),0)
  // A failed confirmation consumes the pending review, so another review is needed.
  await assert.rejects(f.store.confirmImport(second.token));assert.equal(f.writes(),0)
})
test('wrong-owner and stale-storage imports preserve all existing records',async()=>{
  const f=fixture(),p=await f.store.reviewImport(f.file(),'password')
  f.switchOwner();await assert.rejects(f.store.confirmImport(p.token));assert.equal(f.writes(),0)
  const g=fixture(),q=await g.store.reviewImport(g.file(),'password')
  const key='castalia-wallet-identities-v1:'+g.owner();g.disk[key]={schema:'castalia.wallet-identity-storage.v1',revision:7,ciphertext:'other'}
  const prior=JSON.stringify(g.disk);await assert.rejects(g.store.confirmImport(q.token));assert.equal(JSON.stringify(g.disk),prior)
})

test('only exact top-level Wallet identity UI can reach private records',()=>{
  const page='chrome-extension://wallet/src/wallet-identities.html'
  assert.equal(isWalletIdentityPage({id:'wallet',url:page,frameId:0},'wallet',page),true)
  for(const sender of [{id:'wallet',url:'https://example.test',frameId:0},{id:'wallet',url:page+'?origin=https://example.test',frameId:0},{id:'wallet',url:page,frameId:1},{id:'other',url:page,frameId:0}])assert.equal(isWalletIdentityPage(sender,'wallet',page),false)
})

test('explicit identity edits preserve encryption and reject stale form revisions',async()=>{
  const f=fixture();await f.store.saveIdentities(f.ids(),0);assert.equal(f.writes(),1);assert.deepEqual((await f.store.read()).identities,f.ids());
  await assert.rejects(f.store.saveIdentities(f.ids(),0));assert.equal(f.writes(),1);assert.equal(JSON.stringify(f.disk).includes('Chat'),false)
})
