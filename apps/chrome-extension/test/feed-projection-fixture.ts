import { readFileSync } from 'node:fs'
import { initSync, WasmWallet } from '../src/generated/castalia-wallet-core/bindings.js'
import { CASTALIA_WALLET_CORE_WASM } from '../src/generated/castalia-wallet-core/wasm-bytes.js'
import { createWalletIdentitiesStore } from '../src/wallet-identities-store.js'
export const bytes=(s:string)=>new TextEncoder().encode(s)
export const projections=JSON.parse(readFileSync(new URL('../../../contracts/feeds/v1/projection-conformance.json',import.meta.url),'utf8'))
const vectors=JSON.parse(readFileSync(new URL('../../../contracts/feeds/v1/encrypted-v3.json',import.meta.url),'utf8'))
const populated=vectors.cases.find((v:any)=>v.id==='populated')
initSync({module:CASTALIA_WALLET_CORE_WASM})
export function encryptedSourceFixture() {
  const core=new WasmWallet();core.unlock(bytes(vectors.inputs.custodyFile),vectors.inputs.custodyPassword)
  let owner=core.publicKey(),unlocked=true,epoch=1,writes=0,reads=0
  const disk:Record<string,any>={},key='castalia-wallet-identities-v1:'+owner
  let getHook:((read:number)=>void|Promise<void>)|undefined
  let stateHook:(()=>void|Promise<void>)|undefined
  const d={
    state:async()=>{await stateHook?.();return {unlocked,publicKey:owner}},epoch:()=>epoch,now:()=>1000,
    storage:{get:async(k:string)=>{await getHook?.(++reads);return structuredClone({[k]:disk[k]})},set:async(v:Record<string,unknown>)=>{writes++;Object.assign(disk,structuredClone(v))}},
    chainAccounts:()=>JSON.parse(core.chainAccounts()),
    validateContents:(raw:string)=>core.validateCastawayDescriptors(raw),preflight:(raw:string)=>core.preflightCastawayDescriptors(raw),
    validate:(raw:string)=>core.validateWalletIdentities(raw),merge:(a:string,b:string)=>core.mergeWalletIdentities(a,b),
    seal:(raw:string)=>core.sealIdentitySection(raw),open:(raw:string)=>core.openIdentitySection(bytes(raw)),
    importFile:(raw:string,password:string)=>core.importCastaway(bytes(raw),password),exportFile:(raw:string,password:string,now:number)=>core.exportCastaway(raw,password,BigInt(now)),
  }
  const store=createWalletIdentitiesStore(d)
  function seed(sourceRaw=projections.cases[0].sourceRaw){const c=JSON.parse(populated.contentsRaw);delete c.sections.feeds;const raw=JSON.stringify(c).replace('"sections":{','"sections":{"feeds":'+sourceRaw+',');disk[key]={schema:'castalia.wallet-identity-storage.v1',revision:1,ciphertext:core.sealIdentitySection(raw)}}
  seed()
  return {store,core,disk,key,seed,owner:()=>owner,epoch:()=>epoch,unlocked:()=>unlocked,writes:()=>writes,reads:()=>reads,
    onGet:(hook:typeof getHook)=>{getHook=hook},onState:(hook:typeof stateHook)=>{stateHook=hook},
    lock:()=>{unlocked=false;epoch++},bump:()=>{epoch++},switchOwner:()=>{owner='bb'.repeat(32);epoch++},
    replaceCiphertext:()=>{disk[key].ciphertext=core.sealIdentitySection(core.openIdentitySection(bytes(disk[key].ciphertext)))},
    editRevision:()=>{disk[key].revision++},dispose:()=>core.free()}
}
export function deferred<T>(){let resolve!:(value:T)=>void;const promise=new Promise<T>(r=>{resolve=r});return {promise,resolve}}
