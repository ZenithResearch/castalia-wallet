/** Synthetic browser qualification ONLY. Never a production entry point.
 * Uses real encrypted custody/state/source and shared WASM, in an empty profile.
 * Test seeding is not a v3 import qualification or a production writer.
 */
import {installSelectedFeedsRuntime} from '../../apps/chrome-extension/src/selected-feeds-runtime.js'
import {custodyState,custodyEpoch,subscribeCustodyChanges,invalidateCustodyApprovals,walletIdentities} from '../../apps/chrome-extension/src/custody-runtime.js'
import {sessionState} from '../../apps/chrome-extension/src/state/session-state.js'
import {createCustodyOperationQueue} from '../../apps/chrome-extension/src/custody-operation-queue.js'
import {WasmWallet} from '../../apps/chrome-extension/src/generated/castalia-wallet-core/bindings.js'
import encrypted from '../../contracts/feeds/v1/encrypted-v3.json'
import projection from '../../contracts/feeds/v1/projection-conformance.json'
declare const chrome:any
declare const SELECTED_FEEDS_FIXTURE_ORIGIN:string
const origin=SELECTED_FEEDS_FIXTURE_ORIGIN,queue=createCustodyOperationQueue(),setupURL=chrome.runtime.getURL('fixture-setup.html')
let offset=0
const runtime=installSelectedFeedsRuntime(chrome,{run:op=>queue.run(op),epoch:custodyEpoch,onChange:subscribeCustodyChanges,source:()=>walletIdentities.captureFeedProjectionSource(),state:async()=>{const state=await custodyState.getState(),session=await sessionState.getState();return state.publicKey?{setupComplete:state.setupComplete,unlocked:state.unlocked,memberKey:state.publicKey,approvedOrigins:new Set(session.approvedOrigins)}:null}}, {qualified:true,supportsDestination:value=>value===origin},{nowMs:()=>Date.now()+offset,setTimeout:(f,ms)=>setTimeout(f,ms),clearTimeout:id=>clearTimeout(id as ReturnType<typeof setTimeout>)})
async function seed(reseal=false){
  const core=new WasmWallet();try{core.unlock(new TextEncoder().encode(encrypted.inputs.custodyFile),encrypted.inputs.custodyPassword)
    const key='castalia-wallet-identities-v1:'+core.publicKey(),saved=(await chrome.storage.local.get(key))[key]
    const contents=JSON.parse(encrypted.cases.find(c=>c.id==='populated')!.contentsRaw)
    contents.sections.feeds=JSON.parse(projection.cases[0].sourceRaw)
    const raw=reseal?core.openIdentitySection(new TextEncoder().encode(saved.ciphertext)):JSON.stringify(contents)
    const ciphertext=core.sealIdentitySection(raw)
    await chrome.storage.local.set({[key]:{schema:'castalia.wallet-identity-storage.v1',revision:saved?.revision??1,ciphertext}})
  }finally{core.free()}
}
chrome.runtime.onMessage.addListener((message:any,sender:any,respond:(value:unknown)=>void)=>{
  if(message?.type==='CASTALIA_PROVIDER_REQUEST'){
    if(message.method==='castalia.wallet.getCapabilities'){respond({id:message.id,ok:true,result:runtime.capabilities()});return false}
    if(message.method==='castalia.wallet.isAvailable'){respond({id:message.id,ok:true,result:true});return false}
    respond({id:message.id,ok:false,error:'fixture_method_unavailable'});return false
  }
  if(message?.type!=='SELECTED_FEEDS_FIXTURE_CONTROL')return false
  if(sender?.id!==chrome.runtime.id||sender.frameId!==undefined&&sender.frameId!==0||sender.url!==setupURL||!sender.documentId){respond({ok:false});return false}
  void queue.run(async()=>{
    const contexts=await chrome.runtime.getContexts({documentIds:[sender.documentId],documentUrls:[setupURL],frameIds:[0]})
    if(contexts.length!==1||contexts[0].documentUrl!==setupURL||contexts[0].documentId!==sender.documentId||contexts[0].frameId!==0)throw Error('invalid_fixture_document')
    switch(message.action){
      case 'setup':{
        await chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'})
        await custodyState.importEncrypted(encrypted.inputs.custodyFile,encrypted.inputs.custodyPassword,{replaceExisting:false})
        await custodyState.unlock(encrypted.inputs.custodyPassword);await seed();return 'Synthetic custody and encrypted source ready; destination unapproved.'
      }
      case 'approve':await sessionState.approveOrigin(origin);invalidateCustodyApprovals();return 'Synthetic destination approved separately.'
      case 'revoke':await sessionState.revokeOrigin(origin);invalidateCustodyApprovals();return 'Destination revoked.'
      case 'lock':await custodyState.lock();return 'Locked.'
      case 'unlock':await custodyState.unlock(encrypted.inputs.custodyPassword);return 'Unlocked.'
      case 'reseal':await seed(true);return 'Same revision, new ciphertext.'
      case 'advance90':offset+=90_000;return 'Synthetic clock advanced90s.'
      case 'advance31':offset+=31_000;return 'Synthetic clock advanced31s.'
      case 'reset-clock':offset=0;return 'Synthetic clock reset outside an operation.'
      case 'guards':{
        let refused=false;try{await walletIdentities.reviewImport(encrypted.cases.find(c=>c.id==='populated')!.envelope,encrypted.inputs.dataPassword)}catch(error){refused=error instanceof Error&&error.message==='feed_storage_not_qualified'}
        if(!refused)throw Error('v3_default_guard_not_preserved');return 'Existing v3 import guard refused.'
      }
      default:throw Error('unknown_fixture_action')
    }
  }).then(result=>respond({ok:true,result}),error=>respond({ok:false,error:error instanceof Error?error.message:'fixture_failure'}))
  return true
})
