import assert from 'node:assert/strict'
import test from 'node:test'
import {readFileSync} from 'node:fs'
import {createPublicKey,verify} from 'node:crypto'
import {initSync,WasmWallet} from '../src/generated/castalia-wallet-core/bindings.js'
import {CASTALIA_WALLET_CORE_WASM} from '../src/generated/castalia-wallet-core/wasm-bytes.js'
import {buildFilesConsent,filesBase64url,type FilesKeyEnvelopeV1} from '../src/files-key-contract.js'
import {createFilesKeyHandler} from '../src/files-key-handler.js'
initSync({module:CASTALIA_WALLET_CORE_WASM})
const fixture=JSON.parse(readFileSync(new URL('../../../docs/contracts/files-key-wrap-v1.vector.json',import.meta.url),'utf8'))
function provider(wallet:WasmWallet) {
 const owner=wallet.publicKey(),origin='https://castalia.example'
 const publicKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(owner,'hex')]),type:'spki',format:'der'}).export({type:'spki',format:'pem'}).toString()
 return createFilesKeyHandler({runCustody:fn=>fn(),epoch:()=>1,nowMs:Date.now,isCurrent:()=>true,currentOrigin:async()=>origin,reserve:async()=>{},confirm:async()=>true,
  getState:async()=>({memberKey:owner,approvedOrigins:new Set([origin]),wrap:async(binding,key)=>JSON.parse(wallet.wrapFilesKey(JSON.stringify(binding),key)),unwrap:async(binding,envelope)=>wallet.unwrapFilesKey(JSON.stringify(binding),JSON.stringify(envelope)),authenticate:async(body,actualOrigin,nowMs)=>({subject:{subjectId:`did:castalia:member:${owner}`,publicKey,dreggOwnerPublicKey:owner,walletKind:'castalia-dregg'},challenge:body.challenge,signature:Buffer.from(wallet.signFilesServiceAuthentication(JSON.stringify(body.challenge),actualOrigin,body.serviceKind,body.serviceId,BigInt(nowMs))).toString('base64'),signatureAlgorithm:'ed25519'})})})
}
test('actual extension WASM recovers Web-origin ciphertext from existing custody and returns only the scoped data key',async()=>{
 const first=new WasmWallet(),fresh=new WasmWallet(),origin='https://castalia.example'
 try {
  first.unlock(new TextEncoder().encode(JSON.stringify(fixture.custody)),fixture.custodyPassphrase)
  assert.equal(first.publicKey(),fixture.envelope.binding.ownerMemberKey)
  const invoke=provider(first),body={binding:fixture.envelope.binding,key:filesBase64url(new Uint8Array(32).fill(9))}
  const envelope=await invoke('wrap',{...body,consent:await buildFilesConsent('wrap',body,origin)},origin) as FilesKeyEnvelopeV1
  const recovery=first.exportRandomized('new encrypted recovery passphrase');first.lock()
  assert.throws(()=>first.unwrapFilesKey(JSON.stringify(body.binding),JSON.stringify(envelope)))
  fresh.unlock(new TextEncoder().encode(recovery),'new encrypted recovery passphrase')
  const restored=provider(fresh)
  for(const candidate of [fixture.envelope,envelope]) {
   const input={binding:body.binding,envelope:candidate}
   assert.deepEqual(await restored('unwrap',{...input,consent:await buildFilesConsent('unwrap',input,origin)},origin),{key:body.key})
  }
  const now=Date.now(),auth={serviceKind:'gateway' as const,serviceId:body.binding.serviceId,challenge:{audience:`castalia-files://gateway/${body.binding.serviceId}`,domain:'castalia-wallet' as const,expiresAt:new Date(now+60000).toISOString(),issuedAt:new Date(now).toISOString(),nonce:'public-auth-fixture-nonce',operation:'castalia.wallet.signChallenge' as const,origin,version:1 as const}}
  const signed=await restored('authenticate',{...auth,consent:await buildFilesConsent('authenticate',auth,origin)},origin)
  assert.ok('signature' in signed)
  assert.ok(verify(null,Buffer.from(JSON.stringify(auth.challenge)),createPublicKey(signed.subject.publicKey),Buffer.from(signed.signature,'base64')))
 }finally{first.lock();first.free();fresh.lock();fresh.free()}
})
