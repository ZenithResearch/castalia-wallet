import {test} from 'node:test';
import assert from 'node:assert/strict';
import{readFileSync}from'node:fs';
import{createPublicKey,verify}from'node:crypto';
import{initSync,WasmWallet}from'../src/generated/castalia-wallet-core/bindings.js';
import{CASTALIA_WALLET_CORE_WASM}from'../src/generated/castalia-wallet-core/wasm-bytes.js';
initSync({module:CASTALIA_WALLET_CORE_WASM});
const vector=JSON.parse(readFileSync(new URL('../../../docs/contracts/castalia-access-request-v1.vector.json',import.meta.url),'utf8'));
const custody=JSON.parse(readFileSync(new URL('../../../docs/contracts/castalia-wallet-custody-v1.vector.json',import.meta.url),'utf8'));
function wallet(){const w=new WasmWallet();w.unlock(new TextEncoder().encode(JSON.stringify(custody.container)),custody.inputs.passphraseUnicode);return w;}
const pins=[{issuer:'fixture',key_id:'fixture-key',public_key:'22'.repeat(32),audience:'fixture',callers:[{kind:'browser',id:'https://example.test'}]}];
function prepare(w:WasmWallet){return w.prepareAccessRequest(JSON.stringify(vector.challenge),'b'.repeat(32),JSON.stringify(pins),JSON.stringify(pins[0].callers[0]),'100');}
test('actual WASM signs the shared request vector once and lock invalidates prepared requests',()=>{
 const w=wallet(),p=prepare(w),a=JSON.parse(w.approveAccessRequest(p,'101'));
 assert.equal(a.signature,vector.signature);
 const key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(w.publicKey(),'hex')]),type:'spki',format:'der'});
 assert.ok(verify(null,Buffer.from(vector.signing_bytes_hex,'hex'),key,Buffer.from(a.signature,'base64url')));
 assert.throws(()=>w.approveAccessRequest(p,'101'));p.free();
 const stale=prepare(w);w.lock();assert.throws(()=>w.approveAccessRequest(stale,'101'));stale.free();w.free();
});
