/** Source qualification only: opens the fixed public custody fixture, never user input custody. */
import{readFileSync}from'node:fs';import{initSync,WasmWallet}from'../apps/chrome-extension/src/generated/castalia-wallet-core/bindings.js';import{CASTALIA_WALLET_CORE_WASM}from'../apps/chrome-extension/src/generated/castalia-wallet-core/wasm-bytes.js';
initSync({module:CASTALIA_WALLET_CORE_WASM});
const raw=readFileSync(0,'utf8');if(Buffer.byteLength(raw)>20000)throw Error('fixture request too large');const request=JSON.parse(raw);
const fixture=JSON.parse(readFileSync(new URL('../docs/contracts/castalia-wallet-custody-v1.vector.json',import.meta.url),'utf8'));
const wallet=new WasmWallet();wallet.unlock(new TextEncoder().encode(JSON.stringify(fixture.container)),fixture.inputs.passphraseUnicode);
try{
 if(request.operation==='identity')console.log(JSON.stringify({subject_public_key:wallet.publicKey()}));
 else if(request.operation==='approve'){
  const caller={kind:'browser',id:'https://example.test'},pins=[{issuer:'fixture',key_id:'fixture-key',public_key:'22'.repeat(32),audience:'fixture',callers:[caller]}];
  const handle=wallet.prepareAccessRequest(JSON.stringify(request.challenge),'b'.repeat(32),JSON.stringify(pins),JSON.stringify(caller),String(request.now));
  try{console.log(wallet.approveAccessRequest(handle,String(request.now)));}finally{handle.free();}
 }else throw Error('unknown fixture operation');
}finally{wallet.free();}
