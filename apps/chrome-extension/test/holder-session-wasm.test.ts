import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPrivateKey,createPublicKey,generateKeyPairSync,sign,verify} from 'node:crypto';
import {initSync,WasmWallet} from '../src/generated/castalia-wallet-core/bindings.js';
import {CASTALIA_WALLET_CORE_WASM} from '../src/generated/castalia-wallet-core/wasm-bytes.js';
import {createHolderSessionExchange} from '../src/holder-session-exchange.js';

initSync({module:CASTALIA_WALLET_CORE_WASM});
const canonical=(v:any):string=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
const transcript=(domain:string,v:any)=>Buffer.from(domain+'\0'+canonical(v));
const digest=(v:any)=>createHash('sha256').update(canonical(v)).digest('hex');
const publicHex=(key:any)=>key.export({type:'spki',format:'der'}).subarray(-32).toString('hex');
const publicKey=(hex:string)=>createPublicKey({key:Buffer.from('302a300506032b6570032100'+hex,'hex'),type:'spki',format:'der'});

test('actual WASM reviews and approves the private exchange; finite receipt verifies after Wallet lock',async()=>{
 const wallet=new WasmWallet() as any;
 wallet.create('Disposable session exchange test password',1n);
 try{
  const issuer=createPrivateKey({key:Buffer.from('302e020100300506032b657004220420'+'09'.repeat(32),'hex'),type:'pkcs8',format:'der'});
  const session=generateKeyPairSync('ed25519'),origin='https://graph.example',installation='33'.repeat(16),sessionInstallation='44'.repeat(16);
  const pin={issuer:'fixture',key_id:'key',public_key:publicHex(createPublicKey(issuer)),service:'service:fixture'};
  const permissions=[{operation:'devgraph.work.list',resource:'https://work.zenith-research.ca/devgraph',constraints:{archived:false},roles:[{role:'target',selector:{schema:'secs.resource-selector.v1',service:pin.service,kinds:['Task'],selection:{mode:'all'}}}]}];
  const claims={schema:'secs.holder-grant.v2',grant_id:'11'.repeat(16),revision:'22'.repeat(32),issuer:pin.issuer,key_id:pin.key_id,service:pin.service,holder_public_key:wallet.publicKey(),installation_id:null,validity:{schema:'castalia.grant-validity.v1',mode:'until_revoked',not_before:100},max_credential_lifetime_seconds:600,onward_delegation:false,permissions};
  const parent={claims,signature:sign(null,transcript('secs.holder-grant.v2/signature',claims),issuer).toString('hex')};
  const pins=[{...pin,audience:'devgraph',callers:[{kind:'browser',id:origin}]}];delete (pins[0] as any).service;
  const stored=JSON.parse(wallet.reviewHolderGrant(JSON.stringify(parent),JSON.stringify(pins),JSON.stringify({kind:'browser',id:origin}),installation,'1000')).stored;
  let challenge:any,authorization:any,credential:any,reviews=0,approvals=0;
  const calls:string[]=[];
  const invoke=(name:string,args:any[])=>JSON.parse(wallet[name](...args));
  const transport=createHolderSessionExchange({now:()=>1000,randomId:()=>'55'.repeat(16),
   grants:{prepare:async()=>({stored,revision:1}),assertRevision:async r=>assert.equal(r,1)},
   route:()=>'',audience:()=>true,
   review:(s,c,o,a,i,n)=>{reviews++;return invoke('reviewHolderSessionAuthorization',[JSON.stringify(s),JSON.stringify(c),o,a,i,String(n)]);},
   approve:(s,c,signature,o,a,i,n)=>{approvals++;return invoke('approveHolderSessionAuthorization',[JSON.stringify(s),JSON.stringify(c),signature,o,a,i,String(n)]);},
   verify:(p,c,expected,n)=>invoke('verifyHolderSessionCredential',[JSON.stringify(p),JSON.stringify(c),JSON.stringify(expected),String(n)]),
   fetchImpl:async(url,options:any)=>{
    const path=new URL(String(url)).pathname;calls.push(path);
    assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');
    const body=options.body?JSON.parse(options.body):null;let response:any;
    if(path.endsWith('/capabilities'))response={schema:'secs.holder-session-capabilities.v1',supported:true,profile:'secs.holder-session.v1',issuer_pin:pin,audience:'devgraph',grant_schemas:['secs.holder-grant.v2'],credential_schema:'secs.holder-session-credential.v1',presentation_schema:'secs.holder-session-presentation.v1',read_only:true,max_ttl_seconds:600,review_ttl_seconds:120,proof_max_ttl_seconds:60,challenge_path:'/holder-sessions/v1/challenges',exchange_path:'/holder-sessions/v1/exchange',status_path:'/holder-sessions/v1/status'};
    else if(path.endsWith('/challenges')){
     assert.deepEqual(body.parent_grant,parent);assert.equal(body.permissions,null);
     challenge={schema:'secs.holder-session-challenge.v1',challenge_id:'66'.repeat(16),request_id:body.request_id,nonce:'77'.repeat(32),issuer:pin.issuer,key_id:pin.key_id,service:pin.service,audience:body.audience,origin:body.origin,parent_grant_id:claims.grant_id,parent_grant_digest:digest(parent),parent_revision:claims.revision,holder_public_key:claims.holder_public_key,installation_id:body.installation_id,session_installation_id:body.session_installation_id,session_public_key:body.session_public_key,permissions,issued_at:1000,review_deadline:1060,expires_at:1060};
     response={schema:'secs.holder-session-challenge-result.v1',challenge};
    }else{
     assert.equal(path,'/holder-sessions/v1/exchange');authorization=body;
     assert.deepEqual(body.parent_grant,parent);assert.deepEqual(body.challenge,challenge);
     assert.ok(verify(null,transcript('secs.holder-session-possession.v1/signature',challenge),session.publicKey,Buffer.from(body.session_signature,'hex')));
     assert.ok(verify(null,transcript('secs.holder-session-authorization.v1/signature',challenge),publicKey(claims.holder_public_key),Buffer.from(body.holder_signature,'hex')));
     const finite={schema:'secs.holder-session-credential.v1',credential_id:'88'.repeat(16),challenge_digest:digest(challenge),challenge};
     credential={claims:finite,signature:sign(null,transcript('secs.holder-session-credential.v1/signature',finite),issuer).toString('hex')};
     response={schema:'secs.holder-session-result.v1',request_id:challenge.request_id,challenge_id:challenge.challenge_id,state:'issued',credential,expires_at:1060};
    }
    return new Response(JSON.stringify(response),{status:200,headers:{'Content-Type':'application/json'}});
   },
  });
  const prepared=await transport.prepare({service:pin.service,origin,installation,sessionPublicKey:publicHex(session.publicKey),sessionInstallationId:sessionInstallation,ttlSeconds:60,permissions:null});
  assert.equal(prepared.summary.hard_expiry,true);assert.equal(prepared.summary.expires_at,1060);assert.equal('parent_grant' in prepared.summary,false);
  assert.equal(approvals,0);
  const signature=sign(null,transcript('secs.holder-session-possession.v1/signature',challenge),session.privateKey).toString('hex');
  const opened=await transport.activate(prepared,signature);
  assert.deepEqual(opened,{credential});assert.equal(JSON.stringify(opened).includes('"parent_grant":'),false);
  assert.equal(reviews,1);assert.equal(approvals,1);assert.equal(authorization.schema,'secs.holder-session-authorization.v1');
  assert.deepEqual(calls,['capabilities','challenges','exchange'].map(p=>'/holder-sessions/v1/'+p));
  wallet.lock();
  const verified=invoke('verifyHolderSessionCredential',[JSON.stringify(pin),JSON.stringify(credential),JSON.stringify(challenge),'1001']);
  assert.equal(verified.expires_at,1060);
  assert.throws(()=>invoke('reviewHolderSessionAuthorization',[JSON.stringify(stored),JSON.stringify(challenge),origin,'devgraph',installation,'1001']));
  assert.throws(()=>invoke('verifyHolderSessionCredential',[JSON.stringify(pin),JSON.stringify(credential),JSON.stringify(challenge),'1060']));
 }finally{wallet.lock();wallet.free();}
});
