import assert from 'node:assert/strict';
import test from 'node:test';
import {createHolderSessionExchange} from '../src/holder-session-exchange.js';

const BASE='/holder-sessions/v1';
function fixture(attack=''){
 const calls:Array<{url:string;options:any;body:any}>=[];let reviews=0,approvals=0;
 const pin={issuer:'issuer',key_id:'key',public_key:'a'.repeat(64),service:'service:graph'};
 const parent:any={claims:{schema:'secs.holder-grant.v2',max_credential_lifetime_seconds:3600,validity:{schema:'castalia.grant-validity.v1',mode:'until_revoked',not_before:900},permissions:[{operation:'fixture.read'}]},privateFixture:'synthetic-parent-authority'};
 const c={schema:'secs.holder-session-challenge.v1',request_id:'b'.repeat(32),challenge_id:'c'.repeat(32),session_public_key:'d'.repeat(64),session_installation_id:'e'.repeat(32),expires_at:1060,review_deadline:1030};
 const token={claims:{schema:'secs.holder-session-credential.v1',challenge:c},signature:'synthetic-signature'};
 const caps={schema:'secs.holder-session-capabilities.v1',supported:true,profile:'secs.holder-session.v1',issuer_pin:pin,audience:'devgraph',grant_schemas:['secs.holder-grant.v2'],credential_schema:'secs.holder-session-credential.v1',presentation_schema:'secs.holder-session-presentation.v1',read_only:true,max_ttl_seconds:600,review_ttl_seconds:120,proof_max_ttl_seconds:60,challenge_path:BASE+'/challenges',exchange_path:BASE+'/exchange',status_path:BASE+'/status'};
 if(attack==='endpoint')caps.exchange_path='https://evil.example/';
 if(attack==='pin')caps.issuer_pin={...pin,public_key:'f'.repeat(64)};
 if(attack==='v1')parent.claims.schema='secs.holder-grant.v1';
 const transport=createHolderSessionExchange({now:()=>1000,randomId:()=>c.request_id,
  grants:{prepare:async()=>({stored:{pin,parent,grant:parent},revision:1}),assertRevision:async()=>{if(attack==='revision')throw Error('grant_storage_changed')}},
  route:()=>'',audience:()=>attack!=='audience',
  review:(_stored,challenge)=>{reviews++;assert.deepEqual(challenge,c);return{schema:'castalia.holder-session-review.v1'}},
  approve:(_stored,challenge)=>{approvals++;assert.deepEqual(challenge,c);return{schema:'secs.holder-session-authorization.v1',challenge:c,parent_grant:parent}},
  verify:()=>({schema:'castalia.holder-session-credential-verified.v1',credential_digest:'0'.repeat(64),service:pin.service,session_public_key:c.session_public_key,session_installation_id:c.session_installation_id,expires_at:c.expires_at}),
  fetchImpl:async function(this:unknown,url,options:any){
   assert.equal(this,undefined,'native worker fetch must not receive the dependency object as its receiver');
   const body=options.body?JSON.parse(options.body):undefined;calls.push({url:String(url),options,body});
   assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');assert.equal(options.referrerPolicy,'no-referrer');assert.ok(options.signal);
   let result:any=caps;
   if(String(url).endsWith('/challenges'))result={schema:'secs.holder-session-challenge-result.v1',challenge:c};
   if(String(url).endsWith('/exchange')){
    if(attack==='network')throw Error('raw network diagnostic');
    result={schema:'secs.holder-session-result.v1',request_id:c.request_id,challenge_id:c.challenge_id,state:'issued',credential:token,expires_at:c.expires_at};
   }
   let raw=JSON.stringify(result);
   if(attack==='duplicate'&&String(url).endsWith('/challenges'))raw=raw.replace('"schema":','"schema":"duplicate","schema":');
   if(attack==='float'&&String(url).endsWith('/capabilities'))raw=raw.replace('"max_ttl_seconds":600','"max_ttl_seconds":6e2');
   if(attack==='large')raw=JSON.stringify({oversized:'a'.repeat(131072)});
   if(attack==='malformed')raw='{"privateFixture":"must-not-appear-in-diagnostics';
   return new Response(raw,{status:200,headers:{'Content-Type':'application/json'}});
  },
 });
 const request={service:pin.service,origin:'https://graph.example',installation:'f'.repeat(32),sessionPublicKey:c.session_public_key,sessionInstallationId:c.session_installation_id,ttlSeconds:60,permissions:null};
 return{transport,request,calls,parent,counts:()=>({reviews,approvals})};
}
test('issuer transport keeps parent private and uses only fixed cookie-free HTTPS endpoints',async()=>{
 const f=fixture(),p=await f.transport.prepare(f.request);assert.equal(f.counts().approvals,0);
 assert.equal(f.calls[1].body.parent_grant.privateFixture,'synthetic-parent-authority');
 assert.equal(f.calls[1].body.permissions,null,'the trusted receiver chooses the default read subset; never copy every parent permission');
 const result=await f.transport.activate(p,'a'.repeat(128));assert.equal(JSON.stringify(result).includes('synthetic-parent-authority'),false);
 assert.deepEqual(f.calls.map(c=>c.url),['/capabilities','/challenges','/exchange'].map(p=>'https://graph.example'+BASE+p));
 assert.deepEqual(f.counts(),{reviews:1,approvals:1});
});
for(const attack of ['pin','endpoint','duplicate','float','large','v1','audience'])test('issuer preparation rejects '+attack+' before any authorization',async()=>{
 const f=fixture(attack);await assert.rejects(f.transport.prepare(f.request));assert.equal(f.counts().approvals,0);
});
test('changed encrypted grant storage rejects before signing or exchange',async()=>{
 const f=fixture('revision'),p=await f.transport.prepare(f.request);await assert.rejects(f.transport.activate(p,'a'.repeat(128)),/grant_storage_changed/);assert.equal(f.counts().approvals,0);assert.equal(f.calls.length,2);
});
test('an exchange transport failure is unknown and exposes no raw network diagnostics',async()=>{
 const f=fixture('network'),p=await f.transport.prepare(f.request);await assert.rejects(f.transport.activate(p,'a'.repeat(128)),/^Error: holder_session_outcome_unknown$/);assert.equal(f.counts().approvals,1);assert.equal(f.calls.length,3);
});
test('malformed issuer JSON never exposes its raw body through an error',async()=>{
 const f=fixture('malformed');await assert.rejects(f.transport.prepare(f.request),/^Error: invalid_holder_session$/);
});
test('a response broader than explicit requested permissions is rejected before authorization',async()=>{
 const f=fixture(),request={...f.request,permissions:[{operation:'fixture.read',selection:'narrow'}]};
 await assert.rejects(f.transport.prepare(request));assert.equal(f.counts().approvals,0);
});

test('canonical until-revoked grant omits expiry and still has a finite session ceiling',async()=>{
 const f=fixture();assert.equal(Object.hasOwn(f.parent.claims.validity,'not_after'),false);
 assert.deepEqual(await f.transport.options({...f.request,ttlSeconds:3600}),{maximum_ttl_seconds:600,default_ttl_seconds:600});
 f.parent.claims.max_credential_lifetime_seconds=120;
 assert.deepEqual(await f.transport.options({...f.request,ttlSeconds:3600}),{maximum_ttl_seconds:120,default_ttl_seconds:120});
 assert.deepEqual(await f.transport.options({...f.request,ttlSeconds:30}),{maximum_ttl_seconds:30,default_ttl_seconds:30});
 assert.equal(f.counts().approvals,0);assert.ok(f.calls.every(c=>c.url.endsWith('/capabilities')));
});
test('dated parent expiry caps the exact remaining session lifetime',async()=>{
 const f=fixture();f.parent.claims.validity={schema:'castalia.grant-validity.v1',mode:'dated',not_before:900,not_after:1001};
 assert.deepEqual(await f.transport.options({...f.request,ttlSeconds:3600}),{maximum_ttl_seconds:1,default_ttl_seconds:1});
 for(const end of [1000,999]){f.parent.claims.validity.not_after=end;await assert.rejects(f.transport.options(f.request),/read_approval_expired/);}
 assert.equal(f.counts().approvals,0);
});
for(const validity of [undefined,null,{},
 {not_after:null},
 {schema:'castalia.grant-validity.v1',mode:'until_revoked',not_before:900,not_after:null},
 {schema:'castalia.grant-validity.v1',mode:'until_revoked',not_before:900,extra:true},
 {schema:'wrong',mode:'until_revoked',not_before:900},
 {schema:'castalia.grant-validity.v1',mode:'forever',not_before:900},
 {schema:'castalia.grant-validity.v1',mode:'until_revoked',not_before:-1},
 {schema:'castalia.grant-validity.v1',mode:'until_revoked',not_before:1001},
 {schema:'castalia.grant-validity.v1',mode:'dated',not_before:900,not_after:null},
 {schema:'castalia.grant-validity.v1',mode:'dated',not_before:900,not_after:1000.5},
 {schema:'castalia.grant-validity.v1',mode:'dated',not_before:900,not_after:Number.MAX_SAFE_INTEGER+1},
])test('duration options reject malformed or not-yet-valid parent '+JSON.stringify(validity),async()=>{
 const f=fixture();f.parent.claims.validity=validity;
 await assert.rejects(f.transport.options(f.request),/invalid_holder_session/);assert.equal(f.counts().approvals,0);
});
