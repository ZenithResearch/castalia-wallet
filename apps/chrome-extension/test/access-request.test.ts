import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createReadAccessController} from '../src/read-access.js';
function fixture(){
 let epoch=1,live=true,allow=true,signed=0,disposed=0;
 const context={origin:'https://app.test',documentId:'doc',tabId:1,current:()=>live};
 const handle={summary:()=>({kind:'access_request',operation:'access.request',approval_expires_at:220,details:{intent:null}}),approve:()=>{signed++;return{challenge:{},signature:'fixture'}},dispose:()=>{disposed++}};
 const deps:any={run:async(f:any)=>f(),state:async()=>({memberKey:'a'.repeat(64),approvedOrigins:new Set([context.origin])}),epoch:()=>epoch,installation:async()=> 'b'.repeat(32),memberships:async()=>[],membership:async()=>({verified:true}),prepareRequest:async()=>handle,confirm:async()=>allow,randomId:()=> 'unused',now:()=>100};
 return{controller:createReadAccessController(deps),context,deps,deny:()=>{allow=false},lock:()=>{epoch++},navigate:()=>{live=false},counts:()=>({signed,disposed})};
}
test('request approval is one-shot and creates no read or write connection',async()=>{
 const f=fixture();const r=await f.controller.handle({operation:'request',challenge:{},profileId:'fixture'},f.context);
 assert.deepEqual(r,{approval:{challenge:{},signature:'fixture',proof:{verified:true}}});
 assert.deepEqual(f.counts(),{signed:1,disposed:1});
 assert.equal(r.accessId,undefined);
 await assert.rejects(f.controller.handle({operation:'present',accessId:'unused',call:{}},f.context),/read_access_required/);
});
for(const fail of ['deny','lock','navigate'] as const)test(fail+' blocks access-request signature',async()=>{
 const f=fixture();f.deps.confirm=async()=>{f[fail]();return fail!=='deny'};
 await assert.rejects(f.controller.handle({operation:'request',challenge:{},profileId:'fixture'},f.context));
 assert.equal(f.counts().signed,0);assert.equal(f.counts().disposed,1);
});
test('request approval rechecks membership after consent',async()=>{
 const f=fixture();let calls=0;f.deps.membership=async()=>{if(++calls>1)throw Error('membership_revoked');return{}};
 await assert.rejects(f.controller.handle({operation:'request',challenge:{},profileId:'fixture'},f.context),/membership_revoked/);
 assert.equal(f.counts().signed,0);assert.equal(f.counts().disposed,1);
});

test('generic operator consent needs identity, not community membership',async()=>{
 const f=fixture();f.deps.membership=async()=>{throw Error('must not request a membership proof')};
 const result=await f.controller.handle({operation:'request',challenge:{}},f.context);
 assert.deepEqual(result.approval.proof,{});assert.equal(f.counts().signed,1);
});
