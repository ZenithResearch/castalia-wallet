import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareLoginReview, sendGeneralAccessRequest} from '../src/session-login-flow.js';

test('saved access skips duration setup but never approves a session', async()=>{
 const calls:any[]=[];
 const command=async(op:string,value?:any)=>{calls.push([op,value]);return calls.length===1?{options:{maximum_ttl_seconds:1800,default_ttl_seconds:900}}:{challenge:{expires_at:2800}};};
 const request={requested_ttl_seconds:3600};
 assert.deepEqual(await prepareLoginReview(command,request),{challenge:{expires_at:2800}});
 assert.deepEqual(calls,[['prepare',{request,ttlSeconds:undefined}],['prepare',{request,ttlSeconds:1800}]]);
});
test('no saved access returns the access error without asking for wider rights',async()=>{
 const calls:string[]=[];
 await assert.rejects(prepareLoginReview(async op=>{calls.push(op);throw Error('grant_not_saved');},{requested_ttl_seconds:3600}),/grant_not_saved/);
 assert.deepEqual(calls,['prepare']);
});
test('invalid or widened duration ceilings cannot prepare a challenge',async()=>{
 for(const maximum of [0,-1,3601,1.5,NaN]){
  let count=0;
  await assert.rejects(prepareLoginReview(async()=>{count++;return {options:{maximum_ttl_seconds:maximum}};},{requested_ttl_seconds:3600}),/invalid_holder_session/);
  assert.equal(count,1);
 }
});
test('an explicit shorter choice remains bounded and is not overwritten',async()=>{
 const calls:any[]=[];
 await prepareLoginReview(async(op,value)=>{calls.push([op,value]);return {challenge:{}};},{requested_ttl_seconds:3600},60);
 assert.equal(calls.length,1);assert.equal(calls[0][1].ttlSeconds,60);
});
test('one Wallet request gesture prepares then sends exactly the original general request',async()=>{
 const calls:any[]=[];
 const result=await sendGeneralAccessRequest(async(op,value)=>{calls.push([op,value]);return {};},async op=>{calls.push([op]);return {status:'pending'};});
 assert.equal(result.status,'pending');assert.deepEqual(calls,[['prepareAccess',false],['approveAccess']]);
});
test('failed unsigned preparation cannot send, and unknown outcomes are not retried',async()=>{
 let sends=0;
 await assert.rejects(sendGeneralAccessRequest(async()=>{throw Error('preparation_failed');},async()=>{sends++;}),/preparation_failed/);assert.equal(sends,0);
 await assert.rejects(sendGeneralAccessRequest(async()=>({}),async()=>{sends++;throw Error('outcome_unknown');}),/outcome_unknown/);assert.equal(sends,1);
});

test('saved-access help stops before child preparation so stale-grant recovery stays possible',async()=>{
 const calls:any[]=[];
 const request={requested_ttl_seconds:3600};
 const options={maximum_ttl_seconds:3600,default_ttl_seconds:900};
 assert.deepEqual(await prepareLoginReview(async(op,value)=>{calls.push([op,value]);return {options};},request,undefined,true),{options});
 assert.deepEqual(calls,[['prepare',{request,ttlSeconds:undefined}]]);
});
