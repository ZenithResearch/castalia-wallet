import assert from 'node:assert/strict';
import test from 'node:test';
import {createSessionLoginPermit} from '../src/session-login-permit.js';
function fixture(){
 let receive:any,disconnect:any,fenced=0,complete=0;
 const port={onMessage:{addListener:(f:any)=>receive=f},onDisconnect:{addListener:(f:any)=>disconnect=f},disconnect(){},postMessage(m:any){
  if(m.kind==='acquire')queueMicrotask(()=>receive({kind:'granted',leaseId:m.leaseId,expiresAtMs:Date.now()+1000}));
  if(m.kind==='complete'){complete++;queueMicrotask(()=>receive({kind:'released',leaseId:m.leaseId}));}
 }};
 const permit=createSessionLoginPermit({runtime:{connect:()=>port}},'a'.repeat(32),async()=> 'b'.repeat(64),()=>{fenced++;});
 return{permit,disconnect:()=>disconnect(),counts:()=>({fenced,complete})};
}
test('permit is memory-only, exact and consumed before queue release',async()=>{const f=fixture();assert.throws(()=>f.permit.current());await f.permit.run(async token=>{assert.equal(f.permit.check(token.leaseId),token);assert.throws(()=>f.permit.check('c'.repeat(32)));return 3;});assert.throws(()=>f.permit.current());assert.deepEqual(f.counts(),{fenced:0,complete:1});});
test('a returned private rejection closes only the completed phase',async()=>{const f=fixture();await assert.rejects(f.permit.run(async()=>{throw Error('private returned failure');}),/private returned failure/);assert.deepEqual(f.counts(),{fenced:0,complete:1});});
test('service-worker disconnect fences the private signer and never claims normal release',async()=>{const f=fixture();await assert.rejects(f.permit.run(async()=>{f.disconnect();return 2;}));assert.ok(f.counts().fenced>0);assert.equal(f.counts().complete,0);});
