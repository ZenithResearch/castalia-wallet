import test from 'node:test';import assert from 'node:assert/strict';
import {createHolderGrantsStore} from '../src/holder-grants-store.js';
function fixture(){
 let owner='a'.repeat(64),writes=0,signs=0;
 const grant=(service:string)=>({pin:{service},saved_at:1,grant:{claims:{service,grant_id:service,revision:'old',validity:{mode:'dated',not_before:1,not_after:2},permissions:[]}}});
 const grants={'service:one':grant('service:one'),'service:two':grant('service:two')};
 const sealed=new Map<string,string>([['old',JSON.stringify({schema:'castalia.holder-grant-backup.v1',owner_public_key:owner,grants})]]);
 const key='castalia-holder-grants-v1:'+owner;const disk:any={[key]:{schema:'castalia.holder-grant-storage.v1',revision:4,ciphertext:'old'},identity:'keep',accounts:'keep',trust:'keep',journals:'keep'};
 const store=createHolderGrantsStore({storage:{get:async k=>({[k]:disk[k]}),set:async v=>{writes++;Object.assign(disk,v)}},owner:()=>owner,now:()=>100,
  seal:raw=>{sealed.set('new',raw);return'new'},open:c=>sealed.get(c)!,validateBackup:raw=>{const v=JSON.parse(raw);if(v.owner_public_key!==owner)throw Error('wrong_owner');return JSON.stringify(v.grants)},
  review:async()=>{throw Error('no authority review needed')},reviewDerivation:()=>{},derive:()=>{signs++;throw Error('must not sign')},present:()=>{},});
 return {store,disk,key,writes:()=>writes,signs:()=>signs,changeOwner:()=>{owner='b'.repeat(64)},contents:()=>JSON.parse(sealed.get(disk[key].ciphertext)!),changeRecord:()=>{const g=JSON.parse(sealed.get('old')!);g.grants['service:one'].grant.claims.revision='changed';sealed.set('old',JSON.stringify(g))}};
}
test('forget review does not write; confirm removes only exact service and advances encrypted revision',async()=>{
 const f=fixture(),review=await f.store.reviewForget('service:one');assert.equal(f.writes(),0);assert.equal(review.grant.grant_id,'service:one');
 await f.store.forget(review);assert.equal(f.disk[f.key].revision,5);assert.deepEqual(Object.keys(f.contents().grants),['service:two']);
 assert.equal(f.disk.identity,'keep');assert.equal(f.disk.accounts,'keep');assert.equal(f.disk.trust,'keep');assert.equal(f.disk.journals,'keep');assert.equal(f.signs(),0);
 await assert.rejects(f.store.forget(review));assert.equal(f.writes(),1);
 const second=await f.store.reviewForget('service:two');await f.store.forget(second);assert.equal(f.disk[f.key].revision,6);assert.deepEqual(f.contents().grants,{});assert.ok(f.disk[f.key].ciphertext);
});
test('changed revision, exact record or owner rejects forget without writing',async()=>{
 for(const change of ['revision','record','owner']){const f=fixture(),p=await f.store.reviewForget('service:one');if(change==='revision')f.disk[f.key].revision++;if(change==='record')f.changeRecord();if(change==='owner')f.changeOwner();const before=JSON.stringify(f.disk);await assert.rejects(f.store.forget(p));assert.equal(JSON.stringify(f.disk),before);assert.equal(f.writes(),0);}
});
test('missing/invalid service cannot be forgotten and unrelated prepared saves become stale',async()=>{
 const f=fixture();for(const service of ['',null,'x'.repeat(257),'service:missing','__proto__'])await assert.rejects(f.store.reviewForget(service as any));
 const rev=4;await f.store.forget(await f.store.reviewForget('service:one'));await assert.rejects(f.store.assertRevision(rev));
});
