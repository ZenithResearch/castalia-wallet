import test from 'node:test';
import assert from 'node:assert/strict';
import {grantCardPresentation} from '../src/holder-grants-presentation.js';

const record = {service:'devgraph:fixture',grant:{service:'devgraph:fixture',issuer:'fixture-provider',
  validity:{mode:'until_revoked',not_before:10},permissions:[{operation:'devgraph.work.list'},{operation:'devgraph.arena.list'}]}};
test('cards identify the canonical service and saved permissions without claiming server validity',()=>{
  const card=grantCardPresentation(record,100);
  assert.equal(card.title,'devgraph');assert.equal(card.service,'devgraph:fixture');
  assert.equal(card.status,'Saved in Wallet');assert.equal(card.permissionCount,'2 permissions');
  assert.equal(card.validity,'Until revoked');assert.equal(card.issuer,'fixture-provider');
  assert.doesNotMatch(JSON.stringify(card),/verified|active|authorized/i);
});
test('dated and future grants show local time bounds, while unknown services keep their exact name',()=>{
  const dated={...record,service:'maps:one',grant:{...record.grant,validity:{mode:'dated',not_before:10,not_after:100}}};
  assert.equal(grantCardPresentation(dated,100).status,'Expired');
  assert.equal(grantCardPresentation(dated,99).status,'Saved in Wallet');
  assert.equal(grantCardPresentation(dated,5).status,'Not yet valid');
  assert.equal(grantCardPresentation(dated,5).title,'maps');
});
test('presentation preserves unknown operations and untrusted labels as text, never as authority',()=>{
  const c=grantCardPresentation({...record,service:'<img src=x onerror=alert(1)>',grant:{...record.grant,permissions:[{operation:'custom.publish',extra:{keep:true}}]}},100);
  assert.equal(c.title,'<img src=x onerror=alert(1)>');assert.equal(c.permissionCount,'1 permission');
  assert.equal(grantCardPresentation({...record,grant:{...record.grant,permissions:[]}},100).permissionCount,'0 permissions');
});
