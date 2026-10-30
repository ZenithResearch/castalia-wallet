import assert from 'node:assert/strict';import test from 'node:test';
import{permissionPresentation,accessRecoveryPresentation}from'../src/session-login-presentation.js';
test('read labels do not hide resource restrictions, selectors or unknown guards',()=>{const permission={operation:'devgraph.work.get',resource:'service-resource',constraints:{archived:false},roles:[{selector:{selection:{mode:'objects',refs:[{id:'exact-id'}]},ancestry_guard:'must-remain'}}],future_guard:{x:1}};const view=permissionPresentation(permission);assert.equal(view.label,'Read · devgraph · work');const shown=JSON.parse(view.restrictions);const{operation,...restrictions}=permission;assert.deepEqual(shown,restrictions);assert.ok(view.restrictions.includes('must-remain'));});
test('an unknown operation is displayed verbatim rather than relabelled as read',()=>{assert.equal(permissionPresentation({operation:'other.write'}).label,'Operation: other.write');});

test('missing local grant offers existing approved access before a new request',()=>{
 const view=accessRecoveryPresentation({stage:'access_required',descriptor:{},grantDescriptor:{}});
 assert.equal(view.heading,'Check existing access');assert.equal(view.primary,'check_approved');
 assert.match(view.detail,/already have approved access/);assert.doesNotMatch(view.detail,/operator must approve/);
});
test('unsupported and unusable saved parents are never presented as missing',()=>{
 for(const code of ['holder_session_parent_unsupported','invalid_holder_session','session_login_failed','read_approval_expired']){
  const view=accessRecoveryPresentation({stage:'access_required',error:{code,message:'private diagnostic must not appear'},descriptor:{},grantDescriptor:{}});
  assert.doesNotMatch(view.status+' '+view.detail,/No saved grant|has no saved grant|private diagnostic/);
  assert.match(view.detail,/unchanged/);assert.equal(view.primary,'check_approved');
 }
});
test('pending or unknown new request never conceals the separate existing-access check',()=>{
 for(const status of ['pending','unknown','denied']){
  const view=accessRecoveryPresentation({stage:'access_pending',result:{status},descriptor:{},grantDescriptor:{}});
  assert.match(view.detail,new RegExp(status));assert.match(view.detail,/this request/);assert.match(view.detail,/Existing approved access/);
  assert.equal(view.primary,'check_approved');
 }
});
test('request review and failed status check do not claim confirmed pending or approved access',()=>{
 const reviewing=accessRecoveryPresentation({stage:'access_review',descriptor:{},summary:{}});
 assert.equal(reviewing.primary,'confirm_request');assert.match(reviewing.detail,/creates no grant or session/);
 const failure=accessRecoveryPresentation({stage:'access_pending',error:{code:'session_login_failed'},descriptor:{}});
 assert.match(failure.detail,/could not be confirmed/);assert.doesNotMatch(failure.status,/awaiting the operator/);assert.equal(failure.primary,'request');
});
test('recovery copy preserves membership and issuer failures instead of calling them missing grants',()=>{
 for(const [code,pattern] of [['membership_required',/requires a membership proof/],['issuer_setup_required',/trusted provider settings/],['read_approval_expired',/expired/]] as const){
  const view=accessRecoveryPresentation({stage:'access_required',error:{code},grantDescriptor:{}});
  assert.match(view.status,pattern);assert.match(view.detail,/unchanged/);
 }
});
