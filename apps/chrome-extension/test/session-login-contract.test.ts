import assert from 'node:assert/strict';
import test from 'node:test';
import { parseSessionLoginRequest } from '../../../packages/provider-types/src/session-login.js';
const open = {operation:'open_session_login',service:'service:example',session_public_key:'a'.repeat(64),session_installation_id:'b'.repeat(32),requested_ttl_seconds:900};
test('login protocol accepts only bounded public child-key requests',()=>{
 assert.deepEqual(parseSessionLoginRequest(open),open);
 for(const change of [{private_key:'never accepted'},{requested_ttl_seconds:3601},{session_public_key:'invalid'},{session_installation_id:'c'.repeat(64)},{permissions:{}},{origin:'https://forged.example'}])
  assert.throws(()=>parseSessionLoginRequest({...open,...change}),/invalid_session_login_request/);
});
test('access-request descriptor only accepts literal paths under verified binding',()=>{
 const access_request={schema:'castalia.session-login-access.v1',request_schema:'devgraph.access-request-action.v1',result_schemas:['devgraph.access-request-result.v1'],challenge_path:'/devgraph/access-requests/v2/challenges',action_path:'/devgraph/access-requests/v2/actions'};
 assert.deepEqual((parseSessionLoginRequest({...open,access_request}) as any).access_request,access_request);
 for(const p of ['https://other.example/a','//other.example/a','/a/../b','/a/%2e%2e/b','/a?redirect=x','/a#b','/a\\b'])
  assert.throws(()=>parseSessionLoginRequest({...open,access_request:{...access_request,action_path:p}}),/invalid_session_login_request/);
});
test('completion accepts exact same-ceremony proof but no root or alternate route',()=>{
 const complete={operation:'complete_session_login',loginId:'d'.repeat(32),challenge:{schema:'secs.holder-session-challenge.v1'},session_signature:'e'.repeat(128)};
 assert.deepEqual(parseSessionLoginRequest(complete),complete);
 for(const change of [{parent_grant:{}},{origin:'https://forged.example'},{loginId:'arbitrary'},{session_signature:'e'.repeat(127)},{challenge:[]}])
  assert.throws(()=>parseSessionLoginRequest({...complete,...change}),/invalid_session_login_request/);
});
test('grant acquisition only names the existing typed grant profile and exact wrapper',()=>{
 const grant_acquisition={schema:'castalia.session-login-grant.v1',challenge_path:'/monitor/wallet-access/v1/challenges',grant_path:'/monitor/wallet-access/v1/grants/v2',grant_schema:'secs.holder-grant.v2',result_schema:'devgraph.holder-grant-result.v1'};
 assert.deepEqual((parseSessionLoginRequest({...open,grant_acquisition}) as any).grant_acquisition,grant_acquisition);
 for(const change of [{grant_schema:'secs.holder-grant.v1'},{result_schema:'arbitrary'},{grant_path:'https://other.example/'},{grant_path:'/a/%2f/b'},{private_key:'no'}])
  assert.throws(()=>parseSessionLoginRequest({...open,grant_acquisition:{...grant_acquisition,...change}}),/invalid_session_login_request/);
});
test('service adapter labels stay declarative while signed grant profile stays fixed',()=>{const access_request={schema:'castalia.session-login-access.v1',request_schema:'example.access-action.v2',result_schemas:['example.access-result.v2'],challenge_path:'/access/challenges',action_path:'/access/actions'};const grant_acquisition={schema:'castalia.session-login-grant.v1',challenge_path:'/read/challenges',grant_path:'/read/grants',grant_schema:'secs.holder-grant.v2',result_schema:'example.grant-result.v2',membership_requirement:'optional'};assert.deepEqual(parseSessionLoginRequest({...open,access_request,grant_acquisition}),{...open,access_request,grant_acquisition});for(const result_schemas of [[],['invalid'],['example.result.v1','example.result.v1'],Array(5).fill('example.result.v1')])assert.throws(()=>parseSessionLoginRequest({...open,access_request:{...access_request,result_schemas}}));assert.throws(()=>parseSessionLoginRequest({...open,grant_acquisition:{...grant_acquisition,grant_schema:'example.grant.v2'}}));});
