import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createFixtureMatrixReadClient,createMatrixCompanion,createMemoryProtectedStore,createFixtureMatrixTransport} from '../src/index.js';
const deps=()=>{let n=0;return {now:()=>1800000000000,randomId:()=>`fixture-${++n}`}};
test('application read client withholds approval, send and private transport state',async()=>{
 const client=await createFixtureMatrixReadClient(deps());
 assert.deepEqual(Object.keys(client).sort(),['getCapabilities','getStatus','listRooms']);
 const status=await client.getStatus();
 const rooms=await client.listRooms({schema:'castalia.matrix-list-rooms-request.v1',connection_handle:status.connections[0]!.connection_handle,limit:100,cursor:null});
 assert.equal(rooms.rooms.length,2);
 assert.doesNotMatch(JSON.stringify({status,rooms}),/access_token|sealed_state|fixture-access-token-private/);
});
test('connection approval is explicit and consumed only once',async()=>{
 const host=await createMatrixCompanion({...deps(),store:createMemoryProtectedStore(),transport:createFixtureMatrixTransport()});
 const request=await host.client.prepareConnection({schema:'castalia.matrix-connection-request.v1',homeserver:'https://matrix.example',user_id:'@anima:example'});
 assert.equal((await host.client.getStatus()).state,'disconnected');
 const approval={schema:'castalia.matrix-trusted-approval.v1',approval_id:request.approval_id};
 await host.approvals.approve(approval);
 await assert.rejects(host.approvals.approve(approval),/approval_unavailable/);
 assert.equal((await host.client.getStatus()).state,'connected');
});
