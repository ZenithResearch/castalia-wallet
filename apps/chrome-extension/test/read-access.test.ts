import { test } from "node:test";
import assert from "node:assert/strict";
import { createReadAccessController } from "../src/read-access.js";

function fixture() {
  let epoch = 1,
    approved = true,
    live = true,
    signed = 0,
    disposed = 0;
  const context = {
    origin: "https://app.example",
    documentId: "document-1",
    tabId: 1,
    current: () => live,
  };
  const state = {
    memberKey: "a".repeat(64),
    approvedOrigins: new Set([context.origin]),
  };
  const deps = {
    run: async <T>(f: () => Promise<T>) => f(),
    state: async () => state,
    epoch: () => epoch,
    installation: async () => "b".repeat(32),
    memberships: async () => [
      { profileId: "membership", displayName: "Member" },
    ],
    membership: async () => ({ schema: "verified-test-proof" }),
    randomId: () => crypto.randomUUID(),
    now: () => 100,
    prepare: async () => ({
      summary: () => ({
        issuer: "issuer",
        expires_at: 700,
        approval_expires_at: 220,
        permissions: [],
      }),
      approve: () => {
        signed++;
        return { challenge: {}, signature: "test-signature" };
      },
      accept: () => ({ expires_at: 700, receiver: "https://server.example" }),
      present: () => ({ credential: {}, call: {}, proof: {} }),
      dispose: () => {
        disposed++;
      },
    }),
    confirm: async () => approved,
  };
  const controller = createReadAccessController(deps);
  return {
    deps,
    controller,
    context,
    setEpoch: () => epoch++,
    deny: () => {
      approved = false;
    },
    navigate: () => {
      live = false;
    },
    counts: () => ({ signed, disposed }),
  };
}
test("read access needs one human approval and cryptographic acceptance before use", async () => {
  const h = fixture(),
    approved: any = await h.controller.handle(
      { operation: "approve", challenge: {}, profileId: "membership" },
      h.context,
    );
  await assert.rejects(
    h.controller.handle(
      { operation: "present", accessId: approved.accessId, call: {} },
      h.context,
    ),
    /read_access_required/,
  );
  await h.controller.handle(
    { operation: "accept", accessId: approved.accessId, credential: {} },
    h.context,
  );
  assert.ok(
    await h.controller.handle(
      { operation: "present", accessId: approved.accessId, call: {} },
      h.context,
    ),
  );
  assert.equal(h.counts().signed, 1);
  await assert.rejects(
    h.controller.handle(
      { operation: "present", accessId: approved.accessId, call: {} },
      { ...h.context, documentId: "other" },
    ),
    /read_access_required/,
  );
});
test('setup discovery verifies document and epoch without signing or opening consent', async () => {
 const h=fixture();let queried=0;
 Object.assign(h.deps,{setupStatus:async(_profile:unknown,origin:string)=>{queried++;assert.equal(origin,h.context.origin);return{schema:'castalia.read-setup-status.v1',connection_approved:true,profile_approved:true};}});
 const result=await h.controller.handle({operation:'setup_status',profile:{}},h.context);
 assert.equal(result.profile_approved,true);assert.equal(queried,1);assert.equal(h.counts().signed,0);
 Object.assign(h.deps,{setupStatus:async()=>{h.setEpoch();return result;}});
 await assert.rejects(h.controller.handle({operation:'setup_status',profile:{}},h.context),/read_context_changed/);
});
for (const action of ["deny", "navigate", "setEpoch"] as const)
  test(action + " cannot produce a read approval", async () => {
    const h = fixture();
    h.deps.confirm = async () => {
      h[action]();
      return action !== "deny";
    };
    await assert.rejects(
      h.controller.handle({ operation: "approve", challenge: {} }, h.context),
    );
    assert.equal(h.counts().signed, 0);
    assert.equal(h.counts().disposed, 1);
  });
test("unapproved origin is denied before identity disclosure", async () => {
  const h = fixture();
  await assert.rejects(
    h.controller.handle(
      { operation: "identity" },
      { ...h.context, origin: "https://other.example" },
    ),
    /origin_not_approved/,
  );
});
test("lock invalidates and disposes all read connections", async () => {
  const h = fixture(),
    a: any = await h.controller.handle(
      { operation: "approve", challenge: {} },
      h.context,
    );
  h.controller.invalidate();
  await assert.rejects(
    h.controller.handle(
      { operation: "accept", accessId: a.accessId, credential: {} },
      h.context,
    ),
    /read_access_required/,
  );
  assert.equal(h.counts().disposed, 1);
});

test("opt-in graph v2 read keeps legacy membership enforcement and isolates connection handles",async()=>{
 const h=fixture();let checks=0;
 h.deps.memberships=async()=>[];
 h.deps.membership=async()=>{checks++;throw Error('membership_required');};
 await assert.rejects(h.controller.handle({operation:'approve',challenge:{}},h.context),/membership_required/);
 const start=checks;
 const approved:any=await h.controller.handle({operation:'approve_graph_v2',challenge:{}},h.context);
 assert.deepEqual(approved.enrollment.proof,{});assert.equal(checks,start);
 await assert.rejects(h.controller.handle({operation:'accept',accessId:approved.accessId,credential:{}},h.context),/read_protocol_mismatch/);
 await h.controller.handle({operation:'accept_graph_v2',accessId:approved.accessId,credential:{}},h.context);
 await h.controller.handle({operation:'present_graph_v2',accessId:approved.accessId,call:{}},h.context);
 assert.equal(checks,start);
 await assert.rejects(h.controller.handle({operation:'present',accessId:approved.accessId,call:{}},h.context),/read_protocol_mismatch/);
 h.setEpoch();await assert.rejects(h.controller.handle({operation:'present_graph_v2',accessId:approved.accessId,call:{}},h.context),/read_context_changed|read_access_required/);
});
test("graph v2 still validates a supplied membership and needs actual consent",async()=>{
 const h=fixture();h.deps.membership=async()=>{throw Error('membership_invalid');};
 await assert.rejects(h.controller.handle({operation:'approve_graph_v2',challenge:{},profileId:'invalid'},h.context),/membership_invalid/);
 h.deny();await assert.rejects(h.controller.handle({operation:'approve_graph_v2',challenge:{}},h.context),/approval_denied/);assert.equal(h.counts().signed,0);
});

for (const [operation, profileId, included] of [
 ['approve', undefined, true],
 ['approve_graph_v2', undefined, false],
 ['approve_graph_v2', 'membership', true],
] as const) test(operation + ' discloses membership inclusion: ' + String(included), async () => {
 const h = fixture()
 h.deps.confirm = async (summary: any) => { assert.equal(summary.membershipIncluded, included); return false }
 await assert.rejects(h.controller.handle({ operation, challenge: {}, ...(profileId ? { profileId } : {}) }, h.context), /approval_denied/)
 assert.equal(h.counts().signed, 0)
})
