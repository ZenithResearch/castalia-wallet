import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createCredentialPresentationHandler } from '../src/credential-presentation.js'

function harness() {
  let epoch = 1, current = true, approved = true, origin = 'https://app.example', signed = 0, disposed = 0
  const used = new Set<string>()
  const state = { memberKey: 'aa'.repeat(32), approvedOrigins: new Set([origin]) }
  const deps = {
    run: async <T>(f: () => Promise<T>) => f(), state: async () => state, epoch: () => epoch, current: () => current,
    currentOrigin: async () => origin,
    prepare: (_raw: Uint8Array, caller: {kind:string;id:string}) => { assert.equal(caller.id, 'https://app.example'); return {
      summary: () => ({ issuer: 'issuer', holder_public_key: state.memberKey, credential_digest_sha256: 'credential', disclosure: {title:'Application request',statements:['Complete signed request']}, expires_at: 150 }),
      approve: () => { signed++; return { schema: 'castalia.credential-presentation.v2' } }, dispose: () => { disposed++ },
    } },
    reserve: async (id: string) => { if (used.has(id)) throw new Error('credential_replay'); used.add(id) },
    confirm: async (_summary: unknown) => approved,
  }
  return { deps, handler: createCredentialPresentationHandler(deps), state, setEpoch: () => epoch++, setCurrent: () => { current = false }, setApproved: (v:boolean) => { approved = v }, setOrigin: () => { origin = 'https://other.example' }, counts: () => ({signed,disposed}) }
}
test('each credential requires explicit approval and is consumed once', async () => {
  const h = harness(); assert.equal((await h.handler({}, 'https://app.example')).state, 'approved')
  await assert.rejects(h.handler({}, 'https://app.example'), /credential_replay/)
  assert.deepEqual(h.counts(), {signed:1,disposed:2})
})
test('denial disposes preparation and produces no signature', async () => {
  const h=harness(); h.setApproved(false); assert.equal((await h.handler({}, 'https://app.example')).state,'denied'); assert.deepEqual(h.counts(),{signed:0,disposed:1})
})
for (const action of ['setEpoch','setCurrent','setOrigin'] as const) test(action+' during consent rejects completion', async () => {
  const h=harness(); h.deps.confirm=async()=>{h[action]();return true}
  await assert.rejects(h.handler({},'https://app.example'), /presentation_context_changed/); assert.deepEqual(h.counts(),{signed:0,disposed:1})
})
test('origin revocation during consent rejects completion',async()=>{
 const h=harness();h.deps.confirm=async()=>{h.state.approvedOrigins.clear();return true}
 await assert.rejects(h.handler({},'https://app.example'),/origin_not_approved/);assert.equal(h.counts().signed,0)
})
test('unapproved origin is rejected before preparation',async()=>{
 const h=harness();h.state.approvedOrigins.clear();await assert.rejects(h.handler({},'https://app.example'),/origin_not_approved/);assert.deepEqual(h.counts(),{signed:0,disposed:0})
})
test('custody queue is released across human approval',async()=>{
 const h=harness();let held=false;h.deps.run=async f=>{assert.equal(held,false);held=true;try{return await f()}finally{held=false}}
 h.deps.confirm=async()=>{assert.equal(held,false);return true};await h.handler({},'https://app.example')
})

function deferred<T>() {
 let resolve!: (value:T)=>void
 const promise = new Promise<T>(complete=>{resolve=complete})
 return {promise,resolve}
}
for (const boundary of ['origin','state','reserve'] as const) test('initial cancellation during '+boundary+' await cannot open confirmation', async()=>{
 const h=harness(),entered=deferred<void>(),release=deferred<void>()
 let confirmed=0
 h.deps.confirm=async()=>{confirmed++;return true}
 const suspend=async()=>{entered.resolve();await release.promise}
 if(boundary==='origin')h.deps.currentOrigin=async()=>{await suspend();return 'https://app.example'}
 if(boundary==='state')h.deps.state=async()=>{await suspend();return h.state}
 if(boundary==='reserve')h.deps.reserve=async()=>{await suspend()}
 const pending=h.handler({},'https://app.example')
 await entered.promise;h.setCurrent();release.resolve()
 await assert.rejects(pending,/presentation_context_changed/)
 assert.equal(confirmed,0);assert.equal(h.counts().signed,0)
 assert.equal(h.counts().disposed,boundary==='reserve'?1:0)
})
for (const boundary of ['state','origin'] as const) test('cancellation during final '+boundary+' await prevents signing',async()=>{
 const h=harness(),entered=deferred<void>(),release=deferred<void>()
 h.deps.confirm=async()=>{
   if(boundary==='state')h.deps.state=async()=>{entered.resolve();await release.promise;return h.state}
   else h.deps.currentOrigin=async()=>{entered.resolve();await release.promise;return 'https://app.example'}
   return true
 }
 const pending=h.handler({},'https://app.example')
 await entered.promise;h.setCurrent();release.resolve()
 await assert.rejects(pending,/presentation_context_changed/)
 assert.deepEqual(h.counts(),{signed:0,disposed:1})
})
test('cancellation as custody preparation completes cannot create an orphan popup',async()=>{
 const h=harness();let confirmed=0
 const run=h.deps.run
 h.deps.run=async f=>{const result=await run(f);h.setCurrent();return result}
 h.deps.confirm=async()=>{confirmed++;return true}
 await assert.rejects(h.handler({},'https://app.example'),/presentation_context_changed/)
 assert.equal(confirmed,0);assert.deepEqual(h.counts(),{signed:0,disposed:1})
})
test('final origin is read after state and epoch changes during that await deny signing',async()=>{
 const h=harness();const reads:string[]=[]
 h.deps.confirm=async()=>{
  h.deps.state=async()=>{reads.push('state');return h.state}
  h.deps.currentOrigin=async()=>{reads.push('origin');h.setEpoch();return 'https://app.example'}
  return true
 }
 await assert.rejects(h.handler({},'https://app.example'),/presentation_context_changed/)
 assert.deepEqual(reads,['state','origin']);assert.deepEqual(h.counts(),{signed:0,disposed:1})
})
