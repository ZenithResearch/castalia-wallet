import assert from 'node:assert/strict'
import test from 'node:test'
import { forwardReadAccess } from '../src/read-access-content.js'
import { createCastaliaWalletProvider } from '../src/provider.js'
import { NEUTRAL_CAPABILITIES } from '../src/provider-profiles-runtime.js'

for (const operation of ['approve', 'approve_graph_v2', 'request']) {
 test(operation + ' refuses background consent before opening a port', () => {
  const replies: unknown[] = [], page: any = {}; page.top = page
  forwardReadAccess({ runtime: { connect: () => { throw Error('must not connect') } } }, { operation }, r => replies.push(r), page, false)
  assert.deepEqual(replies, [{ ok: false, error: 'approval_required' }])
 })
}
test('subframes cannot disclose even the read identity', () => {
 const replies: unknown[] = [], page: any = { top: {} }
 forwardReadAccess({ runtime: { connect: () => { throw Error('must not connect') } } }, { operation: 'identity' }, r => replies.push(r), page, true)
 assert.deepEqual(replies, [{ ok: false, error: 'approval_required' }])
})
test('the public facade advertises and dispatches the generic graph contract', async () => {
 const calls: unknown[] = []
 const provider = createCastaliaWalletProvider(async input => { calls.push(input); return input.method.endsWith('getCapabilities') ? NEUTRAL_CAPABILITIES : {} })
 for (const c of ['graph_access_v2', 'access_request_v1', 'credential_presentation_v2']) assert.ok((await provider.getCapabilities()).includes(c))
 await provider.readAccess!({ operation: 'identity' })
 assert.deepEqual(calls.at(-1), { type: 'castalia:wallet:request', id: 'castalia-4', method: 'castalia.wallet.readAccess', payload: { operation: 'identity' } })
 assert.equal('devgraph' in provider, false)
})
