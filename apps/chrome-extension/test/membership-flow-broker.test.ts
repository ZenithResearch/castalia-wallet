import assert from 'node:assert/strict'
import test from 'node:test'
import { createMembershipFlowBroker } from '../src/membership-flow-broker.ts'

function harness() {
  let removed: ((windowId: number) => void) | undefined
  let timeout: (() => void) | undefined
  const opened: string[] = []
  const closed: number[] = []
  const broker = createMembershipFlowBroker({
    flowUrl: requestId => `chrome-extension://id/src/onboarding.html?request=${requestId}`,
    createWindow: async url => { opened.push(url); return 42 },
    closeWindow: async id => { closed.push(id) },
    addWindowRemovedListener: listener => { removed = listener },
    removeWindowRemovedListener: () => { removed = undefined },
    setTimeout: callback => { timeout = callback; return 9 },
    clearTimeout: () => { timeout = undefined },
    randomId: () => 'flow-1',
  })
  return { broker, opened, closed, remove: () => removed?.(42), expire: () => timeout?.() }
}

test('membership flow binds one Chrome-owned window to one tab and origin', async () => {
  const h = harness()
  const context = await h.broker.open({ origin: 'https://app.example', tabId: 7 })
  assert.deepEqual(h.opened, ['chrome-extension://id/src/onboarding.html?request=flow-1'])
  assert.deepEqual(context, { requestId: 'flow-1', origin: 'https://app.example', tabId: 7 })
  assert.deepEqual(h.broker.get('flow-1'), context)
  await assert.rejects(
    () => h.broker.open({ origin: 'https://other.example', tabId: 8 }),
    /already open/i,
  )
  assert.equal(h.broker.complete('wrong-flow'), false)
  assert.equal(h.broker.complete('flow-1'), true)
  assert.equal(h.broker.get('flow-1'), null)
  assert.deepEqual(h.closed, [], 'the trusted page closes itself after displaying success')
})

test('window close and timeout invalidate the membership flow', async () => {
  const closed = harness()
  await closed.broker.open({ origin: 'https://app.example', tabId: 7 })
  closed.remove()
  assert.equal(closed.broker.get('flow-1'), null)

  const expired = harness()
  await expired.broker.open({ origin: 'https://app.example', tabId: 7 })
  expired.expire()
  assert.equal(expired.broker.get('flow-1'), null)
  assert.deepEqual(expired.closed, [42])
})
