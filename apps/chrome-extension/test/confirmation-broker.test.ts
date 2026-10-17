import assert from 'node:assert/strict'
import test from 'node:test'
import { createMembershipConfirmationBroker } from '../src/confirmation-broker.ts'

const summary = {
  origin: 'https://app.example',
  memberKeyFingerprint: '0123456789ab…cdef01234567',
  issuedAt: 1_700_000_000_000,
  expiresAt: 1_700_000_300_000,
}

function harness() {
  let removed: ((windowId: number) => void) | undefined
  let timeout: (() => void) | undefined
  const opened: string[] = []
  const closed: number[] = []
  const broker = createMembershipConfirmationBroker({
    confirmationUrl: requestId => `chrome-extension://id/src/confirmation.html?request=${requestId}`,
    createWindow: async url => { opened.push(url); return 41 },
    closeWindow: async id => { closed.push(id) },
    addWindowRemovedListener: listener => { removed = listener },
    removeWindowRemovedListener: () => { removed = undefined },
    setTimeout: callback => { timeout = callback; return 9 },
    clearTimeout: () => { timeout = undefined },
    randomId: () => 'request-1',
  })
  return { broker, opened, closed, remove: () => removed?.(41), expire: () => timeout?.() }
}

test('confirmation broker exposes only display summary and consumes approval once', async () => {
  const h = harness()
  const decision = h.broker.confirm(summary)
  await Promise.resolve()
  assert.deepEqual(h.opened, ['chrome-extension://id/src/confirmation.html?request=request-1'])
  assert.deepEqual(h.broker.claimPendingSummary('request-1'), summary)
  assert.equal(h.broker.claimPendingSummary('request-1'), null, 'reload cannot reclaim confirmation')
  assert.equal(h.broker.resolve('wrong-id', true), false)
  assert.equal(h.broker.resolve('request-1', true), true)
  assert.equal(await decision, true)
  assert.equal(h.broker.claimPendingSummary('request-1'), null)
  assert.equal(h.broker.resolve('request-1', true), false)
  assert.deepEqual(h.closed, [41])
})

test('window close and timeout deny without reusable approval', async () => {
  const closed = harness()
  const closedDecision = closed.broker.confirm(summary)
  await Promise.resolve()
  closed.remove()
  assert.equal(await closedDecision, false)
  assert.equal(closed.broker.resolve('request-1', true), false)

  const expired = harness()
  const expiredDecision = expired.broker.confirm(summary)
  await Promise.resolve()
  expired.expire()
  assert.equal(await expiredDecision, false)
  assert.equal(expired.broker.claimPendingSummary('request-1'), null)
})

test('second pending confirmation is denied instead of replacing the first', async () => {
  const h = harness()
  const first = h.broker.confirm(summary)
  await Promise.resolve()
  await assert.rejects(() => h.broker.confirm(summary), /already pending/i)
  h.broker.resolve('request-1', false)
  assert.equal(await first, false)
})
