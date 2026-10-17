import assert from 'node:assert/strict'
import test from 'node:test'
import {
  CASTALIA_WALLET_REQUEST,
  CASTALIA_WALLET_RESPONSE,
  createPageMessageTransport,
  type CastaliaWalletRequestEnvelope,
} from '../src/provider.ts'

type MessageListener = (event: MessageEvent<unknown>) => void

function createFakePageWindow() {
  const origin = 'https://app.example'
  const listeners = new Set<MessageListener>()
  const timers = new Map<number, { callback: () => void; dueAt: number }>()
  const scheduledDelays: number[] = []
  let currentTime = 0
  let nextTimerId = 1

  const pageWindow = {
    location: { origin },
    setTimeout(callback: () => void, delayMs: number) {
      const timerId = nextTimerId++
      scheduledDelays.push(delayMs)
      timers.set(timerId, { callback, dueAt: currentTime + delayMs })
      return timerId
    },
    clearTimeout(timerId: number) {
      timers.delete(timerId)
    },
    addEventListener(type: string, listener: MessageListener) {
      assert.equal(type, 'message')
      listeners.add(listener)
    },
    removeEventListener(type: string, listener: MessageListener) {
      assert.equal(type, 'message')
      listeners.delete(listener)
    },
    postMessage() {},
  } as unknown as Window

  function advanceBy(delayMs: number) {
    currentTime += delayMs
    for (const [timerId, timer] of [...timers.entries()]
      .filter(([, candidate]) => candidate.dueAt <= currentTime)
      .sort((left, right) => left[1].dueAt - right[1].dueAt)) {
      timers.delete(timerId)
      timer.callback()
    }
  }

  function respond(id: string, result: unknown) {
    const event = {
      source: pageWindow,
      origin,
      data: {
        type: CASTALIA_WALLET_RESPONSE,
        id,
        ok: true,
        result,
      },
    } as MessageEvent<unknown>
    for (const listener of [...listeners]) listener(event)
  }

  return {
    pageWindow,
    advanceBy,
    respond,
    scheduledDelays,
    listenerCount: () => listeners.size,
    timerCount: () => timers.size,
  }
}

function request(method: CastaliaWalletRequestEnvelope['method'], id: string): CastaliaWalletRequestEnvelope {
  return {
    type: CASTALIA_WALLET_REQUEST,
    id,
    method,
    payload: {},
  }
}

test('Generic credential presentation remains pending beyond 15 seconds and can complete', async () => {
  const fake = createFakePageWindow()
  const transport = createPageMessageTransport(fake.pageWindow)
  const pending = transport(request(
    'castalia.wallet.presentCredential',
    'presentation-after-fifteen-seconds',
  ))
  let settled = false
  void pending.then(
    () => { settled = true },
    () => { settled = true },
  )

  assert.deepEqual(fake.scheduledDelays, [125_000])
  fake.advanceBy(15_001)
  await Promise.resolve()
  assert.equal(settled, false)
  assert.equal(fake.listenerCount(), 1)

  fake.respond('presentation-after-fifteen-seconds', true)
  assert.equal(await pending, true)
  assert.equal(fake.listenerCount(), 0)
  assert.equal(fake.timerCount(), 0)
})

test('Generic credential presentation times out and cleans up at 125 seconds', async () => {
  const fake = createFakePageWindow()
  const transport = createPageMessageTransport(fake.pageWindow)
  const pending = transport(request(
    'castalia.wallet.presentCredential',
    'presentation-timeout',
  ))

  fake.advanceBy(124_999)
  assert.equal(fake.listenerCount(), 1)
  assert.equal(fake.timerCount(), 1)

  fake.advanceBy(1)
  await assert.rejects(pending, /Castalia Wallet request timed out/)
  assert.equal(fake.listenerCount(), 0)
  assert.equal(fake.timerCount(), 0)
})

test('noninteractive provider methods retain the 15 second transport timeout', async () => {
  const methods = [
    'castalia.wallet.isAvailable',
    'castalia.wallet.getSubject',
    'castalia.wallet.getMembership',
    'castalia.wallet.signChallenge',
    'castalia.wallet.requestMembershipPresentation',
  ] satisfies CastaliaWalletRequestEnvelope['method'][]

  for (const [index, method] of methods.entries()) {
    const fake = createFakePageWindow()
    const transport = createPageMessageTransport(fake.pageWindow)
    const pending = transport(request(method, `non-presentation-timeout-${index}`))

    assert.deepEqual(fake.scheduledDelays, [15_000], method)
    fake.advanceBy(14_999)
    assert.equal(fake.listenerCount(), 1, method)
    assert.equal(fake.timerCount(), 1, method)

    fake.advanceBy(1)
    await assert.rejects(pending, /Castalia Wallet request timed out/)
    assert.equal(fake.listenerCount(), 0, method)
    assert.equal(fake.timerCount(), 0, method)
  }
})

for(const method of ['castalia.wallet.requestConnection','castalia.wallet.proposeProviderProfile','castalia.wallet.requestMembership','castalia.wallet.openMembershipFlow','castalia.wallet.requestRegistrationV2'] as const)test(method+' retains the complete bounded approval window',async()=>{const f=createFakePageWindow();const pending=createPageMessageTransport(f.pageWindow)(request(method,'approval'));assert.deepEqual(f.scheduledDelays,[125000]);f.advanceBy(125000);await assert.rejects(pending,/timed out/);assert.equal(f.listenerCount(),0)})
