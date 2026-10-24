import assert from 'node:assert/strict'
import test from 'node:test'
import {
  installProviderProfilesRuntime,
  NEUTRAL_CAPABILITIES,
} from '../src/provider-profiles-runtime.js'
function event() {
  const listeners = new Set<(...a: any[]) => any>()
  return {
    addListener: (f: any) => listeners.add(f),
    removeListener: (f: any) => listeners.delete(f),
    emit: (...a: any[]) => {
      for (const f of [...listeners]) f(...a)
    },
  }
}
const origin = 'https://independent.example',
  holder = 'ab'.repeat(32)
const profile = {
  schema: 'castalia.provider-profile.v1',
  display_name: 'Independent provider',
  origins: [origin],
  membership: {
    protocol: 'castalia.zenith-membership.v3',
    issuer_origin: 'https://issuer.example',
    roots: [
      {
        issuerId: 'independent',
        keyId: 'key-1',
        signatureSuite: 'Ed25519',
        publicKey: '12'.repeat(32),
      },
    ],
  },
  presentations: [
    {
      issuer: 'another-authority',
      key_id: 'key-2',
      public_key: '34'.repeat(32),
      audience: 'service',
      callers: [{ kind: 'browser', id: origin }],
    },
  ],
}
const tick = () => new Promise((r) => setTimeout(r, 2))
async function until(f: () => boolean) {
  for (let i = 0; i < 100 && !f(); i++) await tick()
  assert.ok(f())
}
function setup() {
  const saved: any = {},
    windows: string[] = [],
    changes = event(),
    approvedOrigins = new Set<string>(),
    hosts = new Set<string>()
  let epoch = 1,
    locked = false,
    restricted = false
  const chrome: any = {
    runtime: {
      id: 'wallet-test',
      getURL: (p: string) => 'chrome-extension://wallet-test/' + p,
      onMessage: event(),
      onConnect: event(),
    },
    storage: {
      local: {
        setAccessLevel: async (p: any) => {
          restricted = p.accessLevel === 'TRUSTED_CONTEXTS'
        },
        get: async () => structuredClone(saved),
        set: async (v: any) => Object.assign(saved, structuredClone(v)),
      },
    },
    tabs: { get: async () => ({ url: origin + '/files' }), onUpdated: event(), onRemoved: event() },
    windows: {
      create: async ({ url }: any) => {
        windows.push(url)
        return { id: windows.length }
      },
      remove: async () => {},
      onRemoved: event(),
    },
    permissions: {
      contains: async ({ origins }: any) => origins.every((o: string) => hosts.has(o)),
      onRemoved: event(),
    },
  }
  let queue = Promise.resolve<any>(undefined)
  const deps: any = {
    run: (f: any) => {
      const next = queue.then(f)
      queue = next.catch(() => {})
      return next
    },
    state: async () => (locked ? null : { memberKey: holder, approvedOrigins }),
    epoch: () => epoch,
    onChange: (f: any) => {
      changes.addListener(f)
      return () => changes.removeListener(f)
    },
    invalidate: () => {
      epoch++
      changes.emit()
    },
    approveOrigin: async (o: string) => {
      approvedOrigins.add(o)
    },
    sign: () => {
      throw Error('unexpected signature')
    },
    legacyCredential: async () => null,
  }
  const runtime = installProviderProfilesRuntime(chrome, deps)
  const message = (data: any, url = chrome.runtime.getURL('src/provider-settings.html')) =>
    new Promise<any>((resolve) =>
      chrome.runtime.onMessage.emit(data, { id: chrome.runtime.id, url }, resolve),
    )
  function call(operation: string, payload: any = {}) {
    const replies: any[] = []
    let disconnected = false
    const port: any = {
      name: 'castalia-provider-profiles-v1',
      sender: {
        id: chrome.runtime.id,
        frameId: 0,
        documentId: 'document-1',
        documentLifecycle: 'active',
        url: origin + '/files',
        tab: { id: 1, url: origin + '/files' },
      },
      onMessage: event(),
      onDisconnect: event(),
      postMessage: (v: any) => replies.push(v),
      disconnect: () => {
        if (!disconnected) {
          disconnected = true
          port.onDisconnect.emit()
        }
      },
    }
    chrome.runtime.onConnect.emit(port)
    port.onMessage.emit({ operation, payload })
    return { replies, port }
  }
  async function decide(
    index: number,
    purposes: any = { membership: true, presentations: true },
    approved = true,
  ) {
    await until(() => windows.length > index)
    const url = windows[index],
      requestId = new URL(url).searchParams.get('request')
    assert.equal((await message({ type: 'GET_PROVIDER_APPROVAL', requestId }, url)).ok, true)
    return message({ type: 'RESOLVE_PROVIDER_APPROVAL', requestId, approved, purposes }, url)
  }
  return {
    runtime,
    chrome,
    message,
    call,
    decide,
    windows,
    hosts,
    approvedOrigins,
    deps,
    saved,
    restricted: () => restricted,
    lock: () => {
      locked = true
      deps.invalidate()
    },
  }
}
test('zero profiles support connection without enrollment or signing', async () => {
  const f = setup()
  assert.ok(NEUTRAL_CAPABILITIES.includes('connection_v1'))
  const c = f.call('connect')
  await f.decide(0)
  await until(() => c.replies.length > 0)
  assert.deepEqual(c.replies[0], { ok: true, result: { state: 'connected' } })
  assert.equal(f.approvedOrigins.has(origin), true)
  assert.equal(f.restricted(), true)
  assert.deepEqual((await f.runtime.store.snapshot()).profiles, [])
})
test('setup status reveals exact active trust only to a connected origin, without another ceremony', async () => {
  const f = setup(), readProfile = { ...profile, membership: null }
  await f.runtime.store.approve(readProfile)
  assert.deepEqual(await f.runtime.setupStatus(readProfile, origin), {
    schema: 'castalia.read-setup-status.v1', connection_approved: false, profile_approved: false,
  })
  f.approvedOrigins.add(origin)
  assert.deepEqual(await f.runtime.setupStatus(readProfile, origin), {
    schema: 'castalia.read-setup-status.v1', connection_approved: true, profile_approved: true,
  })
  const changed = structuredClone(readProfile)
  changed.presentations[0].public_key = '56'.repeat(32)
  assert.equal((await f.runtime.setupStatus(changed, origin)).profile_approved, false)
  const stored = (await f.runtime.store.snapshot()).profiles[0]
  await f.runtime.store.remove(stored.id, stored.revision)
  assert.equal((await f.runtime.setupStatus(readProfile, origin)).profile_approved, false)
  assert.equal(f.windows.length, 0)
  await assert.rejects(f.runtime.setupStatus(readProfile, 'https://other.example'))
  f.lock()
  assert.deepEqual(await f.runtime.setupStatus(readProfile, origin), {
    schema: 'castalia.read-setup-status.v1', connection_approved: false, profile_approved: false,
  })
})
test('app cannot trust itself; purpose choices are independent and approval persists', async () => {
  const f = setup()
  const c = f.call('propose', profile)
  await until(() => f.windows.length > 0)
  assert.equal((await f.runtime.store.snapshot()).profiles.length, 0)
  await f.decide(0, { membership: false, presentations: true })
  await until(() => c.replies.length > 0)
  assert.equal(c.replies[0].ok, true)
  const profiles = (await f.runtime.store.snapshot()).profiles
  assert.equal(profiles.length, 1)
  assert.equal(profiles[0].profile.membership, null)
  assert.equal((await f.runtime.pins()).length, 1)
  assert.equal(f.approvedOrigins.has(origin), false)
})
test('membership profile needs its exact host permission before approval', async () => {
  const f = setup()
  const c = f.call('propose', profile)
  await f.decide(0)
  await until(() => c.replies.length > 0)
  assert.match(c.replies[0].error, /host_permission/)
  assert.equal((await f.runtime.store.snapshot()).profiles.length, 0)
})
test('manual trust import accepts multiple providers and never silently selects legacy', async () => {
  const f = setup()
  f.hosts.add('https://issuer.example/*')
  const a = await f.message({
    type: 'PROFILE_SETTINGS_SAVE',
    profile,
    purposes: { membership: true, presentations: false },
  })
  assert.equal(a.ok, true)
  const b = await f.message({
    type: 'PROFILE_SETTINGS_SAVE',
    profile: {
      ...profile,
      display_name: 'Second',
      membership: {
        ...profile.membership,
        roots: [{ ...profile.membership.roots[0], issuerId: 'second', publicKey: '56'.repeat(32) }],
      },
    },
    purposes: { membership: true, presentations: false },
  })
  assert.equal(b.ok, true)
  assert.equal((await f.runtime.store.list(origin)).length, 2)
  await assert.rejects(() => f.runtime.store.legacy(origin))
  assert.equal(
    (
      await f.message({
        type: 'PROFILE_SETTINGS_BIND_LEGACY',
        origin,
        profileId: a.profile.id,
        expectedRevision: a.profile.revision,
      })
    ).ok,
    true,
  )
  assert.equal((await f.runtime.store.legacy(origin)).id, a.profile.id)
})
for (const reason of ['navigation', 'lock', 'trust-edit', 'permission-loss'])
  test('pending approval invalidated by ' + reason, async () => {
    const f = setup()
    const c = f.call('propose', profile)
    await until(() => f.windows.length > 0)
    if (reason === 'navigation') f.chrome.tabs.onUpdated.emit(1, { status: 'loading' })
    if (reason === 'lock') f.lock()
    if (reason === 'trust-edit')
      await f.message({
        type: 'PROFILE_SETTINGS_SAVE',
        profile,
        purposes: { membership: false, presentations: true },
      })
    if (reason === 'permission-loss')
      f.chrome.permissions.onRemoved.emit({ origins: ['https://issuer.example/*'] })
    await tick()
    const url = f.windows[0]
    assert.equal(
      (
        await f.message(
          { type: 'GET_PROVIDER_APPROVAL', requestId: new URL(url).searchParams.get('request') },
          url,
        )
      ).ok,
      false,
    )
    assert.equal(
      (await f.runtime.store.snapshot()).profiles.filter((p) => p.profile.membership).length,
      0,
    )
    c.port.disconnect()
  })
test('settings rejects untrusted sender and app proposal cannot widen origins', async () => {
  const f = setup()
  assert.equal(
    (
      await f.message(
        {
          type: 'PROFILE_SETTINGS_SAVE',
          profile,
          purposes: { membership: false, presentations: true },
        },
        origin,
      )
    ).ok,
    false,
  )
  const c = f.call('propose', { ...profile, origins: [origin, 'https://other.example'] })
  await until(() => c.replies.length > 0)
  assert.equal(c.replies[0].error, 'proposal_caller_scope')
  assert.equal(f.windows.length, 0)
})
