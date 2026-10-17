import assert from 'node:assert/strict'
import test from 'node:test'
import { createCustodyStateManager, type CustodyEngine, type LocalStorageArea } from '../src/state/custody-state.ts'

function harness(options: { failSet?: boolean } = {}) {
  const local = new Map<string, unknown>()
  let setCalls = 0
  const storage: LocalStorageArea = {
    async get(key) { return { [key]: local.get(key) } },
    async set(values) {
      setCalls += 1
      if (options.failSet) throw new Error('storage_failed')
      for (const [key, value] of Object.entries(values)) local.set(key, value)
    },
    async remove(key) { local.delete(key) },
  }
  let active: string | null = null
  let creates = 0
  const core: CustodyEngine = {
    create(passphrase, createdAt) {
      assert.equal(passphrase, 'correct horse')
      creates += 1
      active = creates.toString(16).padStart(2, '0').repeat(32)
      return JSON.stringify({ schema: 'castalia.wallet-custody.v1', publicKey: active, createdAt, ciphertext: 'opaque' })
    },
    unlock(record, passphrase) {
      assert.equal(passphrase, 'correct horse')
      assert.match(record, /ciphertext/)
      const parsed = JSON.parse(record) as { publicKey?: string }
      active = parsed.publicKey ?? 'a1'.repeat(32)
      return active
    },
    exportRandomized(passphrase) {
      assert.equal(passphrase, 'correct horse')
      if (!active) throw new Error('locked')
      return JSON.stringify({ schema: 'castalia.wallet-custody.v1', publicKey: active, ciphertext: 'fresh' })
    },
    lock() { active = null },
    publicKey() { if (!active) throw new Error('locked'); return active },
  }
  return {
    local,
    core,
    manager: createCustodyStateManager(storage, core),
    active: () => active,
    setCalls: () => setCalls,
  }
}

test('persists only encrypted custody locally and reload retains identity locked', async () => {
  const { local, core, manager } = harness()
  const created = await manager.create('correct horse', 1_700_000_000_123)
  assert.equal(created.unlocked, true)
  assert.equal(created.publicKey, '01'.repeat(32))
  assert.deepEqual([...local.keys()], ['castalia-encrypted-custody-v1'])
  const serialized = JSON.stringify([...local.values()])
  assert.match(serialized, /ciphertext/)
  assert.doesNotMatch(serialized, /correct horse|private|derived/i)

  await manager.clearSensitiveMemoryForReload()
  assert.equal((await manager.getState()).unlocked, false)
  assert.equal((await manager.getState()).publicKey, '01'.repeat(32))
  assert.throws(() => core.publicKey(), /locked/)
  assert.equal(local.size, 1)
})

test('unlock restores the same identity and lock clears sensitive memory', async () => {
  const { manager, core } = harness()
  const created = await manager.create('correct horse', 1_700_000_000_123)
  await manager.lock()
  assert.throws(() => core.publicKey(), /locked/)
  const unlocked = await manager.unlock('correct horse')
  assert.equal(unlocked.publicKey, created.publicKey)
  await manager.lock()
  assert.equal((await manager.getState()).unlocked, false)
})

test('concurrent creates serialize with one winner and no identity split', async () => {
  const { manager, active, setCalls } = harness()
  const results = await Promise.allSettled([
    manager.create('correct horse', 1_700_000_000_123),
    manager.create('correct horse', 1_700_000_000_124),
  ])
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1)
  assert.equal(results.filter(result => result.status === 'rejected').length, 1)
  const state = await manager.getState()
  assert.equal(state.publicKey, active())
  assert.equal(setCalls(), 1)
})

test('concurrent create and replacement import serialize without identity split', async () => {
  const { manager, active, setCalls } = harness()
  const importedRecord = JSON.stringify({
    schema: 'castalia.wallet-custody.v1',
    publicKey: 'b2'.repeat(32),
    ciphertext: 'imported',
  })
  const [created, imported] = await Promise.all([
    manager.create('correct horse', 1_700_000_000_123),
    manager.importEncrypted(importedRecord, 'correct horse', { replaceExisting: true }),
  ])
  assert.equal(created.publicKey, '01'.repeat(32))
  assert.equal(imported.publicKey, 'b2'.repeat(32))
  assert.equal(imported.state.unlocked, false)
  assert.equal((await manager.getState()).publicKey, 'b2'.repeat(32))
  assert.equal(active(), null)
  assert.equal(setCalls(), 2)
})

test('failed create persistence leaves no active signing key', async () => {
  const { manager, active } = harness({ failSet: true })
  await assert.rejects(() => manager.create('correct horse', 1_700_000_000_123), /storage_failed/)
  assert.equal(active(), null)
  assert.deepEqual(await manager.getState(), { setupComplete: false, unlocked: false, publicKey: null })
})

test('import persists then locks and locked export is rejected', async () => {
  const { manager, active } = harness()
  await manager.create('correct horse', 1_700_000_000_123)
  const importedRecord = JSON.stringify({
    schema: 'castalia.wallet-custody.v1',
    publicKey: 'b2'.repeat(32),
    ciphertext: 'imported',
  })
  const imported = await manager.importEncrypted(importedRecord, 'correct horse', { replaceExisting: true })
  assert.equal(imported.publicKey, 'b2'.repeat(32))
  assert.equal(imported.replaced, true)
  assert.equal(imported.state.unlocked, false)
  assert.equal(active(), null)
  await assert.rejects(() => manager.exportEncrypted('correct horse'), /invalid_wallet_file/)
  assert.equal((await manager.getState()).publicKey, 'b2'.repeat(32))
})

test('failed import persistence leaves old record authoritative and no active key', async () => {
  const base = harness()
  await base.manager.create('correct horse', 1_700_000_000_123)
  const existing = base.local.get('castalia-encrypted-custody-v1')
  const failingStorage: LocalStorageArea = {
    async get(key) { return { [key]: existing } },
    async set() { throw new Error('storage_failed') },
    async remove() {},
  }
  const manager = createCustodyStateManager(failingStorage, base.core)
  const importedRecord = JSON.stringify({ schema: 'castalia.wallet-custody.v1', publicKey: 'c3'.repeat(32), ciphertext: 'imported' })
  await assert.rejects(
    () => manager.importEncrypted(importedRecord, 'correct horse', { replaceExisting: true }),
    /invalid_wallet_file/,
  )
  assert.equal(base.active(), null)
  assert.equal((await manager.getState()).publicKey, '01'.repeat(32))
})
