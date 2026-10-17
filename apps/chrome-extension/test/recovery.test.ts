import assert from 'node:assert/strict'
import test from 'node:test'
import { createRecoveryManager, type RecoveryBackend } from '../src/recovery.ts'

function harness() {
  let exported = false
  let imported = false
  const backend: RecoveryBackend = {
    async exportEncrypted(passphrase) {
      if (passphrase !== 'correct') throw new Error('invalid_wallet_file')
      exported = true
      return '{"schema":"castalia.wallet-custody.v1","ciphertext":"fresh"}'
    },
    async importEncrypted(record, passphrase, options) {
      if (passphrase !== 'correct' || !options.replaceExisting || !record.includes('custody')) {
        throw new Error('invalid_wallet_file')
      }
      imported = true
      return { publicKey: 'aa'.repeat(32), replaced: true }
    },
  }
  return { manager: createRecoveryManager(backend), exported: () => exported, imported: () => imported }
}

test('export is extension-owned and returns an explicit Castalia recovery filename', async () => {
  const { manager, exported } = harness()
  const result = await manager.exportWallet('correct')
  assert.match(result.filename, /^Castalia-Recovery-\d+\.castalia-recovery$/)
  assert.match(result.contents, /"fresh"/)
  assert.equal(exported(), true)
})

test('import delegates to the authoritative custody transaction owner', async () => {
  const { manager, imported } = harness()
  const result = await manager.importWallet(
    '{"schema":"castalia.wallet-custody.v1"}',
    'correct',
    { replaceExisting: true },
  )
  assert.deepEqual(result, { publicKey: 'aa'.repeat(32), replaced: true })
  assert.equal(imported(), true)
})
