import assert from 'node:assert/strict'
import test from 'node:test'
import { MAX_WALLET_IMPORT_BYTES, readWalletImportFile } from '../src/import-file.ts'

test('oversized backup is rejected before its contents are read', async () => {
  let reads = 0
  await assert.rejects(
    () => readWalletImportFile({
      name: 'Castalia-Recovery-1.castalia-recovery',
      size: MAX_WALLET_IMPORT_BYTES + 1,
      async text() { reads += 1; return 'unreachable' },
    }),
    /invalid_wallet_file/,
  )
  assert.equal(reads, 0)
})

test('bounded backup is read exactly once', async () => {
  let reads = 0
  const result = await readWalletImportFile({
    name: 'Castalia-Recovery-1.castalia-recovery',
    size: MAX_WALLET_IMPORT_BYTES,
    async text() { reads += 1; return 'encrypted' },
  })
  assert.equal(result, 'encrypted')
  assert.equal(reads, 1)
})

test('reserved .castaway files are not consumed as wallet recovery exports', async () => {
  let reads = 0
  await assert.rejects(
    () => readWalletImportFile({
      name: 'future.castaway',
      size: 100,
      async text() { reads += 1; return 'wrong contract' },
    }),
    /invalid_wallet_file/,
  )
  assert.equal(reads, 0)
})

test('legacy .castalia-wallet encrypted recovery files remain importable', async () => {
  const result = await readWalletImportFile({
    name: 'legacy.castalia-wallet',
    size: 100,
    async text() { return 'legacy encrypted custody' },
  })
  assert.equal(result, 'legacy encrypted custody')
})
