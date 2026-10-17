import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fetchCastaliaMembership } from '@castalia-wallet/dregg-adapter'

const snapshotArgument = process.argv[2]
if (!snapshotArgument) {
  throw new Error('usage: npm run smoke:dregg-membership -- <live-snapshot.json>')
}

const snapshotPath = resolve(snapshotArgument)
const snapshot = JSON.parse(await readFile(snapshotPath, 'utf8'))
const membership = await fetchCastaliaMembership(snapshot)
if (membership.status !== 'active' || membership.generation !== 1) {
  throw new Error(
    `live membership is not at the expected active generation: ${membership.status}/${membership.generation}`,
  )
}

await writeFile(`${snapshotPath}.done`, 'ok\n', { flag: 'wx' })
process.stdout.write(`${JSON.stringify({
  verified: true,
  cellId: membership.cellId,
  status: membership.status,
  generation: membership.generation,
  balance: membership.balance,
  receiptHeadPresent: membership.lastReceiptHash !== null,
})}\n`)
