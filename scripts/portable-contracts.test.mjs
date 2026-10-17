import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

test('portable Web contract sources match their pinned provenance', async () => {
  const root = new URL('../contracts/portable-web/', import.meta.url)
  const provenance = JSON.parse(await readFile(new URL('provenance.json', root), 'utf8'))
  assert.equal(provenance.repository, 'https://github.com/ZenithResearch/castalia-web')
  assert.match(provenance.revision, /^[a-f0-9]{40}$/)
  for (const [name, hash] of Object.entries(provenance.files)) {
    assert.equal(createHash('sha256').update(await readFile(new URL(name, root))).digest('hex'), hash, name)
  }
})
