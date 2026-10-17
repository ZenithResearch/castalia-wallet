import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const vectors = JSON.parse(readFileSync(resolve(root, 'docs/contracts/castalia-origin-v1.vector.json'), 'utf8'))

function canonicalOrigin(input) {
  if (typeof input !== 'string' || input.length === 0 || input === 'null') throw new Error('invalid origin')
  if (/\s|[\u0000-\u001f\u007f]/u.test(input)) throw new Error('invalid origin')
  let url
  try { url = new URL(input) } catch { throw new Error('invalid origin') }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('invalid origin')
  if (url.username || url.password || url.search || url.hash) throw new Error('invalid origin')
  if (url.pathname !== '/' && url.pathname !== '') throw new Error('invalid origin')
  if (!url.hostname || url.hostname.endsWith('.')) throw new Error('invalid origin')
  const host = url.hostname.includes(':') && !url.hostname.startsWith('[') ? `[${url.hostname}]` : url.hostname
  const port = url.port ? `:${url.port}` : ''
  return `${url.protocol.slice(0, -1)}://${host}${port}`
}

test('origin canonicalization positive vectors', () => {
  for (const vector of vectors.positive) assert.equal(canonicalOrigin(vector.input), vector.output, vector.input)
})

test('origin canonicalization rejects aliases and bypass forms', () => {
  for (const input of vectors.reject) assert.throws(() => canonicalOrigin(input), undefined, input)
})
