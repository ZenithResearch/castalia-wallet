import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const root = new URL('../src/', import.meta.url)

test('extension confirmation page displays issuance proof details with explicit approve and deny', async () => {
  const [html, script] = await Promise.all([
    readFile(new URL('confirmation.html', root), 'utf8'),
    readFile(new URL('confirmation.ts', root), 'utf8'),
  ])
  for (const id of ['origin', 'fingerprint', 'issued-at', 'expires-at', 'approve', 'deny']) {
    assert.match(html, new RegExp(`id=["']${id}["']`))
  }
  assert.match(script, /GET_MEMBERSHIP_CONFIRMATION/)
  assert.match(script, /RESOLVE_MEMBERSHIP_CONFIRMATION/)
  assert.match(script, /decide\(true\)/)
  assert.match(script, /decide\(false\)/)
  assert.doesNotMatch(html + script, /JSON\.stringify|applicationCommitment|nonce/)
  assert.doesNotMatch(html, /Membership class|Application kind|Jurisdiction/)
  const manifest = JSON.parse(await readFile(new URL('../manifest.json', root), 'utf8'))
  const webResources = manifest.web_accessible_resources.flatMap((entry: any) => entry.resources)
  assert.equal(webResources.includes('src/confirmation.html'), false)
  assert.equal(webResources.includes('src/onboarding.html'), false)
  assert.equal(manifest.permissions.includes('windows'), true)
})
