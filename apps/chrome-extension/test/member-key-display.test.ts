import assert from 'node:assert/strict'
import test from 'node:test'
import {
  copyPublicMemberKey,
  publicMemberKeyForDisplay,
} from '../src/member-key-display.ts'

const MEMBER_KEY = '0123456789abcdef'.repeat(4)

test('returns the exact canonical public Member Key only after setup', () => {
  assert.equal(publicMemberKeyForDisplay({ setupComplete: true, publicKey: MEMBER_KEY }), MEMBER_KEY)
  assert.equal(publicMemberKeyForDisplay({ setupComplete: false, publicKey: MEMBER_KEY }), null)
  assert.equal(publicMemberKeyForDisplay({ setupComplete: true, publicKey: 'ab'.repeat(31) }), null)
  assert.equal(publicMemberKeyForDisplay({ setupComplete: true, publicKey: 'AB'.repeat(32) }), null)
})

test('copies all 32 public bytes without abbreviation or transformation', async () => {
  const copied: string[] = []
  const result = await copyPublicMemberKey(
    MEMBER_KEY,
    async value => { copied.push(value) },
    () => false,
  )

  assert.equal(result, 'copied')
  assert.deepEqual(copied, [MEMBER_KEY])
})

test('clipboard denial uses the exact public-only fallback and does not invoke unrelated work', async () => {
  const calls: string[] = []
  const result = await copyPublicMemberKey(
    MEMBER_KEY,
    async () => {
      calls.push('clipboard')
      throw new Error('denied')
    },
    value => {
      calls.push(`fallback:${value}`)
      return false
    },
  )

  assert.equal(result, 'failed')
  assert.deepEqual(calls, ['clipboard', `fallback:${MEMBER_KEY}`])
})

test('invalid or absent public material never reaches clipboard or fallback', async () => {
  let touched = false
  const result = await copyPublicMemberKey(
    'private-seed-shaped-but-invalid',
    async () => { touched = true },
    () => { touched = true; return true },
  )

  assert.equal(result, 'unavailable')
  assert.equal(touched, false)
})
