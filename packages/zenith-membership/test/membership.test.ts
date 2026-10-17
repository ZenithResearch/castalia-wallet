import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import {
  ZENITH_MEMBERSHIP_ENDPOINT_PATH,
  ZENITH_MEMBERSHIP_PROTOCOL,
  deriveZenithMembershipId,
  hexFromBytes,
  issueZenithMembership,
  parseZenithMembershipCredential,
  verifyZenithMembershipCredential,
  zenithMembershipCredentialTranscript,
  zenithMembershipJoinTranscript,
  type ZenithMembershipCredentialV3,
  type ZenithMembershipTrustPolicyV1,
} from '../src/index.ts'

const OWNER = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
const ISSUER_PUBLIC_KEY = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
const ISSUER_KEY_ID = 'zenith-membership-issuer-fixture-ed25519-1'
const REQUEST_SIGNATURE = 'fkNzWF1nzvzuLzhQw4l_HoNh_Bm2TOasWWiRa8V8T6Zu8uUW5xQd72MBGr1djCVr9i5u369Fnh00f9QPTSvQCw'

const CREDENTIAL = {
  schema: 'castalia.zenith-membership-credential.v3',
  version: 3,
  membershipId: 'b2409aad97015e17749442377f14acd6ccd9ce804661738e4aa7e860d554d8a9',
  ownerPublicKey: OWNER,
  status: 'active',
  issuerId: 'zenith-research',
  issuerKeyId: ISSUER_KEY_ID,
  signatureSuite: 'Ed25519',
  issuerSignature: 'b4Sf_uSYTxfhQUaF_Arq44IxYNByxKsrUOgmXCB4dEYbfAlJ6to50ZeY_qBbvZYibHO6A4JrIERZ1DBDxSkRBA',
} as const satisfies ZenithMembershipCredentialV3

const POLICY = {
  schema: 'castalia.zenith-membership-trust-policy.v1',
  version: 1,
  roots: [{
    issuerId: 'zenith-research',
    keyId: ISSUER_KEY_ID,
    signatureSuite: 'Ed25519',
    publicKey: ISSUER_PUBLIC_KEY,
  }],
} as const satisfies ZenithMembershipTrustPolicyV1

function credentialPayload(value: ZenithMembershipCredentialV3) {
  return {
    schema: value.schema,
    version: value.version,
    membershipId: value.membershipId,
    ownerPublicKey: value.ownerPublicKey,
    status: value.status,
    issuerId: value.issuerId,
    issuerKeyId: value.issuerKeyId,
    signatureSuite: value.signatureSuite,
  }
}

test('pins and independently verifies the canonical Zenith membership v3 vector', async () => {
  const vectorUrl = new URL('../../../docs/vectors/castalia-zenith-membership-v3.vector.json', import.meta.url)
  const checksumUrl = new URL('../../../docs/vectors/castalia-zenith-membership-v3.vector.sha256', import.meta.url)
  const bytes = await readFile(vectorUrl)
  const checksum = (await readFile(checksumUrl, 'utf8')).trim().split(/\s+/)[0]
  assert.equal(createHash('sha256').update(bytes).digest('hex'), checksum)
  const vector = JSON.parse(bytes.toString('utf8')) as {
    protocol: string
    ownerPublicKey: string
    issuerPublicKey: string
    issuerKeyId: string
    membershipId: string
    credential: ZenithMembershipCredentialV3
    transcripts: { joinHex: string; credentialHex: string }
  }
  assert.equal(vector.protocol, ZENITH_MEMBERSHIP_PROTOCOL)
  assert.equal(await deriveZenithMembershipId(vector.ownerPublicKey), vector.membershipId)
  assert.equal(hexFromBytes(zenithMembershipJoinTranscript(vector.ownerPublicKey)), vector.transcripts.joinHex)
  assert.equal(
    hexFromBytes(zenithMembershipCredentialTranscript(credentialPayload(vector.credential))),
    vector.transcripts.credentialHex,
  )
  await assert.doesNotReject(() => verifyZenithMembershipCredential(
    vector.credential,
    {
      schema: 'castalia.zenith-membership-trust-policy.v1',
      version: 1,
      roots: [{
        issuerId: 'zenith-research',
        keyId: vector.issuerKeyId,
        signatureSuite: 'Ed25519',
        publicKey: vector.issuerPublicKey,
      }],
    },
    vector.ownerPublicKey,
  ))
})

test('submits the exact possession proof and accepts only the verified owner credential', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = []
  const issued = await issueZenithMembership({
    issuerUrl: 'https://membership.zenith-research.ca',
    ownerPublicKey: OWNER,
    signature: REQUEST_SIGNATURE,
    trustPolicy: POLICY,
    async fetchImpl(url, init) {
      calls.push({ url: String(url), init: init ?? {} })
      return new Response(JSON.stringify(CREDENTIAL), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    },
  })
  assert.deepEqual(issued, CREDENTIAL)
  assert.equal(calls.length, 1)
  assert.equal(calls[0]?.url, `https://membership.zenith-research.ca${ZENITH_MEMBERSHIP_ENDPOINT_PATH}`)
  assert.equal(calls[0]?.init.method, 'POST')
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), {
    schema: 'castalia.zenith-membership-issuance-request.v3',
    version: 3,
    ownerPublicKey: OWNER,
    signatureSuite: 'Ed25519',
    signature: REQUEST_SIGNATURE,
  })
})

test('fails closed on unknown fields, wrong owners, invalid signatures, and unsafe issuer URLs', async () => {
  assert.throws(() => parseZenithMembershipCredential({ ...CREDENTIAL, role: 'administrator' }), /not canonical v3/)
  assert.throws(
    () => zenithMembershipCredentialTranscript({
      ...credentialPayload(CREDENTIAL),
      invented: true,
    }),
    /payload fields are not canonical v3/,
  )
  await assert.rejects(
    () => verifyZenithMembershipCredential(CREDENTIAL, {
      ...POLICY,
      roots: [{ ...POLICY.roots[0], invented: true }],
    }),
    /trust root fields are not canonical/,
  )
  await assert.rejects(
    () => verifyZenithMembershipCredential(CREDENTIAL, POLICY, '44'.repeat(32)),
    /owner does not match/,
  )
  await assert.rejects(
    () => verifyZenithMembershipCredential({ ...CREDENTIAL, issuerSignature: 'A'.repeat(86) }, POLICY),
    /signature is invalid/,
  )
  for (const issuerUrl of [
    'http://membership.zenith-research.ca',
    'https://user:secret@membership.zenith-research.ca',
    'https://membership.zenith-research.ca/api',
  ]) {
    await assert.rejects(
      () => issueZenithMembership({
        issuerUrl,
        ownerPublicKey: OWNER,
        signature: REQUEST_SIGNATURE,
        trustPolicy: POLICY,
        fetchImpl: async () => new Response(JSON.stringify(CREDENTIAL)),
      }),
      /issuer URL/,
    )
  }
})

test('rejects non-JSON, non-success, and noncanonical issuer responses', async () => {
  const base = {
    issuerUrl: 'https://membership.zenith-research.ca',
    ownerPublicKey: OWNER,
    signature: REQUEST_SIGNATURE,
    trustPolicy: POLICY,
  } as const
  await assert.rejects(
    () => issueZenithMembership({
      ...base,
      fetchImpl: async () => new Response('{"error":"invalid_signature"}\n', {
        status: 401,
        headers: { 'content-type': 'application/json' },
      }),
    }),
    /issuer rejected membership request \(401\)/,
  )
  await assert.rejects(
    () => issueZenithMembership({
      ...base,
      fetchImpl: async () => new Response(JSON.stringify(CREDENTIAL), {
        headers: { 'content-type': 'text/plain' },
      }),
    }),
    /application\/json/,
  )
  await assert.rejects(
    () => issueZenithMembership({
      ...base,
      fetchImpl: async () => new Response(JSON.stringify({ ...CREDENTIAL, invented: true }), {
        headers: { 'content-type': 'application/json' },
      }),
    }),
    /not canonical v3/,
  )
})
