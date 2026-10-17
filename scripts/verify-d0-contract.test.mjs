import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const profile = JSON.parse(readFileSync(resolve(root, 'docs/contracts/castalia-membership-v1.json'), 'utf8'))
const vector = JSON.parse(readFileSync(resolve(root, 'docs/contracts/castalia-membership-cell-derivation-v1.vector.json'), 'utf8'))
const localProfile = JSON.parse(readFileSync(resolve(root, 'docs/contracts/castalia-local-v1-source-profile.json'), 'utf8'))

function read(path) {
  return readFileSync(resolve(root, path), 'utf8')
}

test('D0 profile freezes the accepted key and custody boundary', () => {
  assert.equal(profile.status, 'accepted')
  assert.equal(profile.memberKey.suite, 'Ed25519')
  assert.match(profile.memberKey.publicKeyEncoding, /32 raw bytes/)
  assert.ok(profile.memberKey.nonScope.includes('hybrid or post-quantum Dregg turn signing'))
  assert.equal(profile.custody.owner, 'Castalia Wallet extension')
  assert.equal(profile.custody.kdf.name, 'Argon2id')
  assert.equal(profile.custody.aead.name, 'AES-256-GCM')
  assert.equal(profile.custody.passphraseEncoding, 'Unicode NFC, then UTF-8; empty passphrases reject')
  assert.equal(profile.custody.jsonCanonicalization, 'RFC 8785 JSON Canonicalization Scheme (JCS)')
  assert.equal(profile.custody.binaryEncoding, 'unpadded base64url per RFC 4648 section 5')
  assert.match(profile.custody.tagPlacement, /appended to ciphertext/)
  assert.deepEqual(profile.custody.associatedDataFields, ['schema', 'keySuite', 'publicKey', 'createdAt', 'kdf', 'aead'])
})

test('D0 cell identifiers are distinct and non-circular', () => {
  assert.equal(vector.nonCircularity.officialCellDependsOnApplicationCommitment, false)
  assert.equal(vector.nonCircularity.membershipCellDependsOnApplicationCommitment, true)
  assert.notEqual(vector.outputs.applicantOfficialDreggCellId, vector.outputs.membershipCellId)
  for (const output of Object.values(vector.outputs)) assert.match(output, /^[0-9a-f]{64}$/)
})

test('D0 pins canonical Dregg factory semantics and excludes the legacy API', () => {
  assert.equal(localProfile.dregg.observedHead, 'c08967ca2bf2d5fcf25561e070f9a46efc54774b')
  assert.equal(localProfile.dregg.requiredEffect, 'Effect::CreateCellFromFactory')
  assert.equal(localProfile.dregg.requiredCreatedCellFormula, 'CellId::derive_raw(owner_pubkey, token_id)')
  assert.match(localProfile.dregg.forbiddenApi, /legacy dregg_create_from_factory/)
  assert.match(localProfile.dregg.worktreeState, /dirty prototype/)
  assert.match(localProfile.claim, /not a deployment or production trust profile/)
})

test('D0 local profile pins concrete fixture roots and wire paths', () => {
  for (const field of ['federationId', 'castaliaAuthorityPublicKey', 'factoryId', 'childProgramVk']) {
    assert.match(localProfile.dregg[field], /^[0-9a-f]{64}$/)
  }
  assert.equal(localProfile.control.bindingPublicKey, 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
  assert.equal(localProfile.http.challengePath, '/v1/membership/challenges')
  assert.equal(localProfile.http.sessionExchangePath, '/v1/sessions/exchange')
  assert.equal(new TextEncoder().encode(profile.control.applicationDomain).at(-1), 0)
  assert.equal(new TextEncoder().encode(profile.transcripts.controlBinding.domain).at(-1), 0)
  assert.equal(profile.control.applicationDomain.includes('\\0'), false)
  assert.match(profile.control.bindingEncoding, /32-bit little-endian length prefix/)
  assert.ok(profile.control.closedHttpErrors.includes('upstream_ambiguous'))
  assert.deepEqual(profile.enums.requestedClass, { individual: 1, institutional: 2 })
  assert.equal(profile.transcripts.application.orderedFields[0].name, 'factoryId')
  assert.equal(profile.transcripts.application.orderedFields.at(-1).name, 'createdAt')
  assert.deepEqual(profile.transcripts.walletPresentation.jsonFields, ['schema', 'ownerPublicKey', 'challenge', 'signatureSuite', 'signature'])
  assert.equal(profile.wire.activateRequest.path, '/v1/operator/memberships/{applicationId}/activate')
  assert.equal(profile.wire.activateRequest.browserAccessible, false)
  assert.equal(profile.provenance.applicantOfficialDreggCellId.callerOverride, false)
  assert.equal(profile.stateMachine.initial, 'challenge_issued')
  assert.match(profile.saga.forbidden, /no claimed cross-store atomic transaction/)
  assert.equal(profile.bounds.outboxBacklog.overload, 'capacity_exhausted before challenge consumption')
  assert.deepEqual(profile.enums.operatorReasonCode, { approved: 1, 'manual-review-complete': 2 })
  assert.equal(profile.operatorAuthentication.scheme, 'Castalia-Operator-V1')
  assert.match(profile.operatorAuthentication.wire, /^Castalia-Operator-V1/)
  assert.equal(localProfile.control.operatorAuthentication.scheme, 'Castalia-Operator-V1')
  for (const transcript of ['controlBinding', 'sessionChallenge']) {
    for (const field of profile.transcripts[transcript].orderedFields) {
      assert.equal(typeof field.name, 'string')
      assert.equal(typeof field.type, 'string')
    }
  }
  for (const field of ['applicationCommitment', 'membershipCellId', 'birthNonce', 'applicationId', 'challengeId', 'sessionChallengeId', 'creationReceiptId', 'activeReceiptHead', 'activeGeneration', 'requestedScope']) {
    assert.equal(profile.provenance[field].callerOverride, false, `missing closed provenance for ${field}`)
  }
})

test('agents preserve v1 and v2 compatibility while architecture makes v3 active', () => {
  const agents = read('AGENTS.md')
  const architecture = read('docs/castalia-member-key-and-membership-cell.md')
  assert.match(agents, /docs\/castalia-membership-v1-contract\.md/)
  assert.match(agents, /docs\/contracts\/castalia-membership-v1\.json/)
  assert.match(architecture, /Status: active centralized-compatible v3 architecture for Join/)
  assert.match(architecture, /Wallet generates one OS-random 32-byte identity seed/)
  assert.match(
    architecture,
    /portable Dregg-hybrid identity with Ed25519 and ML-DSA-65/,
  )
  assert.match(
    architecture,
    /Zenith membership credential still authenticates the Ed25519 owner anchor only/,
  )
  assert.match(architecture, /castalia\.zenith-membership\.v3/)
  assert.match(architecture, /Dregg permissionless v2 remains implemented/)
  assert.match(architecture, /There is no individual\/institution selection, application, approval queue/)
})

test('v1 contract contains no unresolved byte-level decisions', () => {
  const contract = read('docs/castalia-membership-v1-contract.md')
  for (const forbidden of ['TBD', 'implementation-defined', 'choose later']) {
    assert.equal(contract.includes(forbidden), false, `contract contains ${forbidden}`)
  }
  assert.match(contract, /Argon2id v19/)
  assert.match(contract, /AES-256-GCM/)
  assert.match(contract, /castalia\/control-membership-binding\/v1 \|\| 0x00/)
  assert.match(contract, /D0 creates no wallet, membership, cell, or session/)
})
