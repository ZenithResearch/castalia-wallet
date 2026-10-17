import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import {
  CASTALIA_PERMISSIONLESS_FACTORY_ID,
  CASTALIA_PERMISSIONLESS_PROGRAM_ID,
  CASTALIA_PERMISSIONLESS_TOKEN_ID,
  commitCastaliaMemberApplication,
  decodePermissionlessMembership,
  derivePermissionlessMembershipCellId,
  decodeCastaliaMembership,
  fetchCastaliaMembership,
  issuePermissionlessCastaliaMembership,
  type CastaliaMemberApplicationV1,
  type CellDetailResponse,
  type MembershipExpectation,
} from '../src/index.js'

const AUTHORITY = '41'.repeat(32)
const CELL_ID = '51'.repeat(32)
const APPLICATION: CastaliaMemberApplicationV1 = {
  factoryId: '61'.repeat(32),
  programId: '62'.repeat(32),
  officialDreggCellId: '63'.repeat(32),
  ownerPublicKey: '64'.repeat(32),
  applicationKind: 7,
  applicationVersion: 1,
  applicationNonce: 9,
  membershipClass: 2,
  jurisdictionCode: 840,
  applicationFlags: 5,
  createdAt: 1_700_000_000,
}
const COMMITMENT = commitCastaliaMemberApplication(APPLICATION)

function field(value: bigint): string {
  return value.toString(16).padStart(64, '0')
}

function commitmentFields(commitment: string): string[] {
  const bytes = Buffer.from(commitment, 'hex')
  return Array.from({ length: 4 }, (_, limb) => {
    const chunk = bytes.subarray(limb * 8, limb * 8 + 8)
    return field(chunk.readBigUInt64LE())
  })
}

function expectation(overrides: Partial<MembershipExpectation> = {}): MembershipExpectation {
  return {
    cellId: overrides.cellId ?? CELL_ID,
    authorityPublicKey: overrides.authorityPublicKey ?? AUTHORITY,
    applicationCommitment: overrides.applicationCommitment ?? COMMITMENT,
    application: overrides.application ?? APPLICATION,
  }
}

function activeCell(overrides: Partial<CellDetailResponse> = {}): CellDetailResponse {
  return {
    id: CELL_ID,
    found: true,
    balance: 3_000,
    nonce: 1,
    public_key: AUTHORITY,
    token_id: '52'.repeat(32),
    program_kind: 'Cases',
    fields: [
      field(3_552_571_879_494_730_051n),
      field(1n),
      field(7n),
      field(1n),
      field(9n),
      field(2n),
      field(840n),
      field(5n),
      ...commitmentFields(COMMITMENT),
      field(1n),
      field(1n),
      field(1_700_000_000n),
      field(1_700_000_001n),
    ],
    last_receipt_hash: '53'.repeat(32),
    ...overrides,
  }
}

test('decodes a canonical active Castalia membership cell', () => {
  const membership = decodeCastaliaMembership(activeCell(), expectation())

  assert.equal(membership.cellId, CELL_ID)
  assert.equal(membership.status, 'active')
  assert.equal(membership.generation, 1)
  assert.equal(membership.changedAt, 1_700_000_001)
  assert.equal(membership.applicationCommitment, COMMITMENT)
  assert.equal(membership.lastReceiptHash, '53'.repeat(32))
})

test('rejects an authority-owned cell from a different Castalia authority', () => {
  assert.throws(
    () => decodeCastaliaMembership(activeCell({ public_key: '42'.repeat(32) }), expectation()),
    /authority/i,
  )
})

test('rejects application commitment substitution', () => {
  assert.throws(
    () => decodeCastaliaMembership(activeCell(), expectation({ applicationCommitment: 'ff'.repeat(32) })),
    /application.*commitment/i,
  )
})

test('rejects an application envelope belonging to another member key', () => {
  assert.throws(
    () => decodeCastaliaMembership(activeCell(), expectation({
      application: { ...APPLICATION, ownerPublicKey: '65'.repeat(32) },
    })),
    /application.*commitment/i,
  )
})

test('rejects malformed schema and unknown lifecycle status', () => {
  const wrongSchema = activeCell()
  wrongSchema.fields[1] = field(2n)
  assert.throws(() => decodeCastaliaMembership(wrongSchema, expectation()), /schema version/i)

  const unknownStatus = activeCell()
  unknownStatus.fields[12] = field(99n)
  assert.throws(() => decodeCastaliaMembership(unknownStatus, expectation()), /status/i)
})

test('requires a persistent receipt head after the first lifecycle transition', () => {
  assert.throws(
    () => decodeCastaliaMembership(activeCell({ last_receipt_hash: null }), expectation()),
    /receipt head/i,
  )
})

test('fetches only the configured cell and permits plaintext HTTP only on loopback', async () => {
  const seen: string[] = []
  const fetchImpl: typeof fetch = async (input) => {
    seen.push(String(input))
    return new Response(JSON.stringify(activeCell()), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }

  const membership = await fetchCastaliaMembership(
    { nodeUrl: 'http://127.0.0.1:8765', expectation: expectation() },
    fetchImpl,
  )

  assert.equal(membership.status, 'active')
  assert.deepEqual(seen, [`http://127.0.0.1:8765/api/cell/${CELL_ID}`])

  await assert.rejects(
    fetchCastaliaMembership(
      { nodeUrl: 'http://node.example', expectation: expectation() },
      fetchImpl,
    ),
    /https/i,
  )
})

test('fails closed on node errors without accepting an unverified body', async () => {
  const fetchImpl: typeof fetch = async () => new Response(JSON.stringify(activeCell()), { status: 503 })

  await assert.rejects(
    fetchCastaliaMembership(
      { nodeUrl: 'https://node.example', expectation: expectation() },
      fetchImpl,
    ),
    /503/,
  )
})

const V2_OWNER = '71'.repeat(32)
const V2_CELL_ID = derivePermissionlessMembershipCellId(V2_OWNER)
const V2_PROGRAM_ID = CASTALIA_PERMISSIONLESS_PROGRAM_ID
const V2_STATE_COMMITMENT = '73'.repeat(32)

test('matches the canonical permissionless membership v2 identifiers', () => {
  assert.equal(
    CASTALIA_PERMISSIONLESS_FACTORY_ID,
    '7ad3af1ba0e83ad560a881780295706073c1a0c9fe8656310051f62444903554',
  )
  assert.equal(
    CASTALIA_PERMISSIONLESS_TOKEN_ID,
    '7f66eec85e99cd49ef3c8d733b8c489defe0a721f03fb2c3dd4bea04b1710d1f',
  )
  assert.equal(
    V2_CELL_ID,
    'e4eea3e7352a5c8591508e880ce095421e472946dd3c1936e3efa05870447522',
  )
})

function activeV2Cell(overrides: Partial<CellDetailResponse> = {}): CellDetailResponse {
  return {
    id: V2_CELL_ID,
    found: true,
    balance: 0,
    nonce: 0,
    public_key: V2_OWNER,
    token_id: CASTALIA_PERMISSIONLESS_TOKEN_ID,
    program_kind: 'Cases',
    program: {
      kind: 'Cases',
      cases: [{
        guard: { kind: 'Always' },
        constraints: Array.from({ length: 16 }, (_, index) => ({
          kind: 'Immutable',
          index,
        })),
      }],
    },
    capability_count: 0,
    has_delegate: false,
    has_delegation: false,
    fields: [
      field(3_624_629_473_532_657_987n),
      field(2n),
      field(1n),
      ...Array.from({ length: 9 }, () => field(0n)),
      field(1n),
      field(0n),
      field(0n),
      field(0n),
    ],
    state_commitment: V2_STATE_COMMITMENT,
    last_receipt_hash: null,
    ...overrides,
  }
}

const V2_BINDING = {
  version: 2 as const,
  nodeUrl: 'http://127.0.0.1:8420',
  cellId: V2_CELL_ID,
  ownerPublicKey: V2_OWNER,
  factoryId: CASTALIA_PERMISSIONLESS_FACTORY_ID,
  programId: V2_PROGRAM_ID,
  stateCommitment: V2_STATE_COMMITMENT,
  receiptHash: '74'.repeat(32),
}

test('decodes only exact member-owned immutable Active v2 membership', () => {
  const membership = decodePermissionlessMembership(activeV2Cell(), V2_BINDING)
  assert.equal(membership.cellId, V2_CELL_ID)
  assert.equal(membership.ownerPublicKey, V2_OWNER)
  assert.equal(membership.status, 'active')
  assert.equal(membership.generation, 0)

  assert.throws(
    () => decodePermissionlessMembership(activeV2Cell({ public_key: '75'.repeat(32) }), V2_BINDING),
    /owner/i,
  )
  assert.throws(
    () => decodePermissionlessMembership(activeV2Cell({ capability_count: 1 }), V2_BINDING),
    /capabilities/i,
  )
  assert.throws(
    () => decodePermissionlessMembership(activeV2Cell({ has_delegation: true }), V2_BINDING),
    /delegation/i,
  )
  const mutable = activeV2Cell()
  mutable.program = {
    kind: 'Cases',
    cases: [{ guard: { kind: 'Always' }, constraints: [] }],
  }
  assert.throws(() => decodePermissionlessMembership(mutable, V2_BINDING), /immutable/i)
})

test('pins the checked-in v2 vector, checksum, and canonical program id', () => {
  const vectorUrl = new URL('../../../docs/vectors/castalia-permissionless-membership-v2.vector.json', import.meta.url)
  const checksumUrl = new URL('../../../docs/vectors/castalia-permissionless-membership-v2.vector.sha256', import.meta.url)
  const bytes = readFileSync(vectorUrl)
  const checksum = readFileSync(checksumUrl, 'utf8').trim()
  assert.equal(createHash('sha256').update(bytes).digest('hex'), checksum)
  const vector = JSON.parse(bytes.toString('utf8')) as Record<string, string>
  assert.equal(vector.factoryId, CASTALIA_PERMISSIONLESS_FACTORY_ID)
  assert.equal(vector.programId, CASTALIA_PERMISSIONLESS_PROGRAM_ID)
  assert.equal(vector.tokenId, CASTALIA_PERMISSIONLESS_TOKEN_ID)
  assert.equal(vector.membershipCellId, V2_CELL_ID)
})

test('issues v2 directly through Dregg and verifies the returned live cell', async () => {
  const seen: Array<{ url: string; method: string; body?: unknown }> = []
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input)
    seen.push({
      url,
      method: init?.method ?? 'GET',
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    })
    if (init?.method === 'POST') {
      return new Response(JSON.stringify({
        version: 2,
        membershipCellId: V2_CELL_ID,
        ownerPublicKey: V2_OWNER,
        state: 'active',
        generation: 0,
        factoryId: CASTALIA_PERMISSIONLESS_FACTORY_ID,
        programId: V2_PROGRAM_ID,
        stateCommitment: V2_STATE_COMMITMENT,
        receiptHash: '74'.repeat(32),
        created: true,
      }), { status: 200 })
    }
    return new Response(JSON.stringify(activeV2Cell()), { status: 200 })
  }

  const binding = await issuePermissionlessCastaliaMembership({
    ownerPublicKey: V2_OWNER,
    signature: 'A'.repeat(86),
  }, fetchImpl)

  assert.deepEqual(binding, V2_BINDING)
  assert.equal(seen[0]?.url, 'http://127.0.0.1:8420/api/castalia/memberships')
  assert.equal(seen[0]?.method, 'POST')
  assert.deepEqual(seen[0]?.body, {
    version: 2,
    ownerPublicKey: V2_OWNER,
    signatureSuite: 'Ed25519',
    signature: 'A'.repeat(86),
  })
  assert.equal(seen[1]?.url, `http://127.0.0.1:8420/api/cell/${V2_CELL_ID}`)
})

test('rejects a join response that does not report whether issuance created the cell', async () => {
  const fetchImpl: typeof fetch = async (_input, init) => {
    assert.equal(init?.method, 'POST')
    return new Response(JSON.stringify({
      version: 2,
      membershipCellId: V2_CELL_ID,
      ownerPublicKey: V2_OWNER,
      state: 'active',
      generation: 0,
      factoryId: CASTALIA_PERMISSIONLESS_FACTORY_ID,
      programId: V2_PROGRAM_ID,
      stateCommitment: V2_STATE_COMMITMENT,
      receiptHash: '74'.repeat(32),
    }), { status: 200 })
  }

  await assert.rejects(
    issuePermissionlessCastaliaMembership({
      ownerPublicKey: V2_OWNER,
      signature: 'A'.repeat(86),
    }, fetchImpl),
    /non-canonical permissionless membership binding/,
  )
})
