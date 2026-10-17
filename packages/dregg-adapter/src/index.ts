import { blake3 } from '@noble/hashes/blake3.js'

export type CellDetailResponse = {
  id: string
  found: boolean
  balance: number
  nonce: number
  public_key: string
  token_id: string
  program_kind: string
  program?: unknown
  fields: string[]
  capability_count?: number
  has_delegate?: boolean
  has_delegation?: boolean
  state_commitment?: string
  last_receipt_hash: string | null
}

export type CastaliaMemberApplicationV1 = {
  factoryId: string
  programId: string
  officialDreggCellId: string
  ownerPublicKey: string
  applicationKind: number
  applicationVersion: number
  applicationNonce: number
  membershipClass: number
  jurisdictionCode: number
  applicationFlags: number
  createdAt: number
}

export type MembershipExpectation = {
  cellId: string
  authorityPublicKey: string
  applicationCommitment: string
  application: CastaliaMemberApplicationV1
}

export type CastaliaMembershipStatus =
  | 'pending'
  | 'active'
  | 'suspended'
  | 'revoked'
  | 'expired'

export type CastaliaMembership = {
  cellId: string
  authorityPublicKey: string
  applicationCommitment: string
  status: CastaliaMembershipStatus
  generation: number
  createdAt: number
  changedAt: number
  balance: number
  nonce: number
  lastReceiptHash: string | null
}

export type DreggMembershipClientConfig = {
  nodeUrl: string
  expectation: MembershipExpectation
  timeoutMs?: number
}

const FIELD_COUNT = 16
const MAGIC_CASTMEM1 = 3_552_571_879_494_730_051n
const SCHEMA_VERSION = 1n
const COMMITMENT_SLOT_START = 8
const STATUS_SLOT = 12
const GENERATION_SLOT = 13
const CREATED_AT_SLOT = 14
const CHANGED_AT_SLOT = 15
const HEX_32 = /^[0-9a-f]{64}$/

const STATUS_NAMES: Readonly<Record<string, CastaliaMembershipStatus>> = {
  '0': 'pending',
  '1': 'active',
  '2': 'suspended',
  '3': 'revoked',
  '4': 'expired',
}

function canonicalHex(value: string, label: string): string {
  const normalized = value.toLowerCase()
  if (!HEX_32.test(normalized)) {
    throw new Error(`${label} must be 32-byte lowercase-compatible hex`)
  }
  return normalized
}

function bytesFromHex(value: string, label: string): Uint8Array {
  const normalized = canonicalHex(value, label)
  return Uint8Array.from(
    normalized.match(/.{2}/g) ?? [],
    (byte) => Number.parseInt(byte, 16),
  )
}

function applicationU64(value: number, label: string): bigint {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`)
  }
  return BigInt(value)
}

export function commitCastaliaMemberApplication(
  application: CastaliaMemberApplicationV1,
): string {
  const domain = new TextEncoder().encode('castalia/member-application/v1\0')
  const identities = [
    bytesFromHex(application.factoryId, 'membership factory id'),
    bytesFromHex(application.programId, 'membership program id'),
    bytesFromHex(application.officialDreggCellId, 'official Dregg cell id'),
    bytesFromHex(application.ownerPublicKey, 'membership owner public key'),
  ]
  const values = [
    applicationU64(application.applicationKind, 'application kind'),
    applicationU64(application.applicationVersion, 'application version'),
    applicationU64(application.applicationNonce, 'application nonce'),
    applicationU64(application.membershipClass, 'membership class'),
    applicationU64(application.jurisdictionCode, 'jurisdiction code'),
    applicationU64(application.applicationFlags, 'application flags'),
    applicationU64(application.createdAt, 'application createdAt'),
  ]
  const encoded = new Uint8Array(domain.length + (32 * identities.length) + (8 * values.length))
  let offset = 0
  encoded.set(domain, offset)
  offset += domain.length
  for (const identity of identities) {
    encoded.set(identity, offset)
    offset += identity.length
  }
  const view = new DataView(encoded.buffer)
  for (const value of values) {
    view.setBigUint64(offset, value, true)
    offset += 8
  }
  return Array.from(blake3(encoded), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function fieldU64(fields: string[], slot: number): bigint {
  const encoded = fields[slot]?.toLowerCase()
  if (!encoded || !HEX_32.test(encoded)) {
    throw new Error(`membership field ${slot} must be 32-byte hex`)
  }

  const prefix = encoded.slice(0, 48)
  if (prefix !== '0'.repeat(48)) {
    throw new Error(`membership field ${slot} is outside the canonical u64 range`)
  }
  return BigInt(`0x${encoded.slice(48)}`)
}

function safeNumber(value: bigint, label: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label} exceeds the safe integer range`)
  }
  return Number(value)
}

function decodeApplicationCommitment(fields: string[]): string {
  const bytes: number[] = []
  for (let slot = COMMITMENT_SLOT_START; slot < COMMITMENT_SLOT_START + 4; slot += 1) {
    let limb = fieldU64(fields, slot)
    for (let index = 0; index < 8; index += 1) {
      bytes.push(Number(limb & 0xffn))
      limb >>= 8n
    }
  }
  return bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function decodeCastaliaMembership(
  response: CellDetailResponse,
  expected: MembershipExpectation,
): CastaliaMembership {
  const cellId = canonicalHex(expected.cellId, 'membership cell id')
  const authorityPublicKey = canonicalHex(expected.authorityPublicKey, 'Castalia authority key')
  const applicationCommitment = canonicalHex(
    expected.applicationCommitment,
    'application commitment',
  )
  const recomputedApplicationCommitment = commitCastaliaMemberApplication(expected.application)
  if (recomputedApplicationCommitment !== applicationCommitment) {
    throw new Error('membership application does not match its configured commitment')
  }

  if (!response || typeof response !== 'object' || response.found !== true) {
    throw new Error('membership cell was not found')
  }
  if (canonicalHex(response.id, 'node membership cell id') !== cellId) {
    throw new Error('membership cell id mismatch')
  }
  if (canonicalHex(response.public_key, 'node membership authority') !== authorityPublicKey) {
    throw new Error('membership authority mismatch')
  }
  if (response.program_kind !== 'Cases') {
    throw new Error('membership cell does not carry the canonical Cases program')
  }
  if (!Array.isArray(response.fields) || response.fields.length !== FIELD_COUNT) {
    throw new Error(`membership cell must expose exactly ${FIELD_COUNT} fields`)
  }
  if (fieldU64(response.fields, 0) !== MAGIC_CASTMEM1) {
    throw new Error('membership schema magic mismatch')
  }
  if (fieldU64(response.fields, 1) !== SCHEMA_VERSION) {
    throw new Error('membership schema version mismatch')
  }

  const observedCommitment = decodeApplicationCommitment(response.fields)
  if (observedCommitment !== applicationCommitment) {
    throw new Error('membership application commitment mismatch')
  }

  const statusValue = fieldU64(response.fields, STATUS_SLOT)
  const status = STATUS_NAMES[statusValue.toString()]
  if (!status) {
    throw new Error(`membership status ${statusValue} is not recognized`)
  }

  const generation = safeNumber(fieldU64(response.fields, GENERATION_SLOT), 'membership generation')
  const createdAt = safeNumber(fieldU64(response.fields, CREATED_AT_SLOT), 'membership createdAt')
  const changedAt = safeNumber(fieldU64(response.fields, CHANGED_AT_SLOT), 'membership changedAt')
  if (createdAt === 0 || changedAt < createdAt) {
    throw new Error('membership timestamps are not monotonic')
  }

  let lastReceiptHash: string | null = null
  if (response.last_receipt_hash !== null) {
    lastReceiptHash = canonicalHex(response.last_receipt_hash, 'membership receipt head')
  } else if (generation > 0) {
    throw new Error('membership receipt head is required after a lifecycle transition')
  }

  if (!Number.isSafeInteger(response.balance) || response.balance < 0) {
    throw new Error('membership balance must be a non-negative safe integer')
  }
  if (!Number.isSafeInteger(response.nonce) || response.nonce < 0) {
    throw new Error('membership nonce must be a non-negative safe integer')
  }

  return {
    cellId,
    authorityPublicKey,
    applicationCommitment,
    status,
    generation,
    createdAt,
    changedAt,
    balance: response.balance,
    nonce: response.nonce,
    lastReceiptHash,
  }
}

function validatedNodeBaseUrl(nodeUrl: string): URL {
  const url = new URL(nodeUrl)
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]'
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('Dregg node URL must use HTTPS except on loopback')
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('Dregg node URL must not contain credentials, query, or fragment')
  }
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/`
  return url
}

export async function fetchCastaliaMembership(
  config: DreggMembershipClientConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<CastaliaMembership> {
  const baseUrl = validatedNodeBaseUrl(config.nodeUrl)
  const cellId = canonicalHex(config.expectation.cellId, 'membership cell id')
  const endpoint = new URL(`api/cell/${cellId}`, baseUrl)
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs ?? 10_000)

  try {
    const response = await fetchImpl(endpoint, {
      method: 'GET',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    })
    if (!response.ok) {
      throw new Error(`Dregg membership lookup failed with HTTP ${response.status}`)
    }
    const body: unknown = await response.json()
    return decodeCastaliaMembership(body as CellDetailResponse, config.expectation)
  } finally {
    clearTimeout(timeout)
  }
}

// =============================================================================
// Permissionless Castalia membership v2
// =============================================================================

export const CASTALIA_PERMISSIONLESS_MEMBERSHIP_VERSION = 2 as const
declare const __CASTALIA_DREGG_NODE_URL__: string | undefined
export const CASTALIA_DREGG_NODE_URL = typeof __CASTALIA_DREGG_NODE_URL__ === 'string'
  ? __CASTALIA_DREGG_NODE_URL__
  : 'http://127.0.0.1:8420'
export const CASTALIA_PERMISSIONLESS_JOIN_DOMAIN =
  'castalia/permissionless-membership-join/v2\0'

const MAGIC_CASTMEM2 = 3_624_629_473_532_657_987n
const PERMISSIONLESS_POLICY = 1n
const PERMISSIONLESS_ACTIVE = 1n
const PERMISSIONLESS_FACTORY_DOMAIN =
  new TextEncoder().encode('castalia/permissionless-membership-factory/v2\0')
const PERMISSIONLESS_TOKEN_DOMAIN =
  new TextEncoder().encode('castalia/permissionless-membership-cell/v2\0')
const DREGG_CELL_ID_CONTEXT = new TextEncoder().encode('dregg-cell-id-v1')

function hexFromBytes(value: Uint8Array): string {
  return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('')
}

export const CASTALIA_PERMISSIONLESS_FACTORY_ID = hexFromBytes(
  blake3(PERMISSIONLESS_FACTORY_DOMAIN),
)
export const CASTALIA_PERMISSIONLESS_PROGRAM_ID =
  '6c37adae385c40894127e766deb9aff54e4cd01b0ccf01aff1ac7c12e24441fd'
export const CASTALIA_PERMISSIONLESS_TOKEN_ID = hexFromBytes(
  blake3(PERMISSIONLESS_TOKEN_DOMAIN),
)

export type PermissionlessMembershipBindingV2 = {
  version: 2
  nodeUrl: string
  cellId: string
  ownerPublicKey: string
  factoryId: string
  programId: string
  stateCommitment: string
  receiptHash: string | null
}

export type PermissionlessMembershipV2 = {
  version: 2
  cellId: string
  ownerPublicKey: string
  status: 'active'
  generation: 0
  stateCommitment: string
  lastReceiptHash: string | null
}

type PermissionlessJoinResponse = {
  version: number
  membershipCellId: string
  ownerPublicKey: string
  state: string
  generation: number
  factoryId: string
  programId: string
  stateCommitment: string
  receiptHash: string | null
  created: boolean
}

export function permissionlessMembershipJoinTranscript(ownerPublicKey: string): Uint8Array {
  const owner = bytesFromHex(ownerPublicKey, 'Member Key')
  const domain = new TextEncoder().encode(CASTALIA_PERMISSIONLESS_JOIN_DOMAIN)
  const transcript = new Uint8Array(domain.length + owner.length)
  transcript.set(domain)
  transcript.set(owner, domain.length)
  return transcript
}

export function derivePermissionlessMembershipCellId(ownerPublicKey: string): string {
  const material = new Uint8Array(64)
  material.set(bytesFromHex(ownerPublicKey, 'Member Key'))
  material.set(bytesFromHex(CASTALIA_PERMISSIONLESS_TOKEN_ID, 'membership token id'), 32)
  return hexFromBytes(blake3(material, { context: DREGG_CELL_ID_CONTEXT }))
}

function assertPermissionlessProgram(program: unknown): void {
  if (!program || typeof program !== 'object') {
    throw new Error('membership cell does not expose its canonical program')
  }
  const value = program as {
    kind?: unknown
    cases?: Array<{
      guard?: { kind?: unknown }
      constraints?: Array<{ kind?: unknown; index?: unknown }>
    }>
  }
  const cases = value.cases
  const constraints = cases?.[0]?.constraints
  if (
    value.kind !== 'Cases'
    || cases?.length !== 1
    || cases[0]?.guard?.kind !== 'Always'
    || constraints?.length !== FIELD_COUNT
    || !constraints.every((constraint, index) =>
      constraint.kind === 'Immutable' && constraint.index === index)
  ) {
    throw new Error('membership cell program is not the immutable v2 program')
  }
}

export function decodePermissionlessMembership(
  response: CellDetailResponse,
  binding: PermissionlessMembershipBindingV2,
): PermissionlessMembershipV2 {
  const owner = canonicalHex(binding.ownerPublicKey, 'Member Key')
  if (canonicalHex(binding.factoryId, 'membership factory id') !== CASTALIA_PERMISSIONLESS_FACTORY_ID) {
    throw new Error('membership binding factory is not canonical v2')
  }
  if (canonicalHex(binding.programId, 'membership program id') !== CASTALIA_PERMISSIONLESS_PROGRAM_ID) {
    throw new Error('membership binding program is not canonical v2')
  }
  const cellId = derivePermissionlessMembershipCellId(owner)
  if (canonicalHex(binding.cellId, 'membership cell id') !== cellId) {
    throw new Error('membership binding is not deterministically addressed by this Member Key')
  }
  if (!response || typeof response !== 'object' || response.found !== true) {
    throw new Error('membership cell was not found')
  }
  if (canonicalHex(response.id, 'node membership cell id') !== cellId) {
    throw new Error('membership cell id mismatch')
  }
  if (canonicalHex(response.public_key, 'node membership owner') !== owner) {
    throw new Error('membership owner key does not match this Wallet')
  }
  if (canonicalHex(response.token_id, 'membership token id') !== CASTALIA_PERMISSIONLESS_TOKEN_ID) {
    throw new Error('membership token domain mismatch')
  }
  if (response.program_kind !== 'Cases') {
    throw new Error('membership cell does not carry the canonical Cases program')
  }
  assertPermissionlessProgram(response.program)
  if (
    response.capability_count !== 0
    || response.has_delegate !== false
    || response.has_delegation !== false
  ) {
    throw new Error('base membership must not carry capabilities or delegation')
  }
  if (!Array.isArray(response.fields) || response.fields.length !== FIELD_COUNT) {
    throw new Error(`membership cell must expose exactly ${FIELD_COUNT} fields`)
  }
  const expected = [
    MAGIC_CASTMEM2,
    BigInt(CASTALIA_PERMISSIONLESS_MEMBERSHIP_VERSION),
    PERMISSIONLESS_POLICY,
    0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n,
    PERMISSIONLESS_ACTIVE,
    0n,
    0n,
    0n,
  ]
  for (let slot = 0; slot < expected.length; slot += 1) {
    if (fieldU64(response.fields, slot) !== expected[slot]) {
      throw new Error(`membership field ${slot} is not canonical v2 Active state`)
    }
  }
  const stateCommitment = canonicalHex(
    response.state_commitment ?? '',
    'membership state commitment',
  )
  if (stateCommitment !== canonicalHex(binding.stateCommitment, 'bound state commitment')) {
    throw new Error('membership state commitment changed from the issued binding')
  }
  return {
    version: CASTALIA_PERMISSIONLESS_MEMBERSHIP_VERSION,
    cellId,
    ownerPublicKey: owner,
    status: 'active',
    generation: 0,
    stateCommitment,
    lastReceiptHash: binding.receiptHash,
  }
}

export async function fetchPermissionlessCastaliaMembership(
  binding: PermissionlessMembershipBindingV2,
  fetchImpl: typeof fetch = fetch,
): Promise<PermissionlessMembershipV2> {
  if (binding.version !== CASTALIA_PERMISSIONLESS_MEMBERSHIP_VERSION) {
    throw new Error('unsupported permissionless membership binding version')
  }
  if (canonicalHex(binding.factoryId, 'membership factory id') !== CASTALIA_PERMISSIONLESS_FACTORY_ID) {
    throw new Error('membership binding factory is not canonical v2')
  }
  if (canonicalHex(binding.programId, 'membership program id') !== CASTALIA_PERMISSIONLESS_PROGRAM_ID) {
    throw new Error('membership binding program is not canonical v2')
  }
  const baseUrl = validatedNodeBaseUrl(binding.nodeUrl)
  const cellId = derivePermissionlessMembershipCellId(binding.ownerPublicKey)
  const endpoint = new URL(`api/cell/${cellId}`, baseUrl)
  const response = await fetchImpl(endpoint, {
    method: 'GET',
    headers: { accept: 'application/json' },
  })
  if (!response.ok) {
    throw new Error(`Dregg membership lookup failed with HTTP ${response.status}`)
  }
  return decodePermissionlessMembership(
    await response.json() as CellDetailResponse,
    binding,
  )
}

export async function issuePermissionlessCastaliaMembership(
  request: {
    nodeUrl?: string
    ownerPublicKey: string
    signature: string
  },
  fetchImpl: typeof fetch = fetch,
): Promise<PermissionlessMembershipBindingV2> {
  const ownerPublicKey = canonicalHex(request.ownerPublicKey, 'Member Key')
  if (!/^[A-Za-z0-9_-]{86}$/.test(request.signature)) {
    throw new Error('membership signature must be a 64-byte unpadded base64url value')
  }
  const nodeUrl = request.nodeUrl ?? CASTALIA_DREGG_NODE_URL
  const baseUrl = validatedNodeBaseUrl(nodeUrl)
  const response = await fetchImpl(new URL('api/castalia/memberships', baseUrl), {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      version: CASTALIA_PERMISSIONLESS_MEMBERSHIP_VERSION,
      ownerPublicKey,
      signatureSuite: 'Ed25519',
      signature: request.signature,
    }),
  })
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const message = body && typeof body === 'object' && 'message' in body
      ? String((body as { message: unknown }).message)
      : `HTTP ${response.status}`
    throw new Error(`Dregg membership issuance failed: ${message}`)
  }
  const value = body as Partial<PermissionlessJoinResponse>
  const expectedCellId = derivePermissionlessMembershipCellId(ownerPublicKey)
  if (
    value.version !== CASTALIA_PERMISSIONLESS_MEMBERSHIP_VERSION
    || value.ownerPublicKey !== ownerPublicKey
    || value.state !== 'active'
    || value.generation !== 0
    || typeof value.created !== 'boolean'
    || canonicalHex(value.membershipCellId ?? '', 'issued membership cell id') !== expectedCellId
    || canonicalHex(value.factoryId ?? '', 'issued membership factory id')
      !== CASTALIA_PERMISSIONLESS_FACTORY_ID
    || canonicalHex(value.programId ?? '', 'issued membership program id')
      !== CASTALIA_PERMISSIONLESS_PROGRAM_ID
  ) {
    throw new Error('Dregg returned a non-canonical permissionless membership binding')
  }
  const binding: PermissionlessMembershipBindingV2 = {
    version: CASTALIA_PERMISSIONLESS_MEMBERSHIP_VERSION,
    nodeUrl: baseUrl.origin,
    cellId: expectedCellId,
    ownerPublicKey,
    factoryId: CASTALIA_PERMISSIONLESS_FACTORY_ID,
    programId: CASTALIA_PERMISSIONLESS_PROGRAM_ID,
    stateCommitment: canonicalHex(value.stateCommitment ?? '', 'issued state commitment'),
    receiptHash: value.receiptHash === null || value.receiptHash === undefined
      ? null
      : canonicalHex(value.receiptHash, 'issued receipt hash'),
  }
  await fetchPermissionlessCastaliaMembership(binding, fetchImpl)
  return binding
}
