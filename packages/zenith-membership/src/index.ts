export const ZENITH_MEMBERSHIP_PROTOCOL = 'castalia.zenith-membership.v3' as const
export const ZENITH_MEMBERSHIP_REQUEST_SCHEMA = 'castalia.zenith-membership-issuance-request.v3' as const
export const ZENITH_MEMBERSHIP_CREDENTIAL_SCHEMA = 'castalia.zenith-membership-credential.v3' as const
export const ZENITH_MEMBERSHIP_VERSION = 3 as const
export const ZENITH_MEMBERSHIP_ISSUER_ID = 'zenith-research' as const
export const ZENITH_MEMBERSHIP_ENDPOINT_PATH = '/v3/memberships' as const
export const ZENITH_MEMBERSHIP_JOIN_DOMAIN = 'castalia/zenith-membership-join/v3\0' as const
export const ZENITH_MEMBERSHIP_ID_DOMAIN = 'castalia/zenith-membership-id/v3\0' as const
export const ZENITH_MEMBERSHIP_CREDENTIAL_DOMAIN = 'castalia/zenith-membership-credential/v3\0' as const

const HEX_32 = /^[0-9a-f]{64}$/
const BASE64URL_64 = /^[A-Za-z0-9_-]{86}$/
const IDENTIFIER = /^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])
const textEncoder = new TextEncoder()

export type ZenithMembershipIssuanceRequestV3 = {
  schema: typeof ZENITH_MEMBERSHIP_REQUEST_SCHEMA
  version: typeof ZENITH_MEMBERSHIP_VERSION
  ownerPublicKey: string
  signatureSuite: 'Ed25519'
  signature: string
}

export type ZenithMembershipCredentialV3 = {
  schema: typeof ZENITH_MEMBERSHIP_CREDENTIAL_SCHEMA
  version: typeof ZENITH_MEMBERSHIP_VERSION
  membershipId: string
  ownerPublicKey: string
  status: 'active'
  issuerId: string
  issuerKeyId: string
  signatureSuite: 'Ed25519'
  issuerSignature: string
}

type ZenithMembershipCredentialPayloadV3 = Omit<
  ZenithMembershipCredentialV3,
  'issuerSignature'
>

export type ZenithMembershipTrustRootV1 = {
  issuerId: string
  keyId: string
  signatureSuite: 'Ed25519'
  publicKey: string
}

export type ZenithMembershipTrustPolicyV1 = {
  schema: 'castalia.zenith-membership-trust-policy.v1'
  version: 1
  roots: readonly ZenithMembershipTrustRootV1[]
}

export type IssueZenithMembershipInput = {
  issuerUrl: string
  ownerPublicKey: string
  signature: string
  trustPolicy: ZenithMembershipTrustPolicyV1
  fetchImpl?: typeof fetch
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  return Object.keys(value).sort().join(',') === [...expected].sort().join(',')
}

export function bytesFromHex32(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    throw new Error(`${label} must be 32-byte lowercase hex`)
  }
  return Uint8Array.from(value.match(/../g) ?? [], pair => Number.parseInt(pair, 16))
}

export function hexFromBytes(value: Uint8Array): string {
  return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('')
}

export function bytesFromBase64url64(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string' || !BASE64URL_64.test(value)) {
    throw new Error(`${label} must be a 64-byte unpadded base64url value`)
  }
  const binary = atob(`${value.replace(/-/g, '+').replace(/_/g, '/')}==`)
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0))
  if (bytes.length !== 64) {
    throw new Error(`${label} must be a 64-byte unpadded base64url value`)
  }
  return bytes
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0))
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}

function arrayBufferFromBytes(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength)
  copy.set(value)
  return copy.buffer
}

function u64le(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8)
  new DataView(bytes.buffer).setBigUint64(0, value, true)
  return bytes
}

function framedUtf8(value: string, label: string): Uint8Array {
  if (!IDENTIFIER.test(value)) throw new Error(`${label} is not canonical`)
  const encoded = textEncoder.encode(value)
  const length = new Uint8Array(4)
  new DataView(length.buffer).setUint32(0, encoded.length, true)
  return concatBytes(length, encoded)
}

export function zenithMembershipJoinTranscript(ownerPublicKey: string): Uint8Array {
  return concatBytes(
    textEncoder.encode(ZENITH_MEMBERSHIP_JOIN_DOMAIN),
    bytesFromHex32(ownerPublicKey, 'Member Key'),
  )
}

export async function deriveZenithMembershipId(ownerPublicKey: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    arrayBufferFromBytes(
      concatBytes(
        textEncoder.encode(ZENITH_MEMBERSHIP_ID_DOMAIN),
        bytesFromHex32(ownerPublicKey, 'Member Key'),
      ),
    ),
  )
  return hexFromBytes(new Uint8Array(digest))
}

export function parseZenithMembershipCredential(input: unknown): ZenithMembershipCredentialV3 {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new Error('membership credential must be an object')
  }
  if (!exactKeys(input, [
    'issuerId',
    'issuerKeyId',
    'issuerSignature',
    'membershipId',
    'ownerPublicKey',
    'schema',
    'signatureSuite',
    'status',
    'version',
  ])) {
    throw new Error('membership credential fields are not canonical v3')
  }
  const value = input as Partial<ZenithMembershipCredentialV3>
  if (
    value.schema !== ZENITH_MEMBERSHIP_CREDENTIAL_SCHEMA
    || value.version !== ZENITH_MEMBERSHIP_VERSION
    || value.status !== 'active'
    || value.signatureSuite !== 'Ed25519'
  ) {
    throw new Error('membership credential protocol is not canonical v3')
  }
  bytesFromHex32(value.membershipId, 'membership ID')
  bytesFromHex32(value.ownerPublicKey, 'Member Key')
  framedUtf8(value.issuerId ?? '', 'membership issuer ID')
  framedUtf8(value.issuerKeyId ?? '', 'membership issuer key ID')
  bytesFromBase64url64(value.issuerSignature, 'membership issuer signature')
  return structuredClone(value as ZenithMembershipCredentialV3)
}

function parseZenithMembershipCredentialPayload(
  input: unknown,
): ZenithMembershipCredentialPayloadV3 {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new Error('membership credential payload must be an object')
  }
  if (!exactKeys(input, [
    'issuerId',
    'issuerKeyId',
    'membershipId',
    'ownerPublicKey',
    'schema',
    'signatureSuite',
    'status',
    'version',
  ])) {
    throw new Error('membership credential payload fields are not canonical v3')
  }
  const value = input as Partial<ZenithMembershipCredentialPayloadV3>
  if (
    value.schema !== ZENITH_MEMBERSHIP_CREDENTIAL_SCHEMA
    || value.version !== ZENITH_MEMBERSHIP_VERSION
    || value.status !== 'active'
    || value.signatureSuite !== 'Ed25519'
  ) {
    throw new Error('membership credential payload is not canonical v3')
  }
  bytesFromHex32(value.membershipId, 'membership ID')
  bytesFromHex32(value.ownerPublicKey, 'Member Key')
  framedUtf8(value.issuerId ?? '', 'membership issuer ID')
  framedUtf8(value.issuerKeyId ?? '', 'membership issuer key ID')
  return structuredClone(value as ZenithMembershipCredentialPayloadV3)
}

function credentialPayload(
  credential: ZenithMembershipCredentialV3,
): ZenithMembershipCredentialPayloadV3 {
  return {
    schema: credential.schema,
    version: credential.version,
    membershipId: credential.membershipId,
    ownerPublicKey: credential.ownerPublicKey,
    status: credential.status,
    issuerId: credential.issuerId,
    issuerKeyId: credential.issuerKeyId,
    signatureSuite: credential.signatureSuite,
  }
}

export function zenithMembershipCredentialTranscript(input: unknown): Uint8Array {
  const value = parseZenithMembershipCredentialPayload(input)
  return concatBytes(
    textEncoder.encode(ZENITH_MEMBERSHIP_CREDENTIAL_DOMAIN),
    u64le(BigInt(value.version)),
    bytesFromHex32(value.membershipId, 'membership ID'),
    bytesFromHex32(value.ownerPublicKey, 'Member Key'),
    framedUtf8(value.status, 'membership status'),
    framedUtf8(value.issuerId, 'membership issuer ID'),
    framedUtf8(value.issuerKeyId, 'membership issuer key ID'),
    framedUtf8(value.signatureSuite.toLowerCase(), 'signature suite'),
  )
}

export function validateZenithTrustPolicy(
  policy: unknown,
): asserts policy is ZenithMembershipTrustPolicyV1 {
  if (typeof policy !== 'object' || policy === null || Array.isArray(policy)) {
    throw new Error('Zenith membership trust policy must be an object')
  }
  if (!exactKeys(policy, ['roots', 'schema', 'version'])) {
    throw new Error('Zenith membership trust policy fields are not canonical v1')
  }
  const value = policy as Partial<ZenithMembershipTrustPolicyV1>
  if (
    value.schema !== 'castalia.zenith-membership-trust-policy.v1'
    || value.version !== 1
    || !Array.isArray(value.roots)
    || value.roots.length === 0
  ) {
    throw new Error('Zenith membership trust policy is not canonical v1')
  }
  const roots = value.roots as readonly unknown[]
  const identities = new Set<string>()
  for (const candidate of roots) {
    if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) {
      throw new Error('Zenith membership trust root must be an object')
    }
    if (!exactKeys(candidate, ['issuerId', 'keyId', 'publicKey', 'signatureSuite'])) {
      throw new Error('Zenith membership trust root fields are not canonical')
    }
    const root = candidate as Partial<ZenithMembershipTrustRootV1>
    const issuerId = root.issuerId ?? ''
    const keyId = root.keyId ?? ''
    if (
      root.signatureSuite !== 'Ed25519'
      || !IDENTIFIER.test(issuerId)
      || !IDENTIFIER.test(keyId)
    ) {
      throw new Error('Zenith membership trust root is not canonical')
    }
    bytesFromHex32(root.publicKey, 'issuer public key')
    const identity = `${issuerId}\0${keyId}`
    if (identities.has(identity)) {
      throw new Error('Zenith membership trust policy contains a duplicate root')
    }
    identities.add(identity)
  }
}

export async function verifyZenithMembershipCredential(
  input: unknown,
  policy: ZenithMembershipTrustPolicyV1,
  expectedOwnerPublicKey?: string,
): Promise<ZenithMembershipCredentialV3> {
  validateZenithTrustPolicy(policy)
  const credential = parseZenithMembershipCredential(input)
  if (expectedOwnerPublicKey !== undefined && credential.ownerPublicKey !== expectedOwnerPublicKey) {
    throw new Error('membership credential owner does not match this Member Key')
  }
  if (credential.membershipId !== await deriveZenithMembershipId(credential.ownerPublicKey)) {
    throw new Error('membership credential ID is not deterministic for its owner')
  }
  const root = policy.roots.find(candidate =>
    candidate.issuerId === credential.issuerId
    && candidate.keyId === credential.issuerKeyId)
  if (!root) throw new Error('membership credential issuer is not trusted')
  const publicKey = await globalThis.crypto.subtle.importKey(
    'raw',
    arrayBufferFromBytes(bytesFromHex32(root.publicKey, 'issuer public key')),
    { name: 'Ed25519' },
    false,
    ['verify'],
  )
  const valid = await globalThis.crypto.subtle.verify(
    { name: 'Ed25519' },
    publicKey,
    arrayBufferFromBytes(
      bytesFromBase64url64(credential.issuerSignature, 'membership issuer signature'),
    ),
    arrayBufferFromBytes(
      zenithMembershipCredentialTranscript(credentialPayload(credential)),
    ),
  )
  if (!valid) throw new Error('membership credential signature is invalid')
  return credential
}

export function normalizeZenithMembershipIssuerUrl(value: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('Zenith membership issuer URL is required')
  }
  const url = new URL(value)
  const loopback = LOOPBACK_HOSTS.has(url.hostname)
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('Zenith membership issuer URL must use HTTPS except on loopback')
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('Zenith membership issuer URL must not contain credentials, query, or fragment')
  }
  if (url.pathname !== '/' && url.pathname !== '') {
    throw new Error('Zenith membership issuer URL must be an origin without a path')
  }
  return url.origin
}

export async function issueZenithMembership(
  input: IssueZenithMembershipInput,
): Promise<ZenithMembershipCredentialV3> {
  const issuerUrl = normalizeZenithMembershipIssuerUrl(input.issuerUrl)
  bytesFromHex32(input.ownerPublicKey, 'Member Key')
  bytesFromBase64url64(input.signature, 'membership request signature')
  validateZenithTrustPolicy(input.trustPolicy)
  const request: ZenithMembershipIssuanceRequestV3 = {
    schema: ZENITH_MEMBERSHIP_REQUEST_SCHEMA,
    version: ZENITH_MEMBERSHIP_VERSION,
    ownerPublicKey: input.ownerPublicKey,
    signatureSuite: 'Ed25519',
    signature: input.signature,
  }
  const response = await (input.fetchImpl ?? fetch)(
    `${issuerUrl}${ZENITH_MEMBERSHIP_ENDPOINT_PATH}`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    },
  )
  if (!response.ok) {
    throw new Error(`Zenith membership issuer rejected membership request (${response.status})`)
  }
  if (!(response.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) {
    throw new Error('Zenith membership issuer response must use application/json')
  }
  const text = await response.text()
  if (text.length === 0 || text.length > 8192) {
    throw new Error('Zenith membership issuer response size is invalid')
  }
  let value: unknown
  try {
    value = JSON.parse(text) as unknown
  } catch {
    throw new Error('Zenith membership issuer response is not valid JSON')
  }
  return verifyZenithMembershipCredential(value, input.trustPolicy, input.ownerPublicKey)
}
