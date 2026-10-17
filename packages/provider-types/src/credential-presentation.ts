// Vendored shared contract from bananawalnut/castalia-wallet-auth
// Source: 7ab187d5c7d1de0d8058132021eb9ec726bfa0db src/presentation.ts (MIT). Keep synchronized with that review candidate.
/** Application-neutral credential-bound presentations. Signatures require custody/issuer verification. */
export const CREDENTIAL_SIGNATURE_DOMAIN = 'castalia.request-credential.v1/signature\0'
export const PRESENTATION_SIGNATURE_DOMAIN = 'castalia.credential-presentation.v2/signature\0'
export const PRESENTATION_CAPABILITY = 'credential_presentation_v2' as const
export const PRESENTATION_LIMITS = { requestBytes: 131072, envelopeBytes: 262144, statements: 144, statementBytes: 512, preparationSeconds: 120, presentationSeconds: 60 } as const

export type PresentationCaller = { kind: 'browser' | 'terminal'; id: string }
export type PresentationDisclosure = { title: string; statements: string[] }
export type RequestCredentialClaims = {
  schema: 'castalia.request-credential.v1'
  issuer: string
  key_id: string
  holder_public_key: string
  audience: string
  caller: PresentationCaller
  request_digest_sha256: string
  disclosure_digest_sha256: string
  policy_digest_sha256: string
  nonce: string
  issued_at: number
  expires_at: number
}
export type RequestCredential = { claims: RequestCredentialClaims; signature: string }
export type CredentialPresentationRequestV2 = {
  schema: 'castalia.credential-presentation-request.v2'
  request_bytes_base64: string
  disclosure: PresentationDisclosure
  credential: RequestCredential
}
export type CredentialPresentationV2 = {
  schema: 'castalia.credential-presentation.v2'
  holder_public_key: string
  issuer: string
  key_id: string
  audience: string
  caller: PresentationCaller
  request_digest_sha256: string
  credential_digest_sha256: string
  disclosure_digest_sha256: string
  nonce: string
  issued_at: number
  expires_at: number
  signature: string
}
export type PresentationTrustPin = { issuer: string; key_id: string; public_key: string; audience: string; callers: PresentationCaller[] }
export type PresentationTrustConfig = { schema: 'castalia.wallet-presentation-trust.v1'; caller: PresentationCaller; pins: PresentationTrustPin[] }
export type CredentialPresentationResultV2 =
  | { state: 'approved'; presentation: CredentialPresentationV2 }
  | { state: 'denied' | 'unavailable'; reason: string }
export type CredentialPresentationProvider = {
  getCapabilities(): Promise<readonly string[]>
  presentCredential(request: CredentialPresentationRequestV2): Promise<CredentialPresentationResultV2>
}

/** Fixed-shape wire values use ASCII field names and safe integer times; arbitrary JSON signing is not an API. */
export function canonicalPresentationJson(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'string') { scalarString(value); return JSON.stringify(value) }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value)
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) if (!Object.hasOwn(value, i)) throw new Error('sparse_array')
    return '[' + value.map(canonicalPresentationJson).join(',') + ']'
  }
  if (typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(key => {
      if (!/^[a-z][a-z0-9_]*$/.test(key)) throw new Error('invalid_field_name')
      return JSON.stringify(key) + ':' + canonicalPresentationJson((value as Record<string, unknown>)[key])
    }).join(',') + '}'
  }
  throw new Error('invalid_canonical_value')
}
function scalarString(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const n = value.charCodeAt(i)
    if (n >= 0xd800 && n <= 0xdbff) { const next = value.charCodeAt(++i); if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('invalid_unicode') }
    else if (n >= 0xdc00 && n <= 0xdfff) throw new Error('invalid_unicode')
  }
}
function byteLength(value: string): number { scalarString(value); let n = 0; for (const c of value) { const p = c.codePointAt(0)!; n += p < 128 ? 1 : p < 2048 ? 2 : p < 65536 ? 3 : 4 } return n }
function shape(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw new Error('invalid_shape')
}
function text(value: unknown, max: number, ascii = false): asserts value is string {
  if (typeof value !== 'string' || byteLength(value) < 1 || byteLength(value) > max || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/.test(value) || ascii && !/^[\x20-\x7e]+$/.test(value)) throw new Error('invalid_text')
}
function hex(value: unknown, bytes: number): void { if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) throw new Error('invalid_hex') }
function caller(value: unknown): void {
  shape(value, ['kind', 'id']); text(value.id, 200, true)
  if (!['browser', 'terminal'].includes(value.kind as string)) throw new Error('invalid_caller')
  // Exact canonical browser-origin validation is mandatory in custody and authority; no URL global is needed by this types package.
}
function interval(value: Record<string, unknown>, max: number, now: number): void {
  if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(value.issued_at) || !Number.isSafeInteger(value.expires_at) || (value.issued_at as number) < 0 || (value.issued_at as number) > now || (value.expires_at as number) <= now || (value.expires_at as number) - (value.issued_at as number) > max) throw new Error('invalid_validity')
}
const CLAIM_KEYS = ['schema','issuer','key_id','holder_public_key','audience','caller','request_digest_sha256','disclosure_digest_sha256','policy_digest_sha256','nonce','issued_at','expires_at']
const PRESENTATION_KEYS = ['schema','holder_public_key','issuer','key_id','audience','caller','request_digest_sha256','credential_digest_sha256','disclosure_digest_sha256','nonce','issued_at','expires_at','signature']
/** Structural/time validation only. This does not verify signatures, digests, issuer trust or authority. */
export function assertPresentationRequest(value: unknown, now: number): asserts value is CredentialPresentationRequestV2 {
  shape(value, ['schema','request_bytes_base64','disclosure','credential'])
  if (value.schema !== 'castalia.credential-presentation-request.v2') throw new Error('unsupported_version')
  const bytes = value.request_bytes_base64
  if (typeof bytes !== 'string' || bytes.length === 0 || bytes.length > 174764 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(bytes)) throw new Error('invalid_request_bytes')
  const decodedLength = bytes.length / 4 * 3 - (bytes.endsWith('==') ? 2 : bytes.endsWith('=') ? 1 : 0)
  if (decodedLength > PRESENTATION_LIMITS.requestBytes) throw new Error('request_too_large')
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  if (bytes.endsWith('==') && (alphabet.indexOf(bytes[bytes.length - 3]) & 15) !== 0 || bytes.endsWith('=') && !bytes.endsWith('==') && (alphabet.indexOf(bytes[bytes.length - 2]) & 3) !== 0) throw new Error('noncanonical_base64')
  shape(value.disclosure, ['title','statements']); text(value.disclosure.title, 160)
  const statements = value.disclosure.statements
  if (!Array.isArray(statements) || statements.length < 1 || statements.length > PRESENTATION_LIMITS.statements) throw new Error('invalid_disclosure')
  for (const statement of statements) text(statement, PRESENTATION_LIMITS.statementBytes)
  shape(value.credential, ['claims','signature']); hex(value.credential.signature, 64)
  const c = value.credential.claims; shape(c, CLAIM_KEYS)
  if (c.schema !== 'castalia.request-credential.v1') throw new Error('unsupported_credential')
  for (const key of ['issuer','key_id','audience']) text(c[key], 200, true)
  for (const key of ['holder_public_key','request_digest_sha256','disclosure_digest_sha256','policy_digest_sha256']) hex(c[key], 32)
  hex(c.nonce, 16); caller(c.caller); interval(c, 120, now)
  if (byteLength(canonicalPresentationJson(value)) > PRESENTATION_LIMITS.envelopeBytes) throw new Error('request_too_large')
}
/** Structural/time validation only; verify the fixed-domain signature independently. */
export function assertCredentialPresentation(value: unknown, now: number): asserts value is CredentialPresentationV2 {
  shape(value, PRESENTATION_KEYS)
  if (value.schema !== 'castalia.credential-presentation.v2') throw new Error('unsupported_version')
  for (const key of ['issuer','key_id','audience']) text(value[key], 200, true)
  for (const key of ['holder_public_key','request_digest_sha256','credential_digest_sha256','disclosure_digest_sha256']) hex(value[key], 32)
  hex(value.nonce, 16); hex(value.signature, 64); caller(value.caller); interval(value, 60, now)
}
export function credentialTranscript(claims: RequestCredentialClaims): string { return CREDENTIAL_SIGNATURE_DOMAIN + canonicalPresentationJson(claims) }
export function presentationTranscript(presentation: CredentialPresentationV2): string { const { signature: _signature, ...unsigned } = presentation; return PRESENTATION_SIGNATURE_DOMAIN + canonicalPresentationJson(unsigned) }
export async function presentCredentialWithWallet(provider: CredentialPresentationProvider, request: CredentialPresentationRequestV2): Promise<CredentialPresentationResultV2> {
  if (!(await provider.getCapabilities()).includes(PRESENTATION_CAPABILITY)) return { state: 'unavailable', reason: 'unsupported_version' }
  const now = Math.floor(Date.now() / 1000)
  assertPresentationRequest(request, now)
  const result: unknown = await provider.presentCredential(request)
  if (!result || typeof result !== 'object' || !('state' in result)) throw new Error('invalid_provider_result')
  const fields = result as Record<string, unknown>
  if (fields.state === 'approved') {
    shape(fields, ['state', 'presentation'])
    assertCredentialPresentation(fields.presentation, Math.floor(Date.now() / 1000))
    const p = fields.presentation, c = request.credential.claims
    for (const key of ['holder_public_key','issuer','key_id','audience','request_digest_sha256','disclosure_digest_sha256'] as const) {
      if (p[key] !== c[key]) throw new Error('presentation_binding_mismatch')
    }
    if (canonicalPresentationJson(p.caller) !== canonicalPresentationJson(c.caller) || p.issued_at < c.issued_at || p.expires_at > c.expires_at) throw new Error('presentation_binding_mismatch')
    return {state:'approved',presentation:p}
  }
  shape(fields, ['state','reason'])
  if (fields.state !== 'denied' && fields.state !== 'unavailable') throw new Error('invalid_provider_result')
  text(fields.reason, 200, true)
  return {state:fields.state,reason:fields.reason}
}
