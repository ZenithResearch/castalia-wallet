import { blake3 } from '@noble/hashes/blake3.js'

const HEX32 = /^[0-9a-f]{64}$/
const B64URL16 = /^[A-Za-z0-9_-]{22}$/
const B64URL64 = /^[A-Za-z0-9_-]{86}$/
const MAX_SAFE = Number.MAX_SAFE_INTEGER
const APPLICATION_DOMAIN = 'castalia/member-application/v1\0'
const ENROLLMENT_DOMAIN = 'castalia/wallet-membership-enrollment/v2\0'
const APPLICATION_KEYS = ['factoryId','programId','applicantOfficialDreggCellId','ownerPublicKey','applicationKind','applicationVersion','applicationNonce','membershipClass','jurisdictionCode','applicationFlags','createdAt'] as const
const CHALLENGE_KEYS = ['version','challengeId','nonce','origin','audience','operation','ownerPublicKey','applicationCommitment','signatureSuite','issuedAt','expiresAt'] as const
const PRESENTATION_KEYS = ['schema','ownerPublicKey','challenge','signatureSuite','signature'] as const

export type CastaliaMemberApplicationV1 = {
  factoryId: string; programId: string; applicantOfficialDreggCellId: string; ownerPublicKey: string
  applicationKind: number; applicationVersion: number; applicationNonce: number; membershipClass: number
  jurisdictionCode: number; applicationFlags: number; createdAt: number
}
export type MembershipEnrollmentChallengeV2 = {
  version: 2; challengeId: string; nonce: string; origin: string; audience: string
  operation: 'castalia.membership.enroll'; ownerPublicKey: string; applicationCommitment: string
  signatureSuite: 1; issuedAt: number; expiresAt: number
}
export type MembershipPresentationV2 = {
  schema: 'castalia.wallet-membership-presentation.v2'; ownerPublicKey: string
  challenge: MembershipEnrollmentChallengeV2; signatureSuite: 'Ed25519'; signature: string
}
export type MembershipVerificationContext = { expectedOrigin: string; expectedAudience: string; nowMs: number }

function bytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0
  for (const part of parts) { out.set(part, at); at += part.length }
  return out
}
function utf8(value: string): Uint8Array { return new TextEncoder().encode(value) }
function toHex(value: Uint8Array): string { return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('') }
function decodeBase64url(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)
  const binary = atob(padded); return Uint8Array.from(binary, char => char.charCodeAt(0))
}
function encodeBase64url(value: Uint8Array): string {
  let binary = ''; for (const byte of value) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function hex32(value: unknown, name: string): Uint8Array {
  if (typeof value !== 'string' || !HEX32.test(value)) throw new Error(`${name} must be lowercase hex32`)
  return Uint8Array.from(value.match(/../g)!, x => Number.parseInt(x, 16))
}
function b64url(value: unknown, length: number, pattern: RegExp, name: string): Uint8Array {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`${name} must be canonical base64url`)
  const decoded = decodeBase64url(value)
  if (decoded.length !== length || encodeBase64url(decoded) !== value) throw new Error(`${name} encoding invalid`)
  return decoded
}
function u64(value: unknown, name: string): Uint8Array {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > MAX_SAFE) throw new Error(`${name} must be a safe unsigned integer`)
  const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(value), true); return out
}
function framed(value: Uint8Array): Uint8Array {
  if (value.length > 0xffff_ffff) throw new Error('field too large')
  const length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, value.length, true)
  return bytes(length, value)
}
function exactKeys(value: unknown, keys: readonly string[], name: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must be an object`)
  const actual = Object.keys(value as object).sort(); const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) throw new Error(`${name} fields invalid`)
}
function canonicalOrigin(value: unknown): string {
  if (typeof value !== 'string' || /[\u0000-\u0020\u007f]/.test(value)) throw new Error('origin invalid')
  let url: URL; try { url = new URL(value) } catch { throw new Error('origin invalid') }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) throw new Error('origin invalid')
  if (url.hostname.endsWith('.')) throw new Error('origin invalid')
  const canonical = url.origin
  if (value !== canonical) throw new Error('origin must already be canonical')
  return canonical
}
function validateApplication(input: unknown): CastaliaMemberApplicationV1 {
  exactKeys(input, APPLICATION_KEYS, 'application'); const a = input as CastaliaMemberApplicationV1
  for (const key of APPLICATION_KEYS.slice(0, 4)) hex32(a[key], key)
  for (const key of APPLICATION_KEYS.slice(4)) u64(a[key], key)
  if (a.applicationKind !== 7 || a.applicationVersion !== 1 || a.applicationNonce < 1 || ![1,2].includes(a.membershipClass) || a.applicationFlags !== 0) throw new Error('application policy invalid')
  return a
}
function validateChallenge(input: unknown): MembershipEnrollmentChallengeV2 {
  exactKeys(input, CHALLENGE_KEYS, 'challenge'); const c = input as MembershipEnrollmentChallengeV2
  if (c.version !== 2 || c.operation !== 'castalia.membership.enroll' || c.signatureSuite !== 1) throw new Error('challenge literals invalid')
  b64url(c.challengeId, 16, B64URL16, 'challengeId'); b64url(c.nonce, 16, B64URL16, 'nonce')
  canonicalOrigin(c.origin); if (typeof c.audience !== 'string' || !c.audience || c.audience !== c.audience.normalize('NFC')) throw new Error('audience invalid')
  hex32(c.ownerPublicKey, 'ownerPublicKey'); hex32(c.applicationCommitment, 'applicationCommitment')
  u64(c.issuedAt, 'issuedAt'); u64(c.expiresAt, 'expiresAt')
  if (c.expiresAt <= c.issuedAt || c.expiresAt - c.issuedAt > 300_000) throw new Error('challenge TTL invalid')
  return c
}

export function canonicalMemberApplicationBytes(input: unknown): Uint8Array {
  const a = validateApplication(input)
  return bytes(utf8(APPLICATION_DOMAIN), hex32(a.factoryId,'factoryId'), hex32(a.programId,'programId'), hex32(a.applicantOfficialDreggCellId,'applicantOfficialDreggCellId'), hex32(a.ownerPublicKey,'ownerPublicKey'), u64(a.applicationKind,'applicationKind'), u64(a.applicationVersion,'applicationVersion'), u64(a.applicationNonce,'applicationNonce'), u64(a.membershipClass,'membershipClass'), u64(a.jurisdictionCode,'jurisdictionCode'), u64(a.applicationFlags,'applicationFlags'), u64(a.createdAt,'createdAt'))
}
export function commitMemberApplication(input: unknown): string { return toHex(blake3(canonicalMemberApplicationBytes(input))) }
export function canonicalMembershipEnrollmentChallengeBytes(challengeInput: unknown, applicationInput: unknown): Uint8Array {
  const c = validateChallenge(challengeInput); const a = validateApplication(applicationInput)
  if (c.ownerPublicKey !== a.ownerPublicKey || c.applicationCommitment !== commitMemberApplication(a)) throw new Error('challenge application mismatch')
  return bytes(utf8(ENROLLMENT_DOMAIN), u64(c.version,'version'), framed(b64url(c.challengeId,16,B64URL16,'challengeId')), framed(b64url(c.nonce,16,B64URL16,'nonce')), framed(utf8(c.origin)), framed(utf8(c.audience)), framed(utf8(c.operation)), framed(hex32(c.ownerPublicKey,'ownerPublicKey')), framed(hex32(c.applicationCommitment,'applicationCommitment')), u64(c.signatureSuite,'signatureSuite'), u64(c.issuedAt,'issuedAt'), u64(c.expiresAt,'expiresAt'))
}

function rejectDuplicateKeys(encoded: string): void {
  const stack: Array<Set<string> | null> = []; let i = 0
  const ws = () => { while (/\s/.test(encoded[i] ?? '')) i++ }
  const stringToken = (): string => { const start = i++; let escaped = false; while (i < encoded.length) { const ch = encoded[i++]; if (escaped) escaped = false; else if (ch === '\\') escaped = true; else if (ch === '"') return JSON.parse(encoded.slice(start, i)) } throw new Error('invalid JSON') }
  while (i < encoded.length) { ws(); const ch = encoded[i]
    if (ch === '{') { stack.push(new Set()); i++; continue }
    if (ch === '[') { stack.push(null); i++; continue }
    if (ch === '}' || ch === ']') { stack.pop(); i++; continue }
    if (ch === '"') { const value = stringToken(); ws(); if (encoded[i] === ':' && stack.at(-1) instanceof Set) { const keys = stack.at(-1) as Set<string>; if (keys.has(value)) throw new Error('duplicate field'); keys.add(value) } continue }
    i++
  }
}
export function parseMembershipPresentationV2(encoded: string): MembershipPresentationV2 {
  rejectDuplicateKeys(encoded); const value = JSON.parse(encoded); exactKeys(value, PRESENTATION_KEYS, 'presentation')
  if (value.schema !== 'castalia.wallet-membership-presentation.v2' || value.signatureSuite !== 'Ed25519') throw new Error('presentation literals invalid')
  const challenge = validateChallenge(value.challenge); if (value.ownerPublicKey !== challenge.ownerPublicKey) throw new Error('presentation owner mismatch')
  b64url(value.signature, 64, B64URL64, 'signature')
  return value as MembershipPresentationV2
}
export async function verifyMembershipPresentationV2(presentationInput: unknown, applicationInput: unknown, context: MembershipVerificationContext): Promise<void> {
  exactKeys(presentationInput, PRESENTATION_KEYS, 'presentation'); const p = presentationInput as MembershipPresentationV2
  if (p.schema !== 'castalia.wallet-membership-presentation.v2' || p.signatureSuite !== 'Ed25519') throw new Error('presentation literals invalid')
  const c = validateChallenge(p.challenge); if (p.ownerPublicKey !== c.ownerPublicKey) throw new Error('owner mismatch')
  if (c.origin !== context.expectedOrigin || c.audience !== context.expectedAudience) throw new Error('trusted context mismatch')
  if (c.issuedAt > context.nowMs + 5_000 || context.nowMs > c.expiresAt) throw new Error('challenge time invalid')
  const transcript = canonicalMembershipEnrollmentChallengeBytes(c, applicationInput)
  const publicKey = Uint8Array.from(hex32(p.ownerPublicKey,'ownerPublicKey'))
  const signature = Uint8Array.from(b64url(p.signature,64,B64URL64,'signature'))
  const message = Uint8Array.from(transcript)
  const key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify'])
  if (!await crypto.subtle.verify('Ed25519', key, signature, message)) throw new Error('signature invalid')
}
