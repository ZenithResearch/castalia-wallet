const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])
const HEX_32 = /^[0-9a-f]{64}$/
const KEY_ID = /^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/

export const DEFAULT_ZENITH_MEMBERSHIP_ISSUER_URL = 'http://127.0.0.1:3002'
export const FIXTURE_ZENITH_ISSUER_KEY_ID = 'zenith-membership-issuer-fixture-ed25519-1'
export const FIXTURE_ZENITH_ISSUER_PUBLIC_KEY =
  'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'

export function normalizeZenithMembershipIssuerUrl(value) {
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

export function normalizeZenithIssuerKeyId(value) {
  if (typeof value !== 'string' || !KEY_ID.test(value)) {
    throw new Error('Zenith membership issuer key ID is not canonical')
  }
  return value
}

export function normalizeZenithIssuerPublicKey(value) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    throw new Error('Zenith membership issuer public key must be 32-byte lowercase hex')
  }
  return value
}

export function productionZenithMembershipConfig(input) {
  const config = {
    issuerUrl: normalizeZenithMembershipIssuerUrl(input.issuerUrl),
    issuerKeyId: normalizeZenithIssuerKeyId(input.issuerKeyId),
    issuerPublicKey: normalizeZenithIssuerPublicKey(input.issuerPublicKey),
  }
  if (new URL(config.issuerUrl).protocol !== 'https:') {
    throw new Error('production Zenith membership issuer URL must use HTTPS')
  }
  if (
    config.issuerKeyId === FIXTURE_ZENITH_ISSUER_KEY_ID
    || config.issuerPublicKey === FIXTURE_ZENITH_ISSUER_PUBLIC_KEY
  ) {
    throw new Error('production extension must not trust the Zenith test fixture issuer')
  }
  return config
}

export function zenithIssuerHostPermission(value) {
  return `${normalizeZenithMembershipIssuerUrl(value)}/*`
}
