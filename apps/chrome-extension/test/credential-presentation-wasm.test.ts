import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createPrivateKey, createPublicKey, sign, verify, createHash } from 'node:crypto'
import test from 'node:test'
import { initSync, WasmWallet } from '../src/generated/castalia-wallet-core/bindings.js'
import { CASTALIA_WALLET_CORE_WASM } from '../src/generated/castalia-wallet-core/wasm-bytes.js'

initSync({ module: CASTALIA_WALLET_CORE_WASM })
const encoder = new TextEncoder()
const custody = JSON.parse(readFileSync(new URL('../../../docs/contracts/castalia-wallet-custody-v1.vector.json', import.meta.url), 'utf8'))
const vector = JSON.parse(readFileSync(new URL('../../../docs/vectors/credential-presentation-v2.json', import.meta.url), 'utf8'))
const issuer = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(vector.issuer_seed_hex, 'hex')]), format: 'der', type: 'pkcs8' })
function canonical(value: any): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`
}
function opened() { const core = new WasmWallet(); core.unlock(encoder.encode(JSON.stringify(custody.container)), custody.inputs.passphraseUnicode); return core }
function input(core: WasmWallet) {
  const request = structuredClone(vector.request)
  const trust = structuredClone(vector.trust_config)
  const caller = { kind: 'browser', id: 'https://fixture.example' }
  trust.caller = caller; trust.pins[0].callers = [caller]
  request.credential.claims.caller = caller
  request.credential.claims.holder_public_key = core.publicKey()
  resign(request)
  return { request, pins: JSON.stringify(trust.pins), caller: JSON.stringify(caller) }
}
function resign(request: any) {
  request.credential.claims.disclosure_digest_sha256 = createHash('sha256').update(canonical(request.disclosure)).digest('hex')
  request.credential.signature = sign(null, Buffer.concat([Buffer.from('castalia.request-credential.v1/signature\0'), Buffer.from(canonical(request.credential.claims))]), issuer).toString('hex')
}
function prepare(core: WasmWallet, value = input(core), now = '1800000000') {
  return core.prepareCredentialPresentation(encoder.encode(JSON.stringify(value.request)), value.pins, value.caller, now)
}
test('actual WASM returns a verified generic disclosure and signs fresh credential-bound bytes after approval', () => {
  const core = opened()
  try {
    const value = input(core)
    const raw = encoder.encode(JSON.stringify(value.request))
    const pending = core.prepareCredentialPresentation(raw, value.pins, value.caller, '1800000000')
    raw.fill(0)
    assert.equal(new TextDecoder().decode(pending.canonicalRequest()), canonical(value.request))
    const copy = pending.canonicalRequest(); copy.fill(0)
    assert.equal(new TextDecoder().decode(pending.canonicalRequest()), canonical(value.request))
    const summary = JSON.parse(pending.summary())
    assert.deepEqual(summary.disclosure, value.request.disclosure)
    assert.equal(summary.issuer, 'fixture-issuer')
    assert.equal(summary.expires_at, 1800000120)
    const result = JSON.parse(core.approveCredentialPresentation(pending, '1800000090'))
    assert.equal(result.issued_at, 1800000090); assert.equal(result.expires_at, 1800000120)
    assert.equal(result.request_digest_sha256, value.request.credential.claims.request_digest_sha256)
    const signature = Buffer.from(result.signature, 'hex'); delete result.signature
    const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(core.publicKey(), 'hex')]), format: 'der', type: 'spki' })
    assert.equal(verify(null, Buffer.concat([Buffer.from('castalia.credential-presentation.v2/signature\0'), Buffer.from(canonical(result))]), key, signature), true)
    assert.throws(() => core.approveCredentialPresentation(pending, '1800000091'))
    pending.free()
  } finally { core.lock(); core.free() }
})
test('actual WASM rejects credential, trust, disclosure, nested duplicates and unsafe clocks', () => {
  const core = opened()
  try {
    const value = input(core)
    assert.throws(() => core.prepareCredentialPresentation(encoder.encode(JSON.stringify(value.request)), '[]', value.caller, '1800000000'))
    const duplicate = JSON.stringify(value.request).replace('"issuer":"fixture-issuer"', '"issuer":"other","issuer":"fixture-issuer"')
    assert.throws(() => core.prepareCredentialPresentation(encoder.encode(duplicate), value.pins, value.caller, '1800000000'))
    for (const invalid of ['-1', '1.0', '1e3', '01', '9007199254740992']) assert.throws(() => prepare(core, value, invalid))
    for (const bad of ['\u001b', '\u0085', '\u061c', '\u200e', '\u202e', '\u2066']) {
      const changed = input(core); changed.request.disclosure.title = `Misleading${bad}title`; resign(changed.request)
      assert.throws(() => prepare(core, changed))
    }
    const bad = input(core); bad.request.credential.signature = '00'.repeat(64)
    assert.throws(() => prepare(core, bad))
  } finally { core.lock(); core.free() }
})
test('actual WASM preparations are single-use and bound to lock epoch, instance and approval deadline', () => {
  const first = opened(); const second = opened()
  try {
    const foreign = prepare(first)
    assert.throws(() => second.approveCredentialPresentation(foreign, '1800000001'))
    assert.throws(() => first.approveCredentialPresentation(foreign, '1800000001')); foreign.free()
    const stale = prepare(first)
    first.lock(); first.unlock(encoder.encode(JSON.stringify(custody.container)), custody.inputs.passphraseUnicode)
    assert.throws(() => first.approveCredentialPresentation(stale, '1800000001')); stale.free()
    for (const now of ['1799999999', '1800000120']) {
      const stale = prepare(first)
      assert.throws(() => first.approveCredentialPresentation(stale, now))
      assert.throws(() => first.approveCredentialPresentation(stale, '1800000001')); stale.free()
    }
    const disposed = prepare(first); disposed.dispose()
    assert.throws(() => first.approveCredentialPresentation(disposed, '1800000001')); disposed.free()
  } finally { first.lock(); first.free(); second.lock(); second.free() }
})
