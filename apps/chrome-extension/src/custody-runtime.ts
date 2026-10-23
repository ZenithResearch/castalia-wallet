import { initSync, WasmWallet } from './generated/castalia-wallet-core/bindings.js'
import { CASTALIA_WALLET_CORE_WASM } from './generated/castalia-wallet-core/wasm-bytes.js'
import { createCustodyStateManager } from './state/custody-state.js'
import { createRecoveryManager } from './recovery.js'

declare const chrome: any

initSync({ module: CASTALIA_WALLET_CORE_WASM })
const core = new WasmWallet()
const encoder = new TextEncoder()
let custodyEpochValue = 0
const custodyEpochValueListeners = new Set<() => void>()
function bumpCustodyEpoch() { custodyEpochValue++; for (const listener of custodyEpochValueListeners) { try { listener() } catch {} } }
export function subscribeCustodyChanges(listener: () => void) { custodyEpochValueListeners.add(listener); return () => { custodyEpochValueListeners.delete(listener) } }
export function custodyEpoch() { return custodyEpochValue }
type HybridWalletCore = WasmWallet & {
  mlDsaPublicKey(): string
  mlDsaPublicKeyCommitment(): string
  chainAccounts(): string
  signDreggPq(message: Uint8Array): Uint8Array
}

type FilesWalletCore = WasmWallet & {
  wrapFilesKey(binding: string, key: Uint8Array): string
  unwrapFilesKey(binding: string, envelope: string): Uint8Array
  signFilesServiceAuthentication(challenge: string, origin: string, kind: string, serviceId: string, nowMs: bigint): Uint8Array
}
const filesCore = core as FilesWalletCore
export const filesCustody = {
  wrap: (binding: string, key: Uint8Array): unknown => JSON.parse(filesCore.wrapFilesKey(binding,key)),
  unwrap: (binding: string, envelope: string): Uint8Array => filesCore.unwrapFilesKey(binding,envelope),
  authenticate: (challenge: string, origin: string, kind: string, serviceId: string, nowMs: number): string => bytesToBase64(filesCore.signFilesServiceAuthentication(challenge,origin,kind,serviceId,BigInt(nowMs))),
}
const hybridCore = core as HybridWalletCore

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function rawEd25519PublicKeyPem(publicKeyHex: string): string {
  const prefix = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
  const raw = Uint8Array.from(publicKeyHex.match(/../g)!.map(byte => Number.parseInt(byte, 16)))
  const encoded = bytesToBase64(Uint8Array.from([...prefix, ...raw]))
  return `-----BEGIN PUBLIC KEY-----\n${encoded.match(/.{1,64}/g)!.join('\n')}\n-----END PUBLIC KEY-----`
}

export function durableSigningIdentity() {
  const publicKeyRawHex = core.publicKey()
  const mlDsa65PublicKey = hybridCore.mlDsaPublicKey()
  const mlDsa65PublicKeyCommitment = hybridCore.mlDsaPublicKeyCommitment()
  return {
    publicKey: rawEd25519PublicKeyPem(publicKeyRawHex),
    publicKeyRawHex,
    dreggHybridIdentity: {
      version: 1 as const,
      signatureSuite: 'Ed25519+ML-DSA-65' as const,
      ed25519PublicKey: publicKeyRawHex,
      mlDsa65PublicKey,
      mlDsa65PublicKeyCommitment,
      derivation: 'dregg.hybrid-from-ed25519-seed.v1' as const,
    },
    signBytes(message: Uint8Array): string {
      return bytesToBase64(core.sign(message))
    },
    signDreggPq(message: Uint8Array): string {
      return bytesToBase64(hybridCore.signDreggPq(message))
    },
  }
}

export function durableChainAccounts(): unknown[] {
  const candidate: unknown = JSON.parse(hybridCore.chainAccounts())
  if (!candidate || typeof candidate !== 'object' || !Array.isArray((candidate as { accounts?: unknown }).accounts)) {
    throw new Error('invalid_wallet_file')
  }
  return structuredClone((candidate as { accounts: unknown[] }).accounts)
}

const storage = {
  get: (key: string) => chrome.storage.local.get(key),
  set: (values: Record<string, unknown>) => chrome.storage.local.set(values),
  remove: (key: string) => chrome.storage.local.remove(key),
}

export const custodyState = createCustodyStateManager(storage, {
  create: (passphrase, createdAt) => { bumpCustodyEpoch(); return core.create(passphrase, BigInt(createdAt)) },
  unlock: (record, passphrase) => { bumpCustodyEpoch(); return core.unlock(encoder.encode(record), passphrase) },
  exportRandomized: passphrase => core.exportRandomized(passphrase),
  lock: () => { bumpCustodyEpoch(); core.lock() },
  publicKey: () => core.publicKey(),
})

export const recovery = createRecoveryManager({
  exportEncrypted: passphrase => custodyState.exportEncrypted(passphrase),
  importEncrypted: (record, passphrase, options) => custodyState.importEncrypted(record, passphrase, options),
})

// Application-neutral custody interface; trusted pins are supplied only by extension configuration.
export function prepareCredentialPresentation(raw: Uint8Array, pins: unknown, caller: {kind:'browser';id:string}) {
  const prepared = (core as any).prepareCredentialPresentation(raw, JSON.stringify(pins), JSON.stringify(caller), String(Math.floor(Date.now()/1000)))
  let disposed=false
  return {
    summary: () => JSON.parse(prepared.summary()),
    approve: () => JSON.parse((core as any).approveCredentialPresentation(prepared,String(Math.floor(Date.now()/1000)))),
    dispose: () => { if(disposed)return;disposed=true;prepared.dispose();prepared.free() },
  }
}

/** Trust changes invalidate all pending custody approvals, independently of provider branding. */
export const invalidateCustodyApprovals = bumpCustodyEpoch
/** Generic read custody shares the same Rust/WASM core and lock epoch. */
export function prepareReadAccess(challenge:unknown,origin:string,installation:string,pins:unknown) {
  const wallet=core
  const invoke=<T>(operation:()=>T):T=>{try{return operation()}catch(error){
    const allowed=['issuer_setup_required','invalid_read_policy','read_approval_expired',
      'read_context_changed','read_access_required','read_access_expired','wallet_locked']
    throw new Error(typeof error==='string'&&allowed.includes(error)?error:'read_access_failed')
  }}
  const handle=invoke(()=>wallet.prepareReadAccess(JSON.stringify(challenge),installation,
    JSON.stringify(pins),JSON.stringify({kind:'browser',id:origin}),String(Math.floor(Date.now()/1000))))
  let disposed=false
  return {summary:()=>invoke(()=>JSON.parse(handle.summary())),
    approve:()=>invoke(()=>JSON.parse(wallet.approveReadAccess(handle,String(Math.floor(Date.now()/1000))))),
    accept:(credential:unknown)=>invoke(()=>JSON.parse(wallet.acceptReadCredential(handle,JSON.stringify(credential),String(Math.floor(Date.now()/1000))))),
    present:(call:unknown,caller:string)=>invoke(()=>JSON.parse(wallet.presentReadCall(handle,JSON.stringify(call),caller,String(Math.floor(Date.now()/1000))))),
    dispose:()=>{if(disposed)return;disposed=true;handle.dispose();handle.free()},
  }
}

/** One-shot generic access-request consent, never a credential connection. */
export function prepareAccessRequest(challenge: unknown, origin: string, installation: string, pins: unknown) {
  const invoke = <T>(operation: () => T): T => {
    try { return operation() } catch (error) {
      const allowed = ['wallet_locked', 'issuer_setup_required', 'invalid_access_request',
        'access_context_changed', 'access_approval_expired', 'access_approval_unavailable']
      throw new Error(typeof error === 'string' && allowed.includes(error) ? error : 'access_request_failed')
    }
  }
  const handle = invoke(() => core.prepareAccessRequest(JSON.stringify(challenge), installation,
    JSON.stringify(pins), JSON.stringify({ kind: 'browser', id: origin }), String(Math.floor(Date.now() / 1000))))
  let disposed = false
  return {
    summary: () => invoke(() => JSON.parse(handle.summary())),
    approve: () => invoke(() => JSON.parse(core.approveAccessRequest(handle, String(Math.floor(Date.now() / 1000))))),
    dispose: () => { if (disposed) return; disposed = true; handle.dispose(); handle.free() },
  }
}
