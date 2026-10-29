import { createHolderGrantsStore } from "./holder-grants-store.js"
import { createHolderSessionExchange } from './holder-session-exchange.js'
import { createWalletIdentitiesStore } from './wallet-identities-store.js'
import { initSync, WasmWallet, servicePresentationContext } from './generated/castalia-wallet-core/bindings.js'
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
export function prepareReadAccess(challenge:unknown,origin:string,installation:string,pins:unknown,binding?:unknown) {
  const context = binding ? JSON.parse(servicePresentationContext(JSON.stringify(pins),JSON.stringify({kind:"browser",id:origin}),JSON.stringify(binding),String(Math.floor(Date.now()/1000)))) : null
  const receiver = context?.caller.id ?? origin
  if(context) pins=context.pins
  const wallet=core
  const invoke=<T>(operation:()=>T):T=>{try{return operation()}catch(error){
    const allowed=['issuer_setup_required','invalid_read_policy','read_approval_expired',
      'read_context_changed','read_access_required','read_access_expired','wallet_locked']
    throw new Error(typeof error==='string'&&allowed.includes(error)?error:'read_access_failed')
  }}
  const handle=invoke(()=>wallet.prepareReadAccess(JSON.stringify(challenge),installation,
    JSON.stringify(pins),JSON.stringify({kind:'browser',id:receiver}),String(Math.floor(Date.now()/1000))))
  let disposed=false
  return {summary:()=>invoke(()=>JSON.parse(handle.summary())),
    approve:()=>invoke(()=>JSON.parse(wallet.approveReadAccess(handle,String(Math.floor(Date.now()/1000))))),
    accept:(credential:unknown)=>invoke(()=>JSON.parse(wallet.acceptReadCredential(handle,JSON.stringify(credential),String(Math.floor(Date.now()/1000))))),
    present:(call:unknown,caller:string)=>invoke(()=>JSON.parse(wallet.presentReadCall(handle,JSON.stringify(call),receiver,String(Math.floor(Date.now()/1000))))),
    dispose:()=>{if(disposed)return;disposed=true;handle.dispose();handle.free()},
  }
}

/** One-shot generic access-request consent, never a credential connection. */
export function prepareAccessRequest(challenge: unknown, origin: string, installation: string, pins: unknown,binding?:unknown) {
  const context = binding ? JSON.parse(servicePresentationContext(JSON.stringify(pins),JSON.stringify({kind:"browser",id:origin}),JSON.stringify(binding),String(Math.floor(Date.now()/1000)))) : null
  if(context) pins=context.pins
  const receiver = context?.caller.id ?? origin
  const invoke = <T>(operation: () => T): T => {
    try { return operation() } catch (error) {
      const allowed = ['wallet_locked', 'issuer_setup_required', 'invalid_access_request',
        'access_context_changed', 'access_approval_expired', 'access_approval_unavailable']
      throw new Error(typeof error === 'string' && allowed.includes(error) ? error : 'access_request_failed')
    }
  }
  const handle = invoke(() => core.prepareAccessRequest(JSON.stringify(challenge), installation,
    JSON.stringify(pins), JSON.stringify({ kind: 'browser', id: receiver }), String(Math.floor(Date.now() / 1000))))
  let disposed = false
  return {
    summary: () => invoke(() => JSON.parse(handle.summary())),
    approve: () => invoke(() => JSON.parse(core.approveAccessRequest(handle, String(Math.floor(Date.now() / 1000))))),
    dispose: () => { if (disposed) return; disposed = true; handle.dispose(); handle.free() },
  }
}

/** Descriptor portability is private to the Wallet UI, never a provider method. */
export const walletIdentities = createWalletIdentitiesStore({
  state:()=>custodyState.getState(),epoch:custodyEpoch,now:()=>Date.now(),storage,
  chainAccounts:()=>JSON.parse(hybridCore.chainAccounts()),
  validateContents:raw=>core.validateCastawayDescriptors(raw),
  validate:raw=>core.validateWalletIdentities(raw),
  merge:(current,incoming)=>core.mergeWalletIdentities(current,incoming),
  seal:raw=>core.sealIdentitySection(raw),
  open:raw=>core.openIdentitySection(encoder.encode(raw)),
  importFile:(raw,password)=>core.importCastaway(encoder.encode(raw),password),
  exportFile:(raw,password,now)=>core.exportCastaway(raw,password,BigInt(now)),
})
subscribeCustodyChanges(()=>{walletIdentities.cancel();void chrome.runtime.sendMessage({type:'WALLET_IDENTITIES_INVALIDATED'}).catch(()=>{})})

export function holderGrantStore(pins:()=>Promise<unknown>) {
 return createHolderGrantsStore({storage,owner:()=>core.publicKey(),now:()=>Math.floor(Date.now()/1000),
 seal:raw=>core.sealIdentitySection(raw),open:raw=>core.openIdentitySection(encoder.encode(raw)),
 validateBackup:raw=>(core as any).validateHolderGrantBackup(raw),
 review:async(grant,origin,installation)=>JSON.parse((core as any).reviewHolderGrant(JSON.stringify(grant),JSON.stringify(await pins()),JSON.stringify({kind:'browser',id:origin}),installation,String(Math.floor(Date.now()/1000)))),
 reviewDerivation:(stored,permissions,installation,expires)=>JSON.parse((core as any).reviewHolderDerivation(JSON.stringify(stored),JSON.stringify(permissions),installation,String(Math.floor(Date.now()/1000)),String(expires))),
 derive:(stored,permissions,installation,expires)=>JSON.parse((core as any).deriveHolderCredential(JSON.stringify(stored),JSON.stringify(permissions),installation,String(Math.floor(Date.now()/1000)),String(expires))),
 present:(stored,credential,call)=>JSON.parse((core as any).presentHolderCredential(JSON.stringify(stored),JSON.stringify(credential),JSON.stringify(call),String(Math.floor(Date.now()/1000)))),
 })
}

/** Qualified bridge; each issuer must independently enable the matched receiver. */
export const HOLDER_SESSION_EXCHANGE_QUALIFIED=true
export function holderSessionExchangeAvailable(){return HOLDER_SESSION_EXCHANGE_QUALIFIED&&['reviewHolderSessionAuthorization','approveHolderSessionAuthorization','verifyHolderSessionCredential'].every(name=>typeof (core as any)[name]==='function')}
export function holderSessionExchange(pins:()=>Promise<unknown>,grants:ReturnType<typeof holderGrantStore>) {
 const typed=core as any
 if(!['reviewHolderSessionAuthorization','approveHolderSessionAuthorization','verifyHolderSessionCredential'].every(name=>typeof typed[name]==='function'))return undefined
 const invoke=(f:()=>string)=>{try{return JSON.parse(f())}catch(error){
  const code=typeof error==='string'?error:error instanceof Error?error.message:''
  const allowed=['wallet_locked','issuer_setup_required','invalid_holder_session','invalid_clock','grant_storage_changed']
  throw Error(allowed.includes(code)?code:'holder_session_failed')
 }}
 return createHolderSessionExchange({grants,now:()=>Math.floor(Date.now()/1000),fetchImpl:fetch,
  randomId:()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join(''),
  audience:async(pin:any,origin,audience)=>{
   const trusted=await pins()
   return Array.isArray(trusted)&&trusted.some(p=>p.issuer===pin.issuer&&p.key_id===pin.key_id&&p.public_key===pin.public_key&&p.audience===audience&&p.callers?.some((c:any)=>c.kind==='browser'&&c.id===origin))
  },
  route:async(binding:any,pin:any,origin,now)=>{
   if(binding===undefined)return '' // Only the fixed root protocol on an approved HTTPS profile.
   const trusted=await pins()
   invoke(()=>servicePresentationContext(JSON.stringify(trusted),JSON.stringify({kind:'browser',id:origin}),JSON.stringify(binding),String(now)))
   if(binding.claims?.service!==pin.service||binding.claims?.issuer!==pin.issuer||binding.claims?.key_id!==pin.key_id||binding.claims?.origin!==origin)throw Error('invalid_holder_session')
   return binding.claims.prefix
  },
  review:(stored,challenge,origin,audience,installation,now)=>invoke(()=>typed.reviewHolderSessionAuthorization(JSON.stringify(stored),JSON.stringify(challenge),origin,audience,installation,String(now))),
  approve:(stored,challenge,signature,origin,audience,installation,now)=>invoke(()=>typed.approveHolderSessionAuthorization(JSON.stringify(stored),JSON.stringify(challenge),signature,origin,audience,installation,String(now))),
  verify:(pin,credential,challenge,now)=>invoke(()=>typed.verifyHolderSessionCredential(JSON.stringify(pin),JSON.stringify(credential),JSON.stringify(challenge),String(now))),
 })
}
