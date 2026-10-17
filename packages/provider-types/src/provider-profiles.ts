import type { PresentationTrustPin } from './credential-presentation.js'

export const PROVIDER_PROFILE_CAPABILITIES = ['provider_profiles_v1', 'connection_v1', 'membership_profiles_v1', 'registration_proposal_v2'] as const
export const PROFILE_LIMITS = { bytes: 65536, profiles: 64, roots: 64, origins: 64, pins: 64, credentials: 256 } as const
export type MembershipRootV1 = { issuerId: string; keyId: string; signatureSuite: 'Ed25519'; publicKey: string }
export type ProviderProfileV1 = {
  schema: 'castalia.provider-profile.v1'
  display_name: string
  origins: string[]
  membership: { protocol: 'castalia.zenith-membership.v3'; issuer_origin: string; roots: MembershipRootV1[] } | null
  presentations: PresentationTrustPin[]
}
export type MembershipProfileSummaryV1 = { profileId: string; revision: number; displayName: string; protocol: 'castalia.zenith-membership.v3'; issuerOrigin: string }
export interface ProviderProfilesProvider {
  getCapabilities(): Promise<readonly string[]>
  requestConnection(): Promise<{ state: 'connected' }>
  proposeProviderProfile(profile: ProviderProfileV1): Promise<{ state: 'approved' | 'denied' }>
  listMembershipProfiles(): Promise<MembershipProfileSummaryV1[]>
  requestMembership(input: { profileId: string }): Promise<unknown>
  getMembershipCredential(input: { profileId: string }): Promise<unknown>
}

function shape(value: unknown, keys: string[]): asserts value is Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join(',') !== keys.sort().join(',')) throw new Error('invalid_profile_shape')
}
function text(value: unknown, max: number): asserts value is string {
  if (typeof value !== 'string' || value.length < 1 || value.length > max || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value)) throw new Error('invalid_profile_text')
  for (let i=0; i<value.length; i++) {
    const n=value.charCodeAt(i)
    if (n>=0xd800 && n<=0xdbff) { const next=value.charCodeAt(++i); if (!(next>=0xdc00 && next<=0xdfff)) throw new Error('invalid_profile_text') }
    else if (n>=0xdc00 && n<=0xdfff) throw new Error('invalid_profile_text')
  }
}
function label(value: unknown): asserts value is string { text(value,200); if(!/^[\x20-\x7e]+$/.test(value)) throw new Error('invalid_profile_label') }
function key(value: unknown) { if(typeof value!=='string'||!/^[a-f0-9]{64}$/.test(value)) throw new Error('invalid_profile_key') }
function list(value: unknown, max: number, min=1): asserts value is any[] {
  if(!Array.isArray(value)||value.length<min||value.length>max) throw new Error('invalid_profile_list')
  for(let i=0;i<value.length;i++) if(!Object.hasOwn(value,i)) throw new Error('invalid_profile_list')
}
export function profileOrigin(value: unknown, allowLoopback=true): string {
  text(value,200)
  // URL is available in supported Node and browser runtimes; no DOM dependency is required by this package.
  const URLConstructor = (globalThis as unknown as { URL: new (s:string) => { origin:string; protocol:string; hostname:string; username:string; password:string } }).URL
  const u=new URLConstructor(value)
  if(u.origin!==value||u.username||u.password||u.hostname.endsWith('.')||u.hostname.includes('*')||!(u.protocol==='https:' || allowLoopback && u.protocol==='http:' && ['localhost','127.0.0.1','[::1]'].includes(u.hostname))) throw new Error('invalid_profile_origin')
  return value
}

/** Parsing a profile establishes neither key ownership nor trust. Only trusted Wallet UI may activate it. */
export function parseProviderProfile(input: unknown): ProviderProfileV1 {
  shape(input,['schema','display_name','origins','membership','presentations'])
  if(input.schema!=='castalia.provider-profile.v1') throw new Error('unsupported_profile_version')
  text(input.display_name,160); list(input.origins,PROFILE_LIMITS.origins)
  const origins=input.origins.map(o=>profileOrigin(o)); if(new Set(origins).size!==origins.length) throw new Error('duplicate_profile_origin')
  if(input.membership!==null) {
    const m=input.membership
    shape(m,['protocol','issuer_origin','roots'])
    if(m.protocol!=='castalia.zenith-membership.v3') throw new Error('unsupported_membership_protocol')
    profileOrigin(m.issuer_origin,false); list(m.roots,PROFILE_LIMITS.roots)
    const seen=new Set<string>()
    for(const r of m.roots) {
      shape(r,['issuerId','keyId','signatureSuite','publicKey']); key(r.publicKey)
      for(const id of [r.issuerId,r.keyId]) if(typeof id!=='string'||!/^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/.test(id)) throw new Error('invalid_membership_root')
      if(r.signatureSuite!=='Ed25519') throw new Error('unsupported_membership_suite')
      const id=r.issuerId+'\0'+r.keyId; if(seen.has(id)) throw new Error('ambiguous_membership_root'); seen.add(id)
    }
  }
  list(input.presentations,PROFILE_LIMITS.pins,0)
  const pins=new Set<string>()
  for(const p of input.presentations) {
    shape(p,['issuer','key_id','public_key','audience','callers']); label(p.issuer); label(p.key_id); label(p.audience); key(p.public_key); list(p.callers,PROFILE_LIMITS.origins)
    const id=JSON.stringify([p.issuer,p.key_id,p.audience]); if(pins.has(id)) throw new Error('ambiguous_presentation_pin'); pins.add(id)
    const callers=new Set<string>()
    for(const c of p.callers) {
      shape(c,['kind','id'])
      if(c.kind!=='browser'||!origins.includes(profileOrigin(c.id))||callers.has(c.id)) throw new Error('invalid_profile_caller')
      callers.add(c.id)
    }
  }
  if(input.membership===null && input.presentations.length===0) throw new Error('empty_profile')
  const encoded=JSON.stringify(input)
  if(encodeURIComponent(encoded).replace(/%[A-F0-9]{2}/g,'x').length>PROFILE_LIMITS.bytes) throw new Error('profile_too_large')
  return JSON.parse(encoded) as ProviderProfileV1
}
/** Canonical configuration bytes for local revision comparison; not a signing transcript. */
export function providerProfileBytes(input: unknown): string {
  function canonical(v:any):string {
    if(v===null||typeof v!=='object') return JSON.stringify(v)
    if(Array.isArray(v)) return '['+v.map(canonical).join(',')+']'
    return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}'
  }
  return canonical(parseProviderProfile(input))
}

/** Additive transport version. Request and result remain the receiver's existing typed registration contract. */
export interface RegistrationProposalProviderV2<Request, Result> {
  getCapabilities(): Promise<readonly string[]>
  requestRegistrationV2(request: Request): Promise<Result>
}
