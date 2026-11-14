import {mergeFeedSections,type FeedSection,type FeedReview} from './wallet-feeds.js'

/** Extension-owned adapter. The Rust core owns identity/schema validation. */
export type WalletIdentityRecord={accountId:string;kind:'matrix'|'nostr'|'github'|'x';label:string;identifier:string;server:string}
export type WalletIdentitySection={schema:'castalia.wallet-identities.v1';version:1;ownerMemberKey:string;authority:'descriptor-only';accounts:WalletIdentityRecord[]}
/** Wallet-private, memory-only source snapshot. Never expose this object on a
 * provider wire. Calls must share the custody FIFO; outside invalidation bumps
 * the epoch or cancels this store. No approval or authority is carried here. */
export type FeedProjectionSource={
  readonly owner:string;readonly epoch:number;readonly revision:number
  copySource():Uint8Array
  consumeCurrent(deliver:(currentSource:Uint8Array)=>boolean):Promise<boolean>
  dispose():void
}
type Dependencies={
  state():Promise<{unlocked:boolean;publicKey:string|null}>;epoch():number;now():number
  storage:{get(key:string):Promise<Record<string,unknown>>;set(values:Record<string,unknown>):Promise<void>}
  chainAccounts():unknown;validateContents(raw:string):string;preflight(raw:string):number
  validate(raw:string):string;merge(current:string,incoming:string):string
  seal(raw:string):string;open(encrypted:string):string
  importFile(raw:string,password:string):string;exportFile(raw:string,password:string,now:number):string
}
type Snapshot={revision:number;contents:any;snapshot:string|null}
const stable=(value:any):string=>JSON.stringify(value&&typeof value==='object'?Array.isArray(value)?value.map((v:any)=>JSON.parse(stable(v))):Object.fromEntries(Object.keys(value).sort().map(k=>[k,JSON.parse(stable(value[k]))])):value)
const empty=(owner:string):WalletIdentitySection=>({schema:'castalia.wallet-identities.v1',version:1,ownerMemberKey:owner,authority:'descriptor-only',accounts:[]})
const bounded=(raw:string)=>{if(typeof raw!=='string'||new TextEncoder().encode(raw).length>1_048_576)throw Error('file_too_large');return raw}
const json=(raw:string)=>JSON.parse(bounded(raw))
function supportedContents(contents:any){
  const version=contents?.version
  if(![1,2,3].includes(version)||contents.schema!==`castalia.castaway-contents.v${version}`||Object.prototype.hasOwnProperty.call(contents.sections??{},'feeds')!==(version===3))throw Error('feed_storage_not_qualified')
  return contents
}
// Rollout gate: default v3 import remains refused until all consumers qualify.
// Development acceptance may temporarily remove this throw, never expose a flag.
function requireFeedImportQualified(contents:any){
  if(contents.version===3)throw Error('feed_storage_not_qualified')
}
export function createWalletIdentitiesStore(d:Dependencies){
  let cancellations=0
  let pending:{token:string;owner:string;epoch:number;cancellation:number;revision:number;snapshot:string|null;expires:number;raw:string;ciphertext:string}|null=null
  const key=(owner:string)=>'castalia-wallet-identities-v1:'+owner
  async function guard(owner?:string,epoch?:number){const s=await d.state();if(!s.unlocked||!s.publicKey||! /^[a-f0-9]{64}$/.test(s.publicKey)||owner&&owner!==s.publicKey||epoch!==undefined&&epoch!==d.epoch())throw Error('wallet_changed_or_locked');return s.publicKey}
  function initial(owner:string){return {schema:'castalia.castaway-contents.v1',version:1,sections:{identity:{schema:'zenith.identity-section.v1',version:1,subject:{type:'Person',memberKey:owner,fields:Object.fromEntries(['displayName','givenName','familyName','headline','biography','website','orcid'].map(k=>[k,{value:'',disclosure:'private'}])),roles:[],affiliations:[],journals:[]},updatedAt:0},chainAccounts:d.chainAccounts()}}}
  function identities(contents:any,owner:string):WalletIdentitySection{return json(d.validate(JSON.stringify(contents.sections.walletIdentities??empty(owner))))}
  function feeds(contents:any):FeedSection|null{return contents.sections.feeds??null}
  function validate(raw:string,owner:string){const contents=supportedContents(json(d.validateContents(bounded(raw))));if(contents.sections.identity.subject.memberKey!==owner)throw Error('wrong_owner');identities(contents,owner);return contents}
  async function load(owner:string):Promise<Snapshot>{
    const saved=(await d.storage.get(key(owner)))[key(owner)] as any
    if(saved===undefined)return {revision:0,contents:initial(owner),snapshot:null}
    if(!saved||Object.keys(saved).sort().join(',')!=='ciphertext,revision,schema'||saved.schema!=='castalia.wallet-identity-storage.v1'||!Number.isSafeInteger(saved.revision)||saved.revision<1||typeof saved.ciphertext!=='string')throw Error('invalid_identity_storage')
    return {revision:saved.revision as number,contents:validate(d.open(saved.ciphertext),owner),snapshot:stable(saved)}
  }
  // Production callers run inside the one custody FIFO. Also fence exact bytes,
  // including a same-revision ciphertext replacement, before its single-key set.
  async function unchanged(owner:string,snapshot:string|null){const current=(await d.storage.get(key(owner)))[key(owner)];if((current===undefined?null:stable(current))!==snapshot)throw Error('identities_changed')}
  // Revocation/permission events can invalidate synchronously outside the FIFO.
  // No await may separate this check from installing a review or starting set.
  function finalFence(epoch:number,cancellation:number){if(d.epoch()!==epoch||cancellations!==cancellation)throw Error('wallet_changed_or_locked')}
  function candidate(contents:any,owner:string){
    const raw=JSON.stringify(validate(JSON.stringify(contents),owner))
    if(contents.version===3)d.preflight(raw)
    return {raw,ciphertext:d.seal(raw)}
  }
  function revisionAfter(revision:number){if(!Number.isSafeInteger(revision+1))throw Error('revision_exhausted');return revision+1}
  return {
    cancel(){cancellations++;pending=null},
    async captureFeedProjectionSource():Promise<FeedProjectionSource>{
      const cancellation=cancellations,owner=await guard(),epoch=d.epoch(),saved=await load(owner)
      const section=feeds(saved.contents)
      if(!section||saved.snapshot===null)throw Error('feed_source_unavailable')
      // This is the exact internally prepared section representation. The
      // independent encrypted-record fence also catches reserialization/reseal
      // and same-revision replacement of the surrounding Wallet record.
      const raw=new TextEncoder().encode(JSON.stringify(section))
      try{await guard(owner,epoch);await unchanged(owner,saved.snapshot);finalFence(epoch,cancellation)}
      catch(error){raw.fill(0);throw error}
      let status:'prepared'|'consuming'|'closed'='prepared'
      const dispose=()=>{status='closed';raw.fill(0)}
      return Object.freeze({owner,epoch,revision:saved.revision,
        copySource(){if(status!=='prepared')throw Error('feed_source_consumed');return raw.slice()},
        async consumeCurrent(deliver:(currentSource:Uint8Array)=>boolean):Promise<boolean>{
          if(status!=='prepared')throw Error('feed_source_consumed')
          status='consuming' // consume before any await or callback validation
          try{
            if(typeof deliver!=='function')throw Error('invalid_feed_delivery')
            await guard(owner,epoch);await unchanged(owner,saved.snapshot)
            finalFence(epoch,cancellation)
            if(status!=='consuming')throw Error('feed_source_consumed')
            // No await between the final fence and this synchronous callback.
            // Non-void typing rejects async callbacks; dynamic values never get
            // awaited or interpreted as successful delivery.
            const current=raw.slice()
            try{const delivered=deliver(current);if(typeof delivered!=='boolean')throw Error('invalid_feed_delivery');return delivered}
            finally{current.fill(0)}
          }finally{dispose()}
        },dispose,
      })
    },
    async read(){const owner=await guard(),epoch=d.epoch(),saved=await load(owner);await guard(owner,epoch);return {revision:saved.revision,identities:identities(saved.contents,owner),feeds:structuredClone(feeds(saved.contents))}},
    async reviewImport(file:string,password:string){
      pending=null
      const cancellation=cancellations
      if(typeof password!=='string'||new TextEncoder().encode(password).length>4096)throw Error('invalid_password')
      const owner=await guard(),epoch=d.epoch(),saved=await load(owner)
      const incoming=validate(d.importFile(bounded(file),password),owner)
      requireFeedImportQualified(incoming)
      const merged=json(d.merge(JSON.stringify(identities(saved.contents,owner)),JSON.stringify(identities(incoming,owner)))) as WalletIdentitySection
      const contents=structuredClone(saved.contents)
      contents.sections.identity=incoming.sections.identity
      for(const field of ['memberships','scopedMemberships']){
        const proofs=[...(contents.sections[field]??[])]
        for(const proof of incoming.sections[field]??[]){const old=proofs.find(p=>p.membershipId===proof.membershipId);if(old&&stable(old)!==stable(proof))throw Error('proof_conflict');if(!old)proofs.push(proof)}
        if(proofs.length)contents.sections[field]=proofs
      }
      const combined=mergeFeedSections(feeds(saved.contents),feeds(incoming))
      if(combined){contents.schema='castalia.castaway-contents.v3';contents.version=3;contents.sections.feeds=combined}
      if(incoming.sections.walletIdentities||saved.contents.sections.walletIdentities){
        if(contents.version!==3){contents.schema='castalia.castaway-contents.v2';contents.version=2}
        contents.sections.walletIdentities=merged
      }
      const prepared=candidate(contents,owner)
      revisionAfter(saved.revision)
      await guard(owner,epoch);await unchanged(owner,saved.snapshot)
      const token=crypto.randomUUID()
      finalFence(epoch,cancellation)
      pending={token,owner,epoch,cancellation,revision:saved.revision,snapshot:saved.snapshot,expires:d.now()+120_000,...prepared}
      const review:FeedReview={incoming:feeds(incoming),preserved:feeds(saved.contents),combined}
      return {token,identities:merged,feeds:structuredClone(review),profileReplaced:stable(saved.contents.sections.identity)!==stable(contents.sections.identity),proofCount:(contents.sections.memberships?.length??0)+(contents.sections.scopedMemberships?.length??0)}
    },
    async saveIdentities(section:unknown,expectedRevision:number){
      pending=null
      const cancellation=cancellations
      const owner=await guard(),epoch=d.epoch(),saved=await load(owner)
      if(!Number.isSafeInteger(expectedRevision)||saved.revision!==expectedRevision)throw Error('identities_changed')
      const identities=json(d.validate(JSON.stringify(section))) as WalletIdentitySection
      const contents=structuredClone(saved.contents)
      if(contents.version!==3){contents.schema='castalia.castaway-contents.v2';contents.version=2}
      contents.sections.walletIdentities=identities
      const {ciphertext}=candidate(contents,owner),revision=revisionAfter(saved.revision)
      await guard(owner,epoch);await unchanged(owner,saved.snapshot)
      finalFence(epoch,cancellation)
      await d.storage.set({[key(owner)]:{schema:'castalia.wallet-identity-storage.v1',revision,ciphertext}})
      return {revision,identities}
    },
    async confirmImport(token:string){
      const p=pending;pending=null
      if(!p||p.token!==token||p.expires<=d.now())throw Error('import_review_expired')
      await guard(p.owner,p.epoch);await unchanged(p.owner,p.snapshot)
      const contents=validate(p.raw,p.owner)
      if(contents.version===3)d.preflight(p.raw)
      const revision=revisionAfter(p.revision)
      await guard(p.owner,p.epoch);await unchanged(p.owner,p.snapshot)
      if(p.expires<=d.now())throw Error('import_review_expired')
      finalFence(p.epoch,p.cancellation)
      await d.storage.set({[key(p.owner)]:{schema:'castalia.wallet-identity-storage.v1',revision,ciphertext:p.ciphertext}})
      return {revision,identities:identities(contents,p.owner)}
    },
    async exportFile(password:string){
      if(typeof password!=='string'||[...password].length<12||new TextEncoder().encode(password).length>4096)throw Error('password_minimum_12')
      const owner=await guard(),epoch=d.epoch(),saved=await load(owner)
      if(saved.contents.version===3)throw Error('feed_writer_not_qualified')
      const result=d.exportFile(JSON.stringify(saved.contents),password,d.now());await guard(owner,epoch);return result
    },
  }
}

export function isWalletIdentityPage(sender:any,extensionId:string,pageUrl:string):boolean {
  return sender?.id===extensionId && (sender.frameId===undefined||sender.frameId===0) && sender.url===pageUrl
}
