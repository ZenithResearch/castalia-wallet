/** Extension-owned adapter. The Rust core owns identity/schema validation. */
export type WalletIdentityRecord={accountId:string;kind:'matrix'|'nostr'|'github'|'x';label:string;identifier:string;server:string}
export type WalletIdentitySection={schema:'castalia.wallet-identities.v1';version:1;ownerMemberKey:string;authority:'descriptor-only';accounts:WalletIdentityRecord[]}
type Dependencies={
  state():Promise<{unlocked:boolean;publicKey:string|null}>;epoch():number;now():number
  storage:{get(key:string):Promise<Record<string,unknown>>;set(values:Record<string,unknown>):Promise<void>}
  chainAccounts():unknown;validateContents(raw:string):string;validate(raw:string):string;merge(current:string,incoming:string):string
  seal(raw:string):string;open(encrypted:string):string
  importFile(raw:string,password:string):string;exportFile(raw:string,password:string,now:number):string
}
const stable=(value:any):string=>JSON.stringify(value&&typeof value==='object'?Array.isArray(value)?value.map((v:any)=>JSON.parse(stable(v))):Object.fromEntries(Object.keys(value).sort().map(k=>[k,JSON.parse(stable(value[k]))])):value)
const empty=(owner:string):WalletIdentitySection=>({schema:'castalia.wallet-identities.v1',version:1,ownerMemberKey:owner,authority:'descriptor-only',accounts:[]})
const json=(raw:string)=>{if(typeof raw!=='string'||new TextEncoder().encode(raw).length>1_048_576)throw Error('file_too_large');return JSON.parse(raw)}
export function createWalletIdentitiesStore(d:Dependencies){
  let pending:{token:string;owner:string;epoch:number;revision:number;expires:number;contents:any;ciphertext:string}|null=null
  const key=(owner:string)=>'castalia-wallet-identities-v1:'+owner
  async function guard(owner?:string,epoch?:number){const s=await d.state();if(!s.unlocked||!s.publicKey||! /^[a-f0-9]{64}$/.test(s.publicKey)||owner&&owner!==s.publicKey||epoch!==undefined&&epoch!==d.epoch())throw Error('wallet_changed_or_locked');return s.publicKey}
  function initial(owner:string){return {schema:'castalia.castaway-contents.v1',version:1,sections:{identity:{schema:'zenith.identity-section.v1',version:1,subject:{type:'Person',memberKey:owner,fields:Object.fromEntries(['displayName','givenName','familyName','headline','biography','website','orcid'].map(k=>[k,{value:'',disclosure:'private'}])),roles:[],affiliations:[],journals:[]},updatedAt:0},chainAccounts:d.chainAccounts()}}}
  function identities(contents:any,owner:string):WalletIdentitySection{return json(d.validate(JSON.stringify(contents.sections.walletIdentities??empty(owner))))}
  async function load(owner:string){
    const saved=(await d.storage.get(key(owner)))[key(owner)] as any
    if(saved===undefined)return {revision:0,contents:initial(owner)}
    if(!saved||Object.keys(saved).sort().join(',')!=='ciphertext,revision,schema'||saved.schema!=='castalia.wallet-identity-storage.v1'||!Number.isSafeInteger(saved.revision)||saved.revision<1||typeof saved.ciphertext!=='string')throw Error('invalid_identity_storage')
    const contents=json(d.validateContents(d.open(saved.ciphertext)));identities(contents,owner)
    return {revision:saved.revision as number,contents}
  }
  return {
    cancel(){pending=null},
    async read(){const owner=await guard(),epoch=d.epoch(),saved=await load(owner);await guard(owner,epoch);return {revision:saved.revision,identities:identities(saved.contents,owner)}},
    async reviewImport(file:string,password:string){
      pending=null
      if(typeof password!=='string'||new TextEncoder().encode(password).length>4096)throw Error('invalid_password')
      const owner=await guard(),epoch=d.epoch(),saved=await load(owner)
      const incoming=json(d.validateContents(d.importFile(file,password)))
      if(incoming.sections.identity.subject.memberKey!==owner)throw Error('wrong_owner')
      const merged=json(d.merge(JSON.stringify(identities(saved.contents,owner)),JSON.stringify(identities(incoming,owner))))
      const contents=structuredClone(saved.contents)
      contents.sections.identity=incoming.sections.identity
      for(const field of ['memberships','scopedMemberships']){
        const proofs=[...(contents.sections[field]??[])]
        for(const proof of incoming.sections[field]??[]){const old=proofs.find(p=>p.membershipId===proof.membershipId);if(old&&stable(old)!==stable(proof))throw Error('proof_conflict');if(!old)proofs.push(proof)}
        if(proofs.length)contents.sections[field]=proofs
      }
      if(incoming.sections.walletIdentities||saved.contents.sections.walletIdentities){contents.schema='castalia.castaway-contents.v2';contents.version=2;contents.sections.walletIdentities=merged}
      d.validateContents(JSON.stringify(contents))
      const ciphertext=d.seal(JSON.stringify(contents))
      await guard(owner,epoch)
      const token=crypto.randomUUID()
      pending={token,owner,epoch,revision:saved.revision,expires:d.now()+120_000,contents,ciphertext}
      return {token,identities:merged,profileReplaced:stable(saved.contents.sections.identity)!==stable(contents.sections.identity),proofCount:(contents.sections.memberships?.length??0)+(contents.sections.scopedMemberships?.length??0)}
    },
    async saveIdentities(section:unknown,expectedRevision:number){
      pending=null
      const owner=await guard(),epoch=d.epoch(),saved=await load(owner)
      if(!Number.isSafeInteger(expectedRevision)||saved.revision!==expectedRevision)throw Error('identities_changed')
      const identities=json(d.validate(JSON.stringify(section))) as WalletIdentitySection
      const contents=structuredClone(saved.contents);contents.schema='castalia.castaway-contents.v2';contents.version=2;contents.sections.walletIdentities=identities
      d.validateContents(JSON.stringify(contents))
      const ciphertext=d.seal(JSON.stringify(contents))
      await guard(owner,epoch)
      if(!Number.isSafeInteger(saved.revision+1))throw Error('revision_exhausted')
      await d.storage.set({[key(owner)]:{schema:'castalia.wallet-identity-storage.v1',revision:saved.revision+1,ciphertext}})
      return {revision:saved.revision+1,identities}
    },
    async confirmImport(token:string){
      const p=pending;pending=null
      if(!p||p.token!==token||p.expires<=d.now())throw Error('import_review_expired')
      await guard(p.owner,p.epoch)
      const current=await load(p.owner)
      if(current.revision!==p.revision||!Number.isSafeInteger(p.revision+1))throw Error('identities_changed')
      await guard(p.owner,p.epoch)
      await d.storage.set({[key(p.owner)]:{schema:'castalia.wallet-identity-storage.v1',revision:p.revision+1,ciphertext:p.ciphertext}})
      return {revision:p.revision+1,identities:identities(p.contents,p.owner)}
    },
    async exportFile(password:string){if(typeof password!=='string'||[...password].length<12||new TextEncoder().encode(password).length>4096)throw Error('password_minimum_12');const owner=await guard(),epoch=d.epoch(),saved=await load(owner);const result=d.exportFile(JSON.stringify(saved.contents),password,d.now());await guard(owner,epoch);return result},
  }
}

export function isWalletIdentityPage(sender:any,extensionId:string,pageUrl:string):boolean {
  return sender?.id===extensionId && (sender.frameId===undefined||sender.frameId===0) && sender.url===pageUrl
}
