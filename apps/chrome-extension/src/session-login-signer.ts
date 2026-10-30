import { parseSessionLoginRequest, type SessionLoginStage } from '@castalia-wallet/provider-types';
import { createHolderGrantsStore } from './holder-grants-store.js';
import { createHolderSessionExchange, parseWalletTransportObject } from './holder-session-exchange.js';
import { loginError, loginFailure } from './session-login-errors.js';
export type LoginSnapshot = {
  custody: {publicKey:string;encryptedRecord:string}|null;
  profiles: unknown;
  grants: unknown;
  installation: string;
  lockRevision: unknown;
};
type Dependencies = {
  critical():Promise<void>;assertCritical():void;beforeSessionDispatch():Promise<void>;
  core:any;servicePresentationContext(...args:string[]):string;
  origin:string;deadline:number;now():number;randomId():string;
  snapshot():Promise<LoginSnapshot>;guard():Promise<LoginSnapshot>;
  pins(snapshot:LoginSnapshot):Promise<any[]>;
  journal(metadata:Record<string,unknown>):Promise<void>;
  accessRecord?():Promise<any>;
  saveAccessRecord?(value:unknown):Promise<void>;
  enrollmentState?():Promise<any>;
  clearEnrollment?():Promise<void>;
  journalEnrollment?(metadata:Record<string,unknown>):Promise<void>;
  saveGrants?(record:unknown,expectedRevision:number):Promise<LoginSnapshot>;
  fetchImpl:typeof fetch;
};
const stable=(v:any):string=>v===undefined?'undefined':v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(stable).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+stable(v[k])).join(',')+'}';
/** Instantiate only inside the extension popup's private dedicated Worker.
 * No root, parent, raw authorization or encrypted record is returned to a page. */
export function createSessionLoginSigner(d:Dependencies) {
  const encoder=new TextEncoder();let live=true,unlocked=false,baseline:LoginSnapshot|null=null;
  let preparation:any=null,proof:string|null=null,exchange:ReturnType<typeof createHolderSessionExchange>|null=null;
  let consumed=false,dispatched=false,stage:SessionLoginStage='unlock',preDispatchError:any;
  let loginRequest:import('@castalia-wallet/provider-types').OpenSessionLogin|null=null;
  let accessHandle:any=null,accessAction:any=null,accessPrefix='',accessReceiver=d.origin;
  let grantsStore:ReturnType<typeof createHolderGrantsStore>|null=null,saving=false;
  let grantHandle:any=null,grantChallenge:any=null,enrollment:any=null,grantReview:any=null;
  let forgetReview:{prepared:Awaited<ReturnType<ReturnType<typeof createHolderGrantsStore>['reviewForget']>>;expires:number}|null=null;
  const ensure=()=>{
    if(!live)throw loginFailure('session_login_context_changed',stage,dispatched);
    if(d.now()>=d.deadline)throw loginFailure('session_login_expired',stage,dispatched);
  };
  const guard=async()=>{
    ensure();const actual=await d.guard();ensure();
    if(!baseline||stable(actual)!==stable(baseline))throw loginFailure('session_login_context_changed',stage,dispatched);
  };
  const invoke=(name:string,...args:any[])=>{
    ensure();try{return JSON.parse(d.core[name](...args));}
    catch(error){
      const code=typeof error==='string'?error:error instanceof Error?error.message:'';
      throw loginFailure(code==='invalid_holder_session'?'invalid_holder_session':'session_login_failed',stage,dispatched);
    }
  };
  const clearAccess=()=>{accessHandle?.dispose();accessHandle?.free();accessHandle=null;};
  const clearGrant=()=>{grantHandle?.dispose();grantHandle?.free();grantHandle=null;};
  const stop=()=>{live=false;unlocked=false;preparation=null;proof=null;exchange=null;clearAccess();clearGrant();enrollment=null;grantReview=null;forgetReview=null;d.core.lock();};
  const route=async()=>{
    if(!baseline||!loginRequest)throw loginFailure('session_login_context_changed',stage);
    const pins=await d.pins(baseline);let routedPins=pins,caller={kind:'browser',id:d.origin};accessPrefix='';accessReceiver=d.origin;
    if(loginRequest.service_access_point!==undefined){
      const binding:any=loginRequest.service_access_point;let context:any;
      try{context=JSON.parse(d.servicePresentationContext(JSON.stringify(pins),JSON.stringify(caller),JSON.stringify(binding),String(d.now())));}catch{throw loginFailure('issuer_setup_required',stage);}
      if(binding.claims?.service!==loginRequest.service||binding.claims?.origin!==d.origin||typeof binding.claims?.prefix!=='string')throw loginFailure('invalid_holder_session',stage);
      accessPrefix=binding.claims.prefix.replace(/\/$/,'');routedPins=context.pins;caller=context.caller;accessReceiver=caller.id;
    }
    return {pins:routedPins,caller};
  };
  const accessCall=async(path:string,body:unknown)=>{
    await guard();const fetchImpl=d.fetchImpl;
    const response=await fetchImpl(d.origin+accessPrefix+path,{method:'POST',body:JSON.stringify(body),headers:{'Content-Type':'application/json'},credentials:'omit',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});
    if(!response.ok||response.redirected||response.url&&response.url!==d.origin+accessPrefix+path)throw loginFailure('session_login_failed','access');
    const reader=response.body?.getReader();if(!reader)throw loginFailure('session_login_failed','access');
    let text='',size=0;const decoder=new TextDecoder('utf-8',{fatal:true});
    try{while(true){const p=await reader.read();if(p.done)break;size+=p.value.byteLength;if(size>131072)throw Error('capacity');text+=decoder.decode(p.value,{stream:true});}text+=decoder.decode();return parseWalletTransportObject(text);}
    finally{await reader.cancel().catch(()=>{});}
  };
  const fetchGrant=async()=>{
    if(!enrollment||!loginRequest?.grant_acquisition||!grantsStore||!baseline)throw loginFailure('invalid_session_login_request','enrollment');
    await guard();await d.critical();let result:any;
    try{result=await accessCall(loginRequest.grant_acquisition.grant_path,enrollment);}
    catch{throw loginFailure('holder_grant_outcome_unknown','enrollment');}
    try{
      if(!result||Object.keys(result).sort().join(',')!=='grant,schema'||result.schema!==loginRequest.grant_acquisition.result_schema||
        result.grant?.claims?.schema!=='secs.holder-grant.v2'||result.grant.claims.service!==loginRequest.service)throw Error('invalid grant');
      grantReview=await grantsStore.prepare(result.grant,loginRequest.service,d.origin,baseline.installation,null);await guard();
      return {summary:{permissions:result.grant.claims.permissions,validity:result.grant.claims.validity,service:loginRequest.service,
        replaces_saved_grant:baseline.grants!==undefined}};
    }catch{throw loginFailure('holder_grant_outcome_unknown','enrollment');}
  };
  return {
    async unlock(passphrase:string) {
      ensure();stage='unlock';const snapshot=await d.snapshot();ensure();
      if(!snapshot.custody)throw loginFailure('wallet_not_setup',stage);
      if(typeof passphrase!=='string'||!passphrase||passphrase.length>4096)throw loginFailure('wallet_unlock_failed',stage);
      try{
        const key=d.core.unlock(encoder.encode(snapshot.custody.encryptedRecord),passphrase);
        if(key!==snapshot.custody.publicKey)throw Error('identity changed');
        baseline=structuredClone(snapshot);await guard();unlocked=true;
        return {publicKey:key};
      }catch(error){d.core.lock();unlocked=false;baseline=null;throw loginFailure('wallet_unlock_failed',stage);}
    },
    async prepare(input:unknown,ttlSeconds?:number) {
      ensure();if(!unlocked||!baseline)throw loginFailure('wallet_unlock_failed','unlock');
      if(consumed||preparation)throw loginFailure('session_login_busy','challenge');
      const request=parseSessionLoginRequest(input);
      if(request.operation!=='open_session_login')throw loginFailure('invalid_session_login_request','request');
      loginRequest=request;
      forgetReview=null;
      stage='provider';await guard();const snapshot=baseline,pins=await d.pins(snapshot);
      const installation=snapshot.installation;
      if(!/^[a-f0-9]{32}$/.test(installation))throw loginFailure('session_login_context_changed',stage);
      const storedKey=()=>`castalia-holder-grants-v1:${d.core.publicKey()}`;
      const grants=createHolderGrantsStore({
        storage:{get:async key=>({[key]:key===storedKey()?snapshot.grants:undefined}),set:async values=>{
          if(!saving||!d.saveGrants||Object.keys(values).join(',')!==storedKey())throw loginFailure('invalid_session_login_request','save_grant');
          await guard();const record=values[storedKey()];const actual=await d.saveGrants(record,(snapshot.grants as any)?.revision??0);
          if(stable(actual)!==stable({...snapshot,grants:record}))throw loginFailure('session_login_context_changed','save_grant');
          snapshot.grants=structuredClone(actual.grants);
        }},
        owner:()=>d.core.publicKey(),now:d.now,
        seal:raw=>d.core.sealIdentitySection(raw),open:raw=>d.core.openIdentitySection(encoder.encode(raw)),
        validateBackup:raw=>d.core.validateHolderGrantBackup(raw),
        review:async(grant,origin,id)=>invoke('reviewHolderGrant',JSON.stringify(grant),JSON.stringify(pins),JSON.stringify({kind:'browser',id:origin}),id,String(d.now())),
        reviewDerivation:(stored,permissions,id,expires)=>invoke('reviewHolderDerivation',JSON.stringify(stored),JSON.stringify(permissions),id,String(d.now()),String(expires)),
        derive:(stored,permissions,id,expires)=>{
          if(!saving)throw Error('login cannot derive another grant credential');d.assertCritical();
          return invoke('deriveHolderCredential',JSON.stringify(stored),JSON.stringify(permissions),id,String(d.now()),String(expires));
        },present:()=>{throw Error('login cannot present arbitrary calls');},
      });
      grantsStore=grants;
      exchange=createHolderSessionExchange({grants,now:d.now,randomId:d.randomId,
        route:(binding:any,pin:any,origin,now)=>{
          if(binding===undefined)return '';
          try{JSON.parse(d.servicePresentationContext(JSON.stringify(pins),JSON.stringify({kind:'browser',id:origin}),JSON.stringify(binding),String(now)));}
          catch{throw loginFailure('issuer_setup_required','provider');}
          if(binding.claims?.service!==pin.service||binding.claims?.issuer!==pin.issuer||binding.claims?.key_id!==pin.key_id||binding.claims?.origin!==origin)throw loginFailure('invalid_holder_session','provider');
          return binding.claims.prefix;
        },
        audience:(pin:any,origin,audience)=>pins.some(p=>p.issuer===pin.issuer&&p.key_id===pin.key_id&&p.public_key===pin.public_key&&p.audience===audience&&p.callers?.some((c:any)=>c.kind==='browser'&&c.id===origin)),
        review:(stored,c,origin,audience,id,now)=>invoke('reviewHolderSessionAuthorization',JSON.stringify(stored),JSON.stringify(c),origin,audience,id,String(now)),
        approve:async(stored,c,signature,origin,audience,id,now)=>{
          stage='authorization';await guard();await d.critical();
          return invoke('approveHolderSessionAuthorization',JSON.stringify(stored),JSON.stringify(c),signature,origin,audience,id,String(d.now()));
        },
        verify:(pin,credential,c,now)=>{
          stage='receipt';ensure();return invoke('verifyHolderSessionCredential',JSON.stringify(pin),JSON.stringify(credential),JSON.stringify(c),String(now));
        },
        fetchImpl:async(url,options)=>{
          if(String(url).endsWith('/exchange')){
            try{
              await guard();const c=preparation.challenge;
              await d.journal({schema:'castalia.session-login-recovery.v1',origin:d.origin,service:c.service,
                request_id:c.request_id,challenge_id:c.challenge_id,session_public_key:c.session_public_key,
                session_installation_id:c.session_installation_id,expires_at:c.expires_at});
              await guard();
              await d.critical();await d.beforeSessionDispatch();
            }catch(error){preDispatchError=error;throw error;}
            stage='exchange';dispatched=true;
          }
          const fetchImpl=d.fetchImpl;return fetchImpl(url,options);
        },
      });
      stage='challenge';
      const exchangeRequest={service:request.service,origin:d.origin,installation,sessionPublicKey:request.session_public_key,sessionInstallationId:request.session_installation_id,ttlSeconds:request.requested_ttl_seconds,permissions:request.permissions??null,binding:request.service_access_point};
      let options;try{options=await exchange.options(exchangeRequest);}catch(error){throw Object.assign(new Error('session login options failed'),loginError(error,stage));}
      if(ttlSeconds===undefined)return {options};
      if(!Number.isSafeInteger(ttlSeconds)||ttlSeconds<1||ttlSeconds>request.requested_ttl_seconds)throw loginFailure('invalid_holder_session',stage);
      ttlSeconds=Math.min(ttlSeconds,options.maximum_ttl_seconds);
      try{
        preparation=await exchange.prepare({service:request.service,origin:d.origin,installation,
          sessionPublicKey:request.session_public_key,sessionInstallationId:request.session_installation_id,
          ttlSeconds,permissions:request.permissions??null,binding:request.service_access_point});
        await guard();return {challenge:structuredClone(preparation.challenge),summary:structuredClone(preparation.summary)};
      }catch(error){preparation=null;throw Object.assign(new Error('session login preparation failed'),loginError(error,stage));}
    },
    /** Only the trusted popup calls this after its explicit profile approval.
     * It cannot rebase a root/grant/lock change or an existing preparation. */
    async refreshTrust() {
      ensure();stage='provider';
      if(!unlocked||!baseline||preparation||proof||consumed)throw loginFailure('session_login_context_changed',stage);
      const actual=await d.guard();ensure();
      if(stable({...actual,profiles:baseline.profiles})!==stable(baseline))throw loginFailure('session_login_context_changed',stage);
      await d.pins(actual);baseline=structuredClone(actual);
    },
    async prepareAccess(sendOriginal=false) {
      stage='access';ensure();await guard();clearAccess();
      if(!unlocked||!baseline||preparation||consumed||!loginRequest?.access_request||!d.accessRecord||!d.saveAccessRecord)throw loginFailure('grant_not_saved',stage);
      if(loginRequest.grant_acquisition?.membership_requirement==='required')throw loginFailure('membership_required',stage);
      const {pins:routedPins,caller}=await route();
      const prior=await d.accessRecord();
      const original=prior??{schema:loginRequest.access_request.request_schema,action:'submit',request_id:d.randomId(),subject_public_key:d.core.publicKey(),installation_id:baseline.installation,intent:null};
      if(original.schema!==loginRequest.access_request.request_schema||original.action!=='submit'||typeof original.request_id!=='string'||!/^[a-f0-9]{32}$/.test(original.request_id)||original.subject_public_key!==d.core.publicKey()||original.installation_id!==baseline.installation||original.intent!==null)throw loginFailure('session_login_context_changed',stage);
      accessAction=prior&&!sendOriginal?{...original,action:'status',intent:null}:original;
      const challenge=await accessCall(loginRequest.access_request.challenge_path,{request:accessAction});
      if(challenge?.schema!=='castalia.access-request-challenge.v1'||challenge.receiver!==accessReceiver||stable(challenge.details)!==stable(accessAction)||challenge.operation!==(prior&&!sendOriginal?'access.status':'access.request'))throw loginFailure('invalid_holder_session',stage);
      accessHandle=d.core.prepareAccessRequest(JSON.stringify(challenge),baseline.installation,JSON.stringify(routedPins),JSON.stringify(caller),String(d.now()));
      const summary=JSON.parse(accessHandle.summary());await guard();
      if(!prior)await d.saveAccessRecord(original);
      return {summary,checking:!!prior&&!sendOriginal};
    },
    async approveAccess() {
      stage='access';ensure();await guard();
      if(!accessHandle||!loginRequest?.access_request||!accessAction)throw loginFailure('invalid_session_login_request',stage);
      let authorization:any;
      await d.critical();try{authorization={...JSON.parse(d.core.approveAccessRequest(accessHandle,String(d.now()))),proof:{}};}finally{clearAccess();}
      await guard();let result:any;
      await d.critical();try{result=await accessCall(loginRequest.access_request.action_path,authorization);}catch{throw loginFailure('session_login_access_pending',stage);}
      if(!result||!loginRequest.access_request.result_schemas.includes(result.schema)||result.request_id!==accessAction.request_id||result.authority_issued!==false||!['pending','expired','unknown','approved_pending_activation','denied','active','revoked','superseded','partially_active'].includes(result.status))throw loginFailure('session_login_access_pending',stage);
      return {status:result.status,request_id:accessAction.request_id};
    },
    async reviewForget() {
      ensure();await guard();
      if(!unlocked||!loginRequest||!grantsStore||preparation||proof||consumed||enrollment||grantHandle||grantReview)throw loginFailure('invalid_session_login_request','save_grant');
      const prepared=await grantsStore.reviewForget(loginRequest.service);await guard();forgetReview={prepared,expires:d.now()+120};
      return {summary:{service:prepared.service,grant:prepared.grant,local_only:true}};
    },
    cancelForget(){forgetReview=null;},
    async forget() {
      stage='save_grant';ensure();await guard();const reviewed=forgetReview;forgetReview=null;
      if(!reviewed||d.now()>=reviewed.expires||!grantsStore||preparation||proof||consumed||enrollment||grantHandle||grantReview||saving)throw loginFailure('invalid_session_login_request',stage);
      await d.critical();saving=true;
      try{await grantsStore.forget(reviewed.prepared);await guard();return {forgotten:true};}finally{saving=false;}
    },
    async prepareGrant() {
      stage='enrollment';ensure();await guard();
      if(!unlocked||!baseline||!loginRequest?.grant_acquisition||preparation||consumed||enrollment)throw loginFailure('invalid_session_login_request',stage);
      if(loginRequest.grant_acquisition.membership_requirement!=='optional')throw loginFailure('membership_required','enrollment');
      const unresolved=await d.enrollmentState?.();if(unresolved?.count)return {uncertain:true,...unresolved};
      clearGrant();const context=await route();
      const challenge=await accessCall(loginRequest.grant_acquisition.challenge_path,{subject_public_key:d.core.publicKey(),installation_id:baseline.installation});
      try{grantHandle=d.core.prepareReadAccess(JSON.stringify(challenge),baseline.installation,JSON.stringify(context.pins),JSON.stringify(context.caller),String(d.now()));}
      catch{throw loginFailure('issuer_setup_required',stage);}
      grantChallenge=challenge;const summary=JSON.parse(grantHandle.summary());await guard();return {summary};
    },
    async obtainGrant() {
      stage='enrollment';ensure();await guard();
      if(!grantHandle||!grantChallenge||enrollment||!d.journalEnrollment)throw loginFailure('invalid_session_login_request',stage);
      await d.journalEnrollment({schema:'castalia.session-login-enrollment-recovery.v1',origin:d.origin,service:loginRequest!.service,
        request_id:grantChallenge.request_id,challenge_digest:Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(stable(grantChallenge)))),v=>v.toString(16).padStart(2,'0')).join(''),holder_public_key:d.core.publicKey(),installation_id:baseline!.installation,expires_at:grantChallenge.expires_at});
      await guard();
      await d.critical();try{enrollment={...JSON.parse(d.core.approveReadAccess(grantHandle,String(d.now()))),proof:{}};}finally{clearGrant();}
      return fetchGrant();
    },
    async recoverGrant() {stage='enrollment';ensure();return fetchGrant();},
    async saveGrant() {
      stage='save_grant';ensure();await guard();
      if(!grantReview||!grantsStore||!baseline||saving)throw loginFailure('invalid_session_login_request',stage);
      await d.critical();const reviewed=grantReview;grantReview=null;saving=true;
      try{await grantsStore.activate(reviewed,true,baseline.installation);enrollment=null;grantChallenge=null;await d.clearEnrollment?.();await guard();return {saved:true};}
      finally{saving=false;}
    },
    proof(input:unknown) {
      ensure();stage='possession';const request=parseSessionLoginRequest(input);
      if(request.operation!=='complete_session_login'||!preparation||consumed||proof||
        stable(request.challenge)!==stable(preparation.challenge))throw loginFailure('invalid_holder_session',stage);
      proof=request.session_signature;return {summary:structuredClone(preparation.summary)};
    },
    async approve() {
      ensure();stage='consent';
      if(!exchange||!preparation||!proof||consumed)throw loginFailure('invalid_holder_session',stage);
      consumed=true;
      try{
        await guard();
        const result=await exchange.activate(preparation,proof);await guard();
        return {schema:'castalia.holder-session-opened.v1',credential:result.credential};
      }catch(error){
        const projected=loginError(preDispatchError??error,stage,dispatched);
        throw Object.assign(new Error(projected.code),projected);
      }finally{preparation=null;proof=null;exchange=null;}
    },
    dispose:stop,
  };
}
