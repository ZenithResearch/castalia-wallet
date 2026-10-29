/** Private Wallet → issuer transport. Never pass this preparation to a page. */
const BASE='/holder-sessions/v1';
const LIMIT=131072;
const plain=(v:any)=>!!v&&Object.getPrototypeOf(v)===Object.prototype;
const shape=(v:any,fields:string[])=>plain(v)&&Object.keys(v).sort().join(',')===[...fields].sort().join(',');
const fail=()=>{throw Error('invalid_holder_session');};
const canonical=(v:any):string=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';

function parseUnchecked(text:string):any {
  // Scan property tokens before JSON.parse so escaped duplicate names cannot
  // disappear before the typed Core checks the closed protocol object.
  const stack:Array<Set<string>|null>=[];let at=0;
  while(at<text.length){
    const ch=text[at++];
    if(ch==='{'||ch==='['){stack.push(ch==='{'?new Set():null);if(stack.length>32)fail();}
    else if(ch==='}'||ch===']')stack.pop();
    else if(ch==='"'){
      const start=at-1;let escaped=false,closed=false;
      while(at<text.length){const next=text[at++];if(escaped)escaped=false;else if(next==='\\')escaped=true;else if(next==='"'){closed=true;break;}}
      if(!closed)fail();
      const value=JSON.parse(text.slice(start,at));let next=at;while(/[\t\r\n ]/.test(text[next]??''))next++;
      const keys=stack.at(-1);if(text[next]===':'&&keys){if(keys.has(value))fail();keys.add(value);}
    }
    else if(ch==='-'||/[0-9]/.test(ch)){
      const start=at-1;while(/[0-9eE+.\-]/.test(text[at]??''))at++;
      const token=text.slice(start,at);if(!/^-?(0|[1-9][0-9]*)$/.test(token)||!Number.isSafeInteger(Number(token)))fail();
    }
  }
  const value=JSON.parse(text,(_key,v)=>{if(typeof v==='number'&&!Number.isSafeInteger(v))fail();return v;});
  if(!plain(value))fail();return value;
}
function parse(text:string):any {try{return parseUnchecked(text);}catch{fail();}}

type Request={service:string;origin:string;installation:string;sessionPublicKey:string;sessionInstallationId:string;ttlSeconds:number;permissions:unknown[]|null;binding?:unknown};
type Dependencies={
  grants:{prepare(grant:unknown,service:string,origin:string,installation:string,permissions:unknown):Promise<any>;assertRevision(revision:number):Promise<void>};
  now():number;randomId():string;fetchImpl:typeof fetch;
  route(binding:unknown,pin:unknown,origin:string,now:number):Promise<string>|string;
  audience(pin:unknown,origin:string,audience:string):Promise<boolean>|boolean;
  review(stored:unknown,challenge:unknown,origin:string,audience:string,installation:string,now:number):any;
  approve(stored:unknown,challenge:unknown,signature:string,origin:string,audience:string,installation:string,now:number):any;
  verify(pin:unknown,credential:unknown,challenge:unknown,now:number):any;
};

export function createHolderSessionExchange(d:Dependencies){
  async function call(origin:string,prefix:string,path:string,body?:unknown){
    const u=new URL(origin);if(u.protocol!=='https:'||u.origin!==origin)fail();
    const encoded=body===undefined?undefined:JSON.stringify(body);
    if(encoded!==undefined&&new TextEncoder().encode(encoded).length>LIMIT)fail();
    const response=await d.fetchImpl(origin+prefix+BASE+path,{method:body===undefined?'GET':'POST',
      headers:body===undefined?{}:{'Content-Type':'application/json'},body:encoded,
      credentials:'omit',redirect:'error',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(10000)});
    if(!response.ok||response.redirected||(response.url&&response.url!==origin+prefix+BASE+path))fail();
    const reader=response.body?.getReader();if(!reader)fail();
    const decoder=new TextDecoder('utf-8',{fatal:true});let size=0,text='';
    try{while(true){const part=await reader!.read();if(part.done)break;size+=part.value.byteLength;if(size>LIMIT)fail();text+=decoder.decode(part.value,{stream:true});}text+=decoder.decode();}
    finally{await reader!.cancel().catch(()=>{});}
    return parse(text);
  }
  return{
    async prepare(request:Request){
      const saved=await d.grants.prepare(undefined,request.service,request.origin,request.installation,request.permissions);
      const stored=saved.stored;
      if(stored?.grant?.claims?.schema!=='secs.holder-grant.v2')throw Error('holder_session_parent_unsupported');
      const rawPrefix=await d.route(request.binding,stored.pin,request.origin,d.now());
      if(typeof rawPrefix!=='string'||rawPrefix!==''&&(!/^\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*)?\/?$/.test(rawPrefix)||rawPrefix.split('/').some(p=>p==='.'||p==='..')))fail();
      const prefix=rawPrefix.replace(/\/$/,'');
      const capabilities=await call(request.origin,prefix,'/capabilities');
      const fields=['schema','supported','profile','issuer_pin','audience','grant_schemas','credential_schema','presentation_schema','read_only','max_ttl_seconds','review_ttl_seconds','proof_max_ttl_seconds','challenge_path','exchange_path','status_path'];
      const pin=capabilities.issuer_pin;
      if(!shape(capabilities,fields)||capabilities.schema!=='secs.holder-session-capabilities.v1'||capabilities.supported!==true||
        capabilities.profile!=='secs.holder-session.v1'||typeof capabilities.audience!=='string'||!capabilities.audience||capabilities.read_only!==true||
        capabilities.credential_schema!=='secs.holder-session-credential.v1'||capabilities.presentation_schema!=='secs.holder-session-presentation.v1'||
        JSON.stringify(capabilities.grant_schemas)!=='["secs.holder-grant.v2"]'||
        !Number.isSafeInteger(capabilities.max_ttl_seconds)||capabilities.max_ttl_seconds<1||capabilities.max_ttl_seconds>3600||
        capabilities.review_ttl_seconds!==120||capabilities.proof_max_ttl_seconds!==60||
        capabilities.challenge_path!==prefix+BASE+'/challenges'||capabilities.exchange_path!==prefix+BASE+'/exchange'||capabilities.status_path!==prefix+BASE+'/status'||
        !shape(pin,['issuer','key_id','public_key','service'])||!['issuer','key_id','public_key','service'].every(k=>pin[k]===stored.pin[k]))fail();
      if(!await d.audience(pin,request.origin,capabilities.audience))throw Error('issuer_setup_required');
      const requestId=d.randomId();if(!/^[a-f0-9]{32}$/.test(requestId))fail();
      const result=await call(request.origin,prefix,'/challenges',{schema:'secs.holder-session-prepare.v1',request_id:requestId,
        parent_grant:stored.grant,installation_id:request.installation,session_public_key:request.sessionPublicKey,
        session_installation_id:request.sessionInstallationId,origin:request.origin,audience:capabilities.audience,
        permissions:request.permissions,
        requested_ttl_seconds:Math.min(request.ttlSeconds,capabilities.max_ttl_seconds)});
      if(!shape(result,['schema','challenge'])||result.schema!=='secs.holder-session-challenge-result.v1')fail();
      const c=result.challenge;
      if(c?.request_id!==requestId||c?.session_public_key!==request.sessionPublicKey||c?.session_installation_id!==request.sessionInstallationId||
        !Number.isSafeInteger(c?.expires_at)||c.expires_at>d.now()+Math.min(request.ttlSeconds,capabilities.max_ttl_seconds))fail();
      const summary=await d.review(stored,c,request.origin,capabilities.audience,request.installation,d.now());
      if(request.permissions!==null&&canonical(c.permissions)!==canonical(request.permissions))fail();
      return{challenge:structuredClone(c),summary:structuredClone(summary),stored:structuredClone(stored),
        revision:saved.revision,origin:request.origin,audience:capabilities.audience,installation:request.installation,
        prefix,binding:request.binding};
    },
    async activate(prepared:any,sessionSignature:string){
      await d.grants.assertRevision(prepared.revision);
      const c=prepared.challenge;
      const prefix=(await d.route(prepared.binding,prepared.stored.pin,prepared.origin,d.now())).replace(/\/$/,'');
      if(prefix!==prepared.prefix||!await d.audience(prepared.stored.pin,prepared.origin,prepared.audience))throw Error('issuer_setup_required');
      if(d.now()>=c.review_deadline||d.now()>=c.expires_at)throw Error('read_approval_expired');
      const authorization=await d.approve(prepared.stored,c,sessionSignature,prepared.origin,prepared.audience,prepared.installation,d.now());
      if(d.now()>=c.review_deadline||d.now()>=c.expires_at)throw Error('read_approval_expired');
      let result:any;
      try{result=await call(prepared.origin,prefix,'/exchange',authorization);}
      catch{throw Error('holder_session_outcome_unknown');}
      if(!shape(result,['schema','request_id','challenge_id','state','credential','expires_at'])||
        result.schema!=='secs.holder-session-result.v1'||result.state!=='issued'||result.request_id!==c.request_id||
        result.challenge_id!==c.challenge_id||result.expires_at!==c.expires_at)throw Error('holder_session_outcome_unknown');
      const verified=await d.verify(prepared.stored.pin,result.credential,c,d.now());
      if(!shape(verified,['schema','credential_digest','service','session_public_key','session_installation_id','expires_at'])||
        verified.schema!=='castalia.holder-session-credential-verified.v1'||typeof verified.credential_digest!=='string'||!/^[a-f0-9]{64}$/.test(verified.credential_digest)||verified.expires_at!==c.expires_at||
        verified.service!==prepared.stored.pin.service||verified.session_public_key!==c.session_public_key||
        verified.session_installation_id!==c.session_installation_id)fail();
      return{credential:structuredClone(result.credential)};
    },
  };
}
