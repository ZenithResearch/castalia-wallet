import {CUSTODY_STORAGE_KEY} from './state/custody-state.js';
import {loginFailure} from './session-login-errors.js';
import type {LoginSnapshot} from './session-login-signer.js';
export const LOGIN_PROFILES='castalia-provider-profiles-v1',LOGIN_INSTALLATION='castalia-read-installation-v1';
export const SESSION_LOGIN_INVALIDATION='castalia-session-login-invalidation-v1';
const stable=(v:any):string=>v===undefined?'undefined':v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(stable).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+stable(v[k])).join(',')+'}';
export async function loginSnapshotDigest(snapshot:LoginSnapshot){
  const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(stable(snapshot)));
  return Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join('');
}
export async function readLoginSnapshot(chrome:any,owner?:string):Promise<LoginSnapshot>{
  const first=(await chrome.storage.local.get(CUSTODY_STORAGE_KEY))[CUSTODY_STORAGE_KEY]??null;
  const key=typeof first?.publicKey==='string'?`castalia-holder-grants-v1:${first.publicKey}`:null;
  const names=[CUSTODY_STORAGE_KEY,LOGIN_PROFILES,LOGIN_INSTALLATION,SESSION_LOGIN_INVALIDATION,...(key?[key]:[])];
  const values=await chrome.storage.local.get(names),custody=values[CUSTODY_STORAGE_KEY]??null;
  if(custody?.publicKey!==first?.publicKey||owner!==undefined&&custody?.publicKey!==owner)throw loginFailure('session_login_context_changed','request');
  return {custody,profiles:values[LOGIN_PROFILES],installation:values[LOGIN_INSTALLATION],lockRevision:values[SESSION_LOGIN_INVALIDATION]??null,grants:key?values[key]:undefined};
}
/** Caller MUST run this in the shared custody-operation queue. It writes only
 * the original encrypted grant record format, never plaintext or authority. */
export async function saveLoginGrants(chrome:any,input:{owner:string;expectedRevision:number;expectedSnapshot:string;record:any}){
  const {owner,expectedRevision,expectedSnapshot,record}=input;
  if(typeof owner!=='string'||!/^[a-f0-9]{64}$/.test(owner)||!Number.isSafeInteger(expectedRevision)||expectedRevision<0||
    typeof expectedSnapshot!=='string'||!/^[a-f0-9]{64}$/.test(expectedSnapshot)||!record||Object.getPrototypeOf(record)!==Object.prototype||
    Object.keys(record).sort().join(',')!=='ciphertext,revision,schema'||record.schema!=='castalia.holder-grant-storage.v1'||
    !Number.isSafeInteger(record.revision)||record.revision!==expectedRevision+1||typeof record.ciphertext!=='string'||!record.ciphertext||record.ciphertext.length>1048576)throw loginFailure('invalid_session_login_request','save_grant');
  const current=await readLoginSnapshot(chrome,owner);
  if(((current.grants as any)?.revision??0)!==expectedRevision||await loginSnapshotDigest(current)!==expectedSnapshot)throw loginFailure('session_login_context_changed','save_grant');
  await chrome.storage.local.set({[`castalia-holder-grants-v1:${owner}`]:record});
}
