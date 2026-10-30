/** Additive popup ceremony. The browser owns its temporary proof key; Wallet
 * owns unlock, parent grants and consent. These are transport objects, not new
 * signed secS formats. Advertise only after the complete host is qualified. */
export const SESSION_LOGIN_CAPABILITY = 'session_login_v1' as const;
/** Transport bound only, never a grant or service-policy entitlement. */
export const SESSION_LOGIN_MAX_TTL_SECONDS = 3600;
/** Initial UI choice only; authority ceilings come from verified parent/service. */
export const SESSION_LOGIN_DEFAULT_TTL_SECONDS = 900;
export const SESSION_LOGIN_CEREMONY_MS = 300_000;
export type OpenSessionLogin = {
  operation: 'open_session_login';
  /** Optional public correlation ID permits cancellation before preparation. */
  loginId?: string;
  service: string;
  session_public_key: string;
  session_installation_id: string;
  requested_ttl_seconds: number;
  permissions?: unknown[];
  service_access_point?: unknown;
  profile?: unknown;
  access_request?: {
    schema: 'castalia.session-login-access.v1';
    request_schema:string;
    result_schemas:string[];
    challenge_path: string;
    action_path: string;
    catalog_path?: string;
  };
  grant_acquisition?: {
    schema:'castalia.session-login-grant.v1';
    challenge_path:string;
    grant_path:string;
    grant_schema:'secs.holder-grant.v2';
    result_schema:string;
    membership_requirement?:'optional'|'required';
  };
};
export type CompleteSessionLogin = {
  operation: 'complete_session_login';
  loginId: string;
  challenge: Record<string, unknown>;
  session_signature: string;
};
export type CancelSessionLogin = { operation:'cancel_session_login'; loginId:string };
export type SessionLoginCancelled = { schema:'castalia.session-login-cancelled.v1'; dispatched:boolean };
export type SessionLoginRequest = OpenSessionLogin | CompleteSessionLogin | CancelSessionLogin;
export type SessionLoginPrepared = {
  schema: 'castalia.session-login-prepared.v1';
  loginId: string;
  challenge: Record<string, unknown>;
};
export type SessionLoginOpened = {
  schema: 'castalia.holder-session-opened.v1';
  credential: Record<string, unknown>;
};
export type SessionLoginStage = 'request' | 'unlock' | 'provider' | 'access' |
  'challenge' | 'enrollment' | 'save_grant' | 'possession' | 'consent' | 'authorization' | 'exchange' | 'receipt';
/** Only an actual extension result may assert pre-dispatch failure. A lost
 * channel/result has no such assertion and must recover the original session. */
export type SessionLoginFailure = {
  code: 'invalid_session_login_request' | 'approval_required' | 'session_login_busy' |
    'session_login_cancelled' | 'session_login_expired' | 'wallet_not_setup' |
    'wallet_unlock_failed' | 'membership_required' | 'issuer_setup_required' | 'grant_not_saved' |
    'session_login_access_pending' | 'read_approval_expired' |
    'invalid_holder_session' | 'session_login_context_changed' |
    'session_login_failed' | 'holder_session_parent_unsupported' | 'holder_grant_outcome_unknown' | 'holder_session_outcome_unknown';
  stage: SessionLoginStage;
  /** True means SESSION exchange MAY have occurred, not that issuance succeeded.
   * Access/enrollment outcomes use their own stage and original-request recovery. */
  dispatched: boolean;
};
const plain = (v: unknown): v is Record<string, any> =>
  !!v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype;
const invalid = (): never => { throw Error('invalid_session_login_request'); };
const tag=(v:unknown)=>typeof v==='string'&&/^[a-z][a-z0-9.-]{0,120}\.v[1-9][0-9]?$/.test(v);
const path=(p:unknown)=>typeof p==='string'&&p.length<=512&&/^\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*)$/.test(p)&&p.split('/').every(v=>v!=='.'&&v!=='..');
export function parseSessionLoginRequest(value: unknown): SessionLoginRequest {
  if (!plain(value)) return invalid();
  let bytes: number;
  try { bytes = new TextEncoder().encode(JSON.stringify(value)).length; }
  catch { return invalid(); }
  if (bytes > 131072) return invalid();
  const fields = value.operation === 'open_session_login'
    ? ['operation', 'loginId', 'service', 'session_public_key', 'session_installation_id', 'requested_ttl_seconds', 'permissions', 'service_access_point', 'profile', 'access_request', 'grant_acquisition']
    : value.operation === 'complete_session_login'
      ? ['operation', 'loginId', 'challenge', 'session_signature'] : value.operation === 'cancel_session_login' ? ['operation','loginId'] : [];
  if (!fields.length || Object.keys(value).some(k => !fields.includes(k))) return invalid();
  if (value.operation === 'open_session_login') {
    if (value.loginId!==undefined&&(typeof value.loginId!=='string'||!/^[a-f0-9]{32}$/.test(value.loginId))||
        typeof value.service !== 'string' || !value.service || value.service.length > 256 ||
        typeof value.session_public_key !== 'string' || !/^[a-f0-9]{64}$/.test(value.session_public_key) ||
        typeof value.session_installation_id !== 'string' || !/^[a-f0-9]{32}$/.test(value.session_installation_id) ||
        !Number.isSafeInteger(value.requested_ttl_seconds) || value.requested_ttl_seconds < 1 ||
        value.requested_ttl_seconds > SESSION_LOGIN_MAX_TTL_SECONDS ||
        value.permissions !== undefined && !Array.isArray(value.permissions)) return invalid();
    if(value.access_request!==undefined){
      const a=value.access_request;
      if(!plain(a)||a.schema!=='castalia.session-login-access.v1'||
        Object.keys(a).some(k=>!['schema','request_schema','result_schemas','challenge_path','action_path','catalog_path'].includes(k)))return invalid();
      if(!tag(a.request_schema)||!Array.isArray(a.result_schemas)||a.result_schemas.length<1||a.result_schemas.length>4||new Set(a.result_schemas).size!==a.result_schemas.length||!a.result_schemas.every(tag)||!path(a.challenge_path)||!path(a.action_path)||a.catalog_path!==undefined&&!path(a.catalog_path))return invalid();
    }
    if(value.grant_acquisition!==undefined){
      const a=value.grant_acquisition;
      if(!plain(a)||Object.keys(a).some(k=>!['challenge_path','grant_path','grant_schema','result_schema','schema','membership_requirement'].includes(k))||a.membership_requirement!==undefined&&!['optional','required'].includes(a.membership_requirement)||
        a.schema!=='castalia.session-login-grant.v1'||a.grant_schema!=='secs.holder-grant.v2'||!tag(a.result_schema)||
        !path(a.challenge_path)||!path(a.grant_path))return invalid();
    }
  } else if (typeof value.loginId !== 'string' || !/^[a-f0-9]{32}$/.test(value.loginId) ||
      value.operation==='complete_session_login'&&(!plain(value.challenge) || typeof value.session_signature !== 'string' ||
      !/^[a-f0-9]{128}$/.test(value.session_signature))) return invalid();
  return structuredClone(value) as SessionLoginRequest;
}
