import type { SessionLoginFailure, SessionLoginStage } from '@castalia-wallet/provider-types';
const codes: SessionLoginFailure['code'][] = ['invalid_session_login_request','approval_required','session_login_busy','session_login_cancelled','session_login_expired','wallet_not_setup','wallet_unlock_failed','membership_required','issuer_setup_required','grant_not_saved','session_login_access_pending','read_approval_expired','invalid_holder_session','session_login_context_changed','session_login_failed','holder_session_parent_unsupported','holder_grant_outcome_unknown','holder_session_outcome_unknown'];
const stages: SessionLoginStage[] = ['request','unlock','provider','access','challenge','enrollment','save_grant','possession','consent','authorization','exchange','receipt'];
export function loginFailure(code: SessionLoginFailure['code'], stage: SessionLoginStage, dispatched=false) {
  return Object.assign(new Error(code), {code,stage,dispatched});
}
/** Never send a raw exception, network diagnostic or private Core value. */
export function loginError(value: any, stage: SessionLoginStage, dispatched=false): SessionLoginFailure {
  const code = codes.includes(value?.code) ? value.code : codes.includes(value?.message) ? value.message : 'session_login_failed';
  return {code: dispatched ? 'holder_session_outcome_unknown' : code,
    stage: stages.includes(value?.stage) ? value.stage : stage,
    dispatched: dispatched || value?.dispatched === true};
}
