/** Presentation only. Unknown fields remain visible; this never evaluates rights. */
const labels:Record<string,string>={list:'Browse',get:'Read',relationships:'Read connections'};
export function permissionPresentation(permission:any){
 const operation=String(permission?.operation??'unrecognized'),parts=operation.split('.'),verb=parts.pop()!;
 const label=labels[verb]?labels[verb]+' · '+parts.join(' · '):'Operation: '+operation;
 const details=Object.fromEntries(Object.entries(permission??{}).filter(([key])=>key!=='operation'));
 return {label,restrictions:JSON.stringify(details,null,2)};
}

/** Public UI copy only: a request's status is not the Wallet's saved-grant state. */
export function accessRecoveryPresentation(state:any){
 const reviewing=state.stage==='access_review',pending=state.stage==='access_pending';
 const primary=reviewing?'confirm_request':state.grantDescriptor?'check_approved':'request';
 if(reviewing)return {heading:'Review access request',status:'Review this access request.',detail:'Review this exact request. This creates no grant or session.',primary};
 if(pending){
  const status=state.result?.status;
  return {heading:'Access request status',status:status?'Request status: '+status+'.':'Request status could not be confirmed.',
   detail:(status==='active'?'The operator approved this request.':status?'Status of this request: '+status+'.':'The status of this request could not be confirmed.')+
    (state.grantDescriptor?' Existing approved access is checked separately. Check approved access to review the grant available now;':'')+
    ' Checking this original request sends no replacement request.',primary};
 }
 const code=state.error?.code;
 if(code){
  const unsupported=code==='holder_session_parent_unsupported';
  const reasons:Record<string,string>={membership_required:'This service requires a membership proof. This popup does not support that enrollment yet.',issuer_setup_required:'This service does not match your trusted provider settings.',session_login_context_changed:'Wallet or trust settings changed. Start a new login.',session_login_expired:'This login expired. Start again from the application.',read_approval_expired:'The saved access or review has expired.'};
  return {heading:unsupported?'Saved grant needs a compatible session':'Access needs attention',
   status:unsupported?'The saved grant uses an older session format.':reasons[code]??'Wallet could not use the available access.',
   detail:(unsupported?'Your saved grant is unchanged. It cannot authorize this session profile.':'Your saved Wallet records are unchanged. This result does not establish that your access is missing or revoked.')+
    ' Check approved access to review what the service currently allows before requesting new permissions.',primary};
 }
 if(state.savedGrantAvailable===true)return {heading:'Saved access',status:'A grant is saved in this Wallet.',
  detail:'This confirms only the local copy; it does not confirm the service still authorizes it. Check approved access for the service’s current permissions, or forget this local copy.',primary};
 return {heading:'Check existing access',status:'Check your approved access.',
  detail:'A reusable grant is not saved in this browser Wallet. You may already have approved access on the service. Check it before sending a new access request.',primary};
}
