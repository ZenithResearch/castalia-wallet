import {permissionPresentation} from './session-login-presentation.js';
import { createSessionLoginPopupHost } from './session-login-popup-host.js';
declare const chrome:any;
const $=(id:string)=>document.getElementById(id)!;
const buttons=Array.from(document.querySelectorAll('button'));
let host:Awaited<ReturnType<typeof createSessionLoginPopupHost>>|null=null;
const messages:Record<string,string>={wallet_unlock_failed:'Could not unlock this Wallet. Try again here.',membership_required:'This service requires a membership proof. This popup does not support that enrollment yet; no proof or new grant was sent.',wallet_not_setup:'Set up or import your Wallet in Castalia before logging in.',issuer_setup_required:'This service does not match your trusted provider settings.',read_approval_expired:'This review has expired. Return to the application for a new review.',session_login_context_changed:'The application, Wallet or trust settings changed. Start a new login.',holder_session_outcome_unknown:'The original session result is uncertain. Return to the application and check its original result; do not start another session.',session_login_expired:'This login expired. Start again from the application.',session_login_failed:'Wallet could not finish this login. No automatic retry was sent.'};
function render(state:any){
  for(const id of ['unlock','provider','lifetime','review','access','grant'])$(id).hidden=true;
  buttons.forEach(b=>b.disabled=false);$('status').classList.remove('error');
  if(state.stage==='closed'||state.stage==='done'){window.close();return;}
  const text:Record<string,string>={unlock:'Unlock Wallet to continue.',unlocking:'Unlocking your Wallet…',provider:'Review the issuer before continuing.',preparing:'Checking your saved grant…',waiting_proof:'Confirming the application’s temporary key…',lifetime:'Choose a duration within your approved access.',grant_review:'Review the service’s approved grant.',save_grant:'Save this reusable grant in Wallet.',grant_recovery:'The original grant result is uncertain.',grant_uncertain:'An earlier grant attempt is unresolved.',review:'Review the exact access for this session.',opening:'Creating the reviewed session…',access_required:'No saved grant is available.',access_review:'Review your access request.',access_pending:'Your access request is awaiting the operator.'};
  $('status').textContent=state.message??messages[state.error?.code]??text[state.stage]??'Wallet could not finish this login.';
  if(state.error||state.stage==='failed')$('status').classList.add('error');
  if(state.stage==='unlock'){$('unlock').hidden=false;($('passphrase') as HTMLInputElement).focus();}
  if(state.stage==='provider'){$('provider').hidden=false;$('provider-name').textContent=state.profile?.display_name??'Service provider';$('provider-details').textContent=JSON.stringify(state.profile,null,2);}
  if(state.stage==='lifetime'){
    $('lifetime').hidden=false;$('refresh-approved').hidden=!state.grantDescriptor;const select=$('duration') as HTMLSelectElement;select.replaceChildren();
    const max=state.options.maximum_ttl_seconds;
    for(const n of [...new Set([60,300,900,1800,3600,max])].filter(n=>n<=max).sort((a,b)=>a-b)){const option=new Option(n<60?n+' seconds':n%60?n+' seconds':n/60+' minutes',String(n));select.add(option);}
    select.value=String(state.options.default_ttl_seconds);
  }
  if(state.stage==='review'){
    $('review').hidden=false;$('permission-summary').replaceChildren(...state.summary.permissions.map((permission:any)=>{const view=permissionPresentation(permission),row=document.createElement('div'),label=document.createElement('h3'),scope=document.createElement('pre');label.textContent=view.label;scope.textContent=view.restrictions;row.append(label,scope);return row;}));$('permissions').textContent=JSON.stringify(state.summary.permissions,null,2);
    $('expiry').textContent='Ends '+new Date(state.summary.expires_at*1000).toLocaleString()+'. This expiry cannot be extended by using the session.';
  }
  if(['access_required','access_review','access_pending'].includes(state.stage)){
    $('access').hidden=false;$('prepare-grant').hidden=!state.grantDescriptor||state.stage==='access_review';$('send-original').hidden=state.result?.status!=='unknown';$('request-access').hidden=!state.descriptor||state.stage==='access_review';$('confirm-request').hidden=state.stage!=='access_review';
    $('request-access').textContent=state.stage==='access_pending'?'Check original request':'Request access';
    $('confirm-request').textContent=state.checking?'Check request status':'Send access request';
    $('access-details').hidden=state.stage!=='access_review';$('access-details').textContent=state.summary?JSON.stringify(state.summary.details,null,2):'';
    $('access-status').textContent=state.stage==='access_review'?'Review this exact request. This creates no grant or session.':state.result?.status==='active'?'Access is approved. Choose Check approved access to obtain and save its grant here.':state.stage==='access_pending'?'Request status: '+(state.result?.status??'uncertain')+'. Check this original request; no replacement request is sent.':state.error?'The service could not prepare a session from the saved access. You can explicitly check approved access or review an access request. Your saved grant has not been removed.':'This Wallet has no saved grant for this service. The operator must approve access before a session can start.';
  }
  if(['grant_review','save_grant','grant_recovery','grant_uncertain'].includes(state.stage)){
    $('grant').hidden=false;
    $('grant-details').hidden=!state.summary;$('grant-details').textContent=state.summary?JSON.stringify(state.summary,null,2):'';
    $('grant-status').textContent=state.stage==='grant_review'?'Approve this exact request to obtain the access already authorized by the operator. This does not start an application session.':state.stage==='save_grant'?'Keep this verified reusable grant encrypted in Wallet. The application receives only a separate finite credential after your next review.':state.stage==='grant_recovery'?'The service may have issued the grant. Check the exact original enrollment while this popup remains open; no new signature or automatic save is sent.':'An earlier popup closed before its grant result was saved. That grant may still exist. Starting again requires a new review and may obtain another grant; it does not cancel the earlier one.';
    for(const [id,stage]of [['obtain-grant','grant_review'],['save-grant','save_grant'],['recover-grant','grant_recovery'],['acknowledge-grant','grant_uncertain']])$(id).hidden=state.stage!==stage;
  }
  if(['unlocking','preparing','opening'].includes(state.stage))buttons.filter(b=>b.id!=='cancel').forEach(b=>b.disabled=true);
}
$('unlock').addEventListener('submit',event=>{event.preventDefault();const input=$('passphrase') as HTMLInputElement;const value=input.value;input.value='';void host?.unlock(value);});
$('trust').onclick=()=>void host?.trust();
$('choose-duration').onclick=()=>void host?.chooseLifetime(Number(($('duration') as HTMLSelectElement).value));
$('refresh-approved').onclick=()=>void host?.prepareGrant();
$('prepare-grant').onclick=()=>void host?.prepareGrant();
$('obtain-grant').onclick=()=>void host?.obtainGrant();
$('save-grant').onclick=()=>void host?.saveGrant();
$('recover-grant').onclick=()=>void host?.recoverGrant();
$('acknowledge-grant').onclick=()=>void host?.acknowledgeEnrollment();
$('send-original').onclick=()=>void host?.requestAccess(true);
$('approve').onclick=()=>void host?.approve();
$('request-access').onclick=()=>void host?.requestAccess();
$('confirm-request').onclick=()=>void host?.confirmRequest();
$('cancel').onclick=()=>{host?.cancel();window.close();};
window.addEventListener('pagehide',()=>host?.dispose(),{once:true});
void(async()=>{
  try{
    const id=new URL(location.href).searchParams.get('login')??'';
    host=await createSessionLoginPopupHost(chrome,id,()=>new Worker(chrome.runtime.getURL('dist/session-login-worker.js'),{type:'module'}),render);
    $('origin').textContent=host.origin;render({stage:'unlock'});
  }catch{render({stage:'failed',message:'This login is no longer available. Return to the application and try again.'});}
})();
