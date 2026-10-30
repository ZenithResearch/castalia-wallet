import {grantCardPresentation} from './holder-grants-presentation.js';
import {permissionPresentation} from './session-login-presentation.js';

/** Wallet-owned display. All provider-controlled values use textContent. */
export function displayGrants(target:HTMLElement,records:any[],onRemove?:(service:string,trigger:HTMLButtonElement)=>void) {
  const doc=target.ownerDocument;
  const element=(tag:string,text?:string,className?:string)=>{
    const node=doc.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;
  };
  target.replaceChildren();
  for(const record of records){
    const c=record.grant??record,view=grantCardPresentation(record),card=element('article',undefined,'grant-card');
    const details=doc.createElement('details'),summary=doc.createElement('summary');
    const heading=element('div',undefined,'grant-heading');heading.append(element('h2',view.title),element('p',view.service,'service-id'));
    summary.append(heading,element('span',view.status,'grant-badge'));
    const subtitle=element('p',`${view.permissionCount} · ${view.validity}`,'grant-subtitle');
    summary.append(subtitle,element('span','View details','details-cue'));details.append(summary);
    const body=element('div',undefined,'grant-details');
    body.append(element('p','Saved copy only. The service checks current approval when you use it.','muted'));
    const metadata=doc.createElement('dl');
    for(const [label,value] of [['Provider',c.issuer],['Service',c.service],['Grant ID',c.grant_id],['Revision',c.revision],
      ['Wallet identity',c.holder_public_key],['Installation',c.installation_id??'Not bound to one installation'],
      ['Valid from',new Date(c.validity.not_before*1000).toLocaleString()],['Validity',view.validity],
      ['Maximum credential duration',`${c.max_credential_lifetime_seconds} seconds`],['Onward delegation',c.onward_delegation===false?'Disabled':String(c.onward_delegation)]]){
      const row=element('div');row.append(element('dt',label),element('dd',String(value)));metadata.append(row);
    }
    body.append(metadata,element('h3','Permissions'));
    for(const permission of c.permissions){
      const view=permissionPresentation(permission),item=element('div',undefined,'permission');
      item.append(element('h4',view.label),element('code',String(permission.operation)),element('pre',view.restrictions));body.append(item);
    }
    const raw=doc.createElement('details');raw.className='technical-details';raw.append(element('summary','All grant fields'),element('pre',JSON.stringify(c,null,2)));body.append(raw);
    details.append(body);card.append(details);
    if(onRemove){
      const actions=element('div',undefined,'grant-actions'),update=doc.createElement('details');update.className='update-help';
      update.append(element('summary','Update access'));
      const steps=element('div',undefined,'update-steps');steps.append(element('p','If the owner changed your permissions, retrieve the current approved grant. You do not need to remove this copy first.'));
      const list=doc.createElement('ol');
      for(const text of ['Open the service and choose Sign in with Wallet.','In Wallet, open Saved access help → Check saved access.','Choose Check approved access, review the grant, then Save grant in Wallet.'])list.append(element('li',text));
      steps.append(list,element('p','Saving replaces only this service’s local copy. Then review a new browser session to use the updated access.','muted'));update.append(steps);
      const remove=doc.createElement('button');remove.type='button';remove.className='remove-action';remove.textContent='Remove from Wallet';remove.setAttribute('aria-label',`Remove ${view.title} grant from Wallet`);remove.onclick=()=>onRemove(view.service,remove);
      actions.append(update,remove);card.append(actions);
    }
    target.append(card);
  }
  if(!records.length){const empty=element('div',undefined,'empty-state');empty.append(element('h2','No saved grants'),element('p','Connect to a service and choose Save grant in Wallet. Your approved access may still exist on the service.'));target.append(empty);}
}
