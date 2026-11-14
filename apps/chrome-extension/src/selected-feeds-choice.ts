import {selectionForChoices,text,sourceTitle,collectionTitle} from './selected-feeds-ui.js'
import type {FeedSection} from './wallet-feeds.js'
declare const chrome:any
const id=new URL(location.href).searchParams.get('request'),status=document.querySelector<HTMLElement>('#status')!,next=document.querySelector<HTMLButtonElement>('#continue')!,cancel=document.querySelector<HTMLButtonElement>('#cancel')!
const send=async(type:string,extra:object={})=>{const response=await chrome.runtime.sendMessage({type,requestId:id,...extra});if(response?.ok!==true)throw Error(response?.error??'approval_unavailable');return response}
const error=(e:unknown)=>{status.textContent=e instanceof Error?e.message:'Selection is unavailable.';next.disabled=true}
void(async()=>{
  const result=await send('GET_SELECTED_FEEDS_CHOICES'),section:FeedSection=result.section
  document.querySelector('#origin')!.textContent=result.origin
  document.querySelector('#expires')!.textContent=new Date(result.expiresAt*1000).toLocaleTimeString()
  const sources=new Set<string>(),labels=new Set<string>(),members=new Set<string>(),updates:(()=>void)[]=[]
  function choice(parent:HTMLElement,label:string,className:string,key:string,values:Set<string>,disabled=false){const row=text(document,parent,'label',''),input=document.createElement('input');input.type='checkbox';input.className=className;input.dataset.key=key;input.disabled=disabled;input.checked=false;row.appendChild(input);text(document,row,'span',label);input.addEventListener('change',()=>{if(input.checked)values.add(key);else values.delete(key);for(const update of updates)update()});return input}
  const collectionRoot=document.querySelector<HTMLElement>('#collections')!
  for(const label of section.collections)choice(collectionRoot,`${collectionTitle(label.title)} (${label.id})`,'label-choice',label.id,labels)
  const sourceRoot=document.querySelector<HTMLElement>('#sources')!
  for(const source of section.subscriptions){const row=text(document,sourceRoot,'section',''),eligible=source.disclosure==='selected';choice(row,sourceTitle(source.title)+(eligible?'':' — private; unavailable for sharing'),'source-choice',source.id,sources,!eligible);text(document,row,'p',source.url);text(document,row,'p',`Source ID: ${source.id}`)
    for(const labelID of source.collectionIds){const label=section.collections.find(c=>c.id===labelID),key=JSON.stringify([source.id,labelID]),input=choice(row,`Include membership: ${label?collectionTitle(label.title):labelID}`,'membership-choice',key,members,true);updates.push(()=>{input.disabled=!eligible||!sources.has(source.id)||!labels.has(labelID);if(input.disabled){input.checked=false;members.delete(key)}})}
  }
  next.disabled=false;cancel.disabled=false
  next.addEventListener('click',()=>{next.disabled=true;cancel.disabled=true;void send('SUBMIT_SELECTED_FEEDS_CHOICES',{selection:JSON.stringify(selectionForChoices(section,sources,labels,members))}).catch(error)})
  cancel.addEventListener('click',()=>{next.disabled=true;cancel.disabled=true;void send('CANCEL_SELECTED_FEEDS_CHOICES').catch(error)})
})().catch(error)
