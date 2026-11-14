import {showSection} from './selected-feeds-ui.js'
declare const chrome:any
const requestId=new URL(location.href).searchParams.get('request'),status=document.querySelector<HTMLElement>('#status')!,approve=document.querySelector<HTMLButtonElement>('#approve')!,deny=document.querySelector<HTMLButtonElement>('#deny')!
const send=async(type:string,extra:object={})=>{const response=await chrome.runtime.sendMessage({type,requestId,...extra});if(response?.ok!==true)throw Error(response?.error??'approval_unavailable');return response}
const error=(e:unknown)=>{status.textContent=e instanceof Error?e.message:'Confirmation is unavailable.';approve.disabled=true;deny.disabled=true}
void(async()=>{const {summary}=await send('GET_SELECTED_FEEDS_CONFIRMATION');if(summary.kind!=='selected_feeds')throw Error('Unsupported confirmation.')
  document.querySelector('#origin')!.textContent=summary.origin;document.querySelector('#expires')!.textContent=new Date(summary.expiresAt*1000).toLocaleTimeString();showSection(document,document.querySelector<HTMLElement>('#selected')!,summary.section)
  const decide=(approved:boolean)=>{approve.disabled=true;deny.disabled=true;void send('RESOLVE_SELECTED_FEEDS_CONFIRMATION',{approved}).catch(error)}
  approve.disabled=false;deny.disabled=false;approve.addEventListener('click',()=>decide(true));deny.addEventListener('click',()=>decide(false))
})().catch(error)
