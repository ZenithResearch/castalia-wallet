declare const chrome:any
const requestId=new URL(location.href).searchParams.get('request')
const approve=document.getElementById('approve') as HTMLButtonElement
const deny=document.getElementById('deny') as HTMLButtonElement
const status=document.getElementById('status')!
function send(message:unknown):Promise<any>{return new Promise((resolve,reject)=>chrome.runtime.sendMessage(message,(r:any)=>{if(chrome.runtime.lastError||!r?.ok)reject(new Error(r?.error??'confirmation_unavailable'));else resolve(r)}))}
async function decide(approved:boolean){approve.disabled=true;deny.disabled=true;try{await send({type:'RESOLVE_CREDENTIAL_PRESENTATION_CONFIRMATION',requestId,approved})}catch(e){status.textContent=e instanceof Error?e.message:'Confirmation unavailable'}}
approve.addEventListener('click',()=>void decide(true));deny.addEventListener('click',()=>void decide(false))
void(async()=>{try{
 if(!requestId)throw new Error('Missing confirmation request')
 const {summary}=await send({type:'GET_CREDENTIAL_PRESENTATION_CONFIRMATION',requestId})
 document.getElementById('issuer')!.textContent=summary.issuer
 document.getElementById('title')!.textContent=summary.disclosure.title
 document.getElementById('statements')!.textContent=summary.disclosure.statements.join('\n\n')
 document.getElementById('bindings')!.textContent=JSON.stringify({...summary,disclosure:undefined},null,2)
 approve.disabled=false;deny.disabled=false
}catch(e){status.textContent=e instanceof Error?e.message:'Confirmation unavailable'}})()
