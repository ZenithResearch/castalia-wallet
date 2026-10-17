/** One document connection owns one credential approval. */
export function forwardCredentialPresentation(port: any, payload: unknown, reply: (value: unknown) => void, page: Pick<Window,'addEventListener'|'removeEventListener'>) {
  let done=false
  const finish=(value:unknown)=>{if(done)return;done=true;page.removeEventListener('pagehide',dispose);try{reply(value)}finally{try{port.disconnect()}catch{}}}
  const dispose=()=>finish({ok:false,error:'presentation_context_changed'})
  page.addEventListener('pagehide',dispose,{once:true})
  port.onMessage.addListener(finish);port.onDisconnect.addListener(dispose)
  try{port.postMessage(payload)}catch{dispose()}
}
