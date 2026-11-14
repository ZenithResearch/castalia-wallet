/** Separate data-only bridge. It never accepts page choices or destination. */
export function forwardSelectedFeeds(chrome:any,payload:unknown,reply:(value:unknown)=>void,page:Pick<Window,'addEventListener'|'removeEventListener'|'top'>,gesture:boolean){
  if(page.top!==page||!gesture||!payload||typeof payload!=='object'||Array.isArray(payload)||Object.keys(payload).length!==0){reply({ok:false,error:'approval_required'});return}
  const port=chrome.runtime.connect({name:'castalia-selected-feeds-v1'});let done=false
  const finish=(value:unknown)=>{if(done)return;done=true;page.removeEventListener('pagehide',cancel);port.onMessage.removeListener(finish);port.onDisconnect.removeListener(cancel);try{reply(value)}finally{try{port.disconnect()}catch{}}}
  const cancel=()=>finish({ok:false,error:'feed_projection_context_changed'})
  page.addEventListener('pagehide',cancel,{once:true});port.onMessage.addListener(finish);port.onDisconnect.addListener(cancel)
  try{port.postMessage({})}catch{cancel()}
}
export function installSelectedFeedsLifecycle(chrome:any,page:Pick<Window,'addEventListener'|'top'>){
  if(page.top!==page)return
  page.addEventListener('pagehide',()=>{void chrome.runtime.sendMessage({type:'CASTALIA_SELECTED_FEEDS_DOCUMENT_CLOSED'}).catch(()=>{})})
}
