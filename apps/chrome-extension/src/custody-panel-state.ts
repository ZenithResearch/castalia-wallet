import type { CustodyState } from './state/custody-state.js'

export const CUSTODY_PANEL_PORT = 'castalia-custody-panel-v1'
export type CustodyPanelSnapshot = {
  state: CustodyState
  chainAccounts: Array<{networkId: string; address: string}>
}

// Public display fields only. This channel cannot carry root custody, approvals,
// encrypted records, passwords, or commands from a page to the signer.
function snapshot(value: any): CustodyPanelSnapshot {
  const s=value?.state,accounts=value?.chainAccounts
  if(!s || typeof s.setupComplete!=='boolean' || typeof s.unlocked!=='boolean' ||
    (s.publicKey!==null && (typeof s.publicKey!=='string'||!/^[a-f0-9]{64}$/.test(s.publicKey))) ||
    s.unlocked&&!s.setupComplete || s.setupComplete!==(s.publicKey!==null) ||
    !Array.isArray(accounts)||accounts.length>32||!s.unlocked&&accounts.length)throw Error('invalid_custody_state')
  return {state:{setupComplete:s.setupComplete,unlocked:s.unlocked,publicKey:s.publicKey},
    chainAccounts:accounts.map((a:any)=>{
      if(typeof a?.networkId!=='string'||typeof a.address!=='string'||a.networkId.length>128||a.address.length>512)throw Error('invalid_custody_state')
      return {networkId:a.networkId,address:a.address}
    })}
}

/** Passive observer: no timers, alarms, heartbeats, custody persistence or retries. */
export function installCustodyPanelRuntime(chrome:any,deps:{snapshot():Promise<unknown>;subscribe(f:()=>void):()=>void}){
  chrome.runtime.onConnect.addListener((port:any)=>{
    if(port.name!==CUSTODY_PANEL_PORT)return
    const sender=port.sender,urls=['src/sidepanel.html','src/popup.html'].map(p=>chrome.runtime.getURL(p))
    if(sender?.id!==chrome.runtime.id||!urls.includes(sender?.url)||sender.frameId!==undefined&&sender.frameId!==0){port.disconnect();return}
    let live=true,revision=0
    let unsubscribe=()=>{}
    const close=()=>{if(!live)return;live=false;revision++;unsubscribe()}
    const publish=()=>{
      const current=++revision
      void deps.snapshot().then(value=>{
        if(live&&revision===current)port.postMessage({type:'CUSTODY_PANEL_STATE',...snapshot(value)})
      }).catch(()=>{close();try{port.disconnect()}catch{}})
    }
    port.onDisconnect.addListener(close)
    unsubscribe=deps.subscribe(publish)
    publish()
  })
}

/** Losing a worker invalidates Ready immediately; reconnect only on user events. */
export function observeCustodyPanel(runtime:any,view:{snapshot(value:CustodyPanelSnapshot):void;unavailable():void}){
  let port:any=null,revision=0,disposed=false
  const refresh=()=>{
    if(disposed)return
    const current=++revision,old=port;port=null
    try{old?.disconnect()}catch{}
    view.unavailable()
    try{
      const connected=runtime.connect({name:CUSTODY_PANEL_PORT});port=connected
      const unavailable=()=>{
        if(disposed||revision!==current)return
        // Consume Chrome's bounded disconnect error; never display diagnostics.
        void runtime.lastError
        revision++;port=null;view.unavailable()
      }
      connected.onDisconnect.addListener(unavailable)
      connected.onMessage.addListener((message:any)=>{
        if(disposed||revision!==current)return
        try{
          if(message?.type!=='CUSTODY_PANEL_STATE')throw Error('invalid_custody_state')
          view.snapshot(snapshot(message))
        }catch{unavailable();try{connected.disconnect()}catch{}}
      })
    }catch{if(revision===current){revision++;port=null;view.unavailable()}}
  }
  return {refresh,dispose(){if(disposed)return;disposed=true;revision++;const old=port;port=null;try{old?.disconnect()}catch{}}}
}
