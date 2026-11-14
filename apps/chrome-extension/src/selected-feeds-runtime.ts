import {createFeedProjectionController, type FeedProjectionSummary} from './feed-projection-controller.js'
import {createOperationConfirmationBroker} from './operation-confirmation-broker.js'
import type {FeedProjectionSource} from './wallet-identities-store.js'
import type {FeedSection} from './wallet-feeds.js'

/** An explicit host qualification boundary; no page/storage/environment switch. */
export const SELECTED_FEEDS_QUALIFIED = false
export const SELECTED_FEEDS_CAPABILITY = 'selected_feeds_v1'
export const SELECTED_FEEDS_PORT = 'castalia-selected-feeds-v1'
type State={setupComplete:boolean;unlocked:boolean;memberKey:string;approvedOrigins:ReadonlySet<string>}
type Dependencies={
  run<T>(operation:()=>Promise<T>):Promise<T>;state():Promise<State|null>;epoch():number
  onChange(callback:()=>void):()=>void;source():Promise<FeedProjectionSource>
}
type Qualification={qualified:boolean;supportsDestination(origin:string):boolean}
type Clock={nowMs():number;setTimeout(callback:()=>void,ms:number):unknown;clearTimeout(timer:unknown):void}
const defaultClock:Clock={nowMs:Date.now,setTimeout:(f,ms)=>setTimeout(f,ms),clearTimeout:t=>clearTimeout(t as ReturnType<typeof setTimeout>)}
const closed=(value:unknown,keys:string[]):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',')
const failure=(error:unknown)=>{
  const code=error instanceof Error?error.message:''
  const allowed=['feed_projection_capacity','feed_projection_unsupported','feed_projection_context_changed','feed_projection_expired','feed_projection_delivery_failed','origin_not_approved','wallet_locked','feed_source_unavailable','identities_changed','wallet_changed_or_locked','approval_denied','approval_unavailable','invalid_feed_request','invalid_feed_selection','invalid_confirmation_sender']
  return allowed.includes(code)?code:'feed_projection_failed'
}
type Owner={tabId:number;documentId:string;url:string;cancel():void}
type Popup={url:string;windowId?:number;tabId?:number;documentId?:string;claimed:boolean;open:Promise<void>;owner:Owner;handle(message:Record<string,unknown>):unknown}

/** Browser-owned bridge only. Default production policy denies before custody
 * reads. A fixture may inject qualification without changing a production flag.
 * All live operations, including canceled queued work, occupy one global budget.
 */
export function installSelectedFeedsRuntime(chrome:any,deps:Dependencies,qualification?:Qualification,clock:Clock=defaultClock){
  const policy=qualification??{qualified:SELECTED_FEEDS_QUALIFIED,supportsDestination:()=>false}
  const qualified=()=>policy.qualified&&typeof chrome.runtime.getContexts==='function'
  const active=new Set<Owner>(),documents=new Map<number,string>(),popups=new Map<string,Popup>()
  let disposed=false
  function invalidate(tabId?:number){for(const owner of [...active])if(tabId===undefined||owner.tabId===tabId)owner.cancel();if(tabId===undefined)documents.clear();else documents.delete(tabId)}
  const unsubscribe=deps.onChange(()=>invalidate())
  const updated=(id:number,change:any)=>{for(const owner of [...active])if(owner.tabId===id&&(change.status==='loading'||typeof change.url==='string'&&change.url!==owner.url)){invalidate(id);break}}
  const removed=(id:number)=>invalidate(id)
  chrome.tabs.onUpdated.addListener(updated);chrome.tabs.onRemoved.addListener(removed)
  const onMessage=(message:any,sender:any,respond:(value:unknown)=>void)=>{
    if(message?.type==='CASTALIA_SELECTED_FEEDS_DOCUMENT_CLOSED'){
      if(closed(message,['type'])&&sender?.id===chrome.runtime.id&&sender.frameId===0&&Number.isSafeInteger(sender.tab?.id)&&documents.get(sender.tab.id)===sender.documentId)invalidate(sender.tab.id)
      return false
    }
    if(!['GET_SELECTED_FEEDS_CHOICES','SUBMIT_SELECTED_FEEDS_CHOICES','CANCEL_SELECTED_FEEDS_CHOICES','GET_SELECTED_FEEDS_CONFIRMATION','RESOLVE_SELECTED_FEEDS_CONFIRMATION'].includes(message?.type))return false
    void(async()=>{
      if(typeof message.requestId!=='string')throw Error('invalid_confirmation_sender')
      const popup=popups.get(message.requestId)
      if(!popup)throw Error('approval_unavailable')
      await popup.open
      if(popups.get(message.requestId)!==popup||sender?.id!==chrome.runtime.id||sender.frameId!==undefined&&sender.frameId!==0||sender.url!==popup.url||sender.tab!==undefined&&sender.tab.id!==popup.tabId||typeof sender.documentId!=='string'||!sender.documentId||sender.documentLifecycle&&sender.documentLifecycle!=='active')throw Error('invalid_confirmation_sender')
      if(typeof chrome.runtime.getContexts!=='function')throw Error('approval_unavailable')
      const contexts=await chrome.runtime.getContexts({documentIds:[sender.documentId],documentUrls:[popup.url],windowIds:[popup.windowId],frameIds:[0]})
      if(popups.get(message.requestId)!==popup||contexts.length!==1||contexts[0].documentId!==sender.documentId||contexts[0].documentUrl!==popup.url||contexts[0].windowId!==popup.windowId||contexts[0].tabId!==popup.tabId||contexts[0].frameId!==0)throw Error('invalid_confirmation_sender')
      if(popup.documentId!==undefined&&sender.documentId!==popup.documentId)throw Error('invalid_confirmation_sender')
      const claiming=message.type==='GET_SELECTED_FEEDS_CHOICES'||message.type==='GET_SELECTED_FEEDS_CONFIRMATION'
      if(claiming){if(popup.claimed)throw Error('approval_unavailable');popup.claimed=true;popup.documentId=sender.documentId}
      else if(!popup.claimed)throw Error('approval_unavailable')
      return popup.handle(message)
    })().then(result=>respond({ok:true,...result as object}),error=>respond({ok:false,error:failure(error)}))
    return true
  }
  chrome.runtime.onMessage.addListener(onMessage)
  const onConnect=(port:any)=>{
    if(port.name!==SELECTED_FEEDS_PORT)return
    if(disposed||!qualified()){try{port.postMessage({ok:false,error:'feed_projection_unsupported'})}finally{try{port.disconnect()}catch{}};return}
    if(active.size>=16){try{port.postMessage({ok:false,error:'feed_projection_capacity'})}finally{try{port.disconnect()}catch{}};return}
    const sender=port.sender,tabId=sender?.tab?.id,documentId=sender?.documentId,url=sender?.url
    let origin=''
    try{
      if(sender?.id!==chrome.runtime.id||sender.frameId!==0||!Number.isSafeInteger(tabId)||tabId<0||typeof documentId!=='string'||!documentId||documentId.length>256||typeof url!=='string'||url.length>8192||url!==sender.tab.url||sender.documentLifecycle&&sender.documentLifecycle!=='active')throw Error()
      const parsed=new URL(url);origin=parsed.origin
      if(parsed.protocol!=='https:'&&!(parsed.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(parsed.hostname)))throw Error()
      if(parsed.username||parsed.password)throw Error()
    }catch{try{port.postMessage({ok:false,error:'feed_projection_context_changed'})}finally{try{port.disconnect()}catch{}};return}
    // Unsupported destinations learn availability only, without custody reads.
    let supported=false;try{supported=policy.supportsDestination(origin)===true}catch{}
    if(!supported){try{port.postMessage({ok:false,error:'feed_projection_unsupported'})}finally{try{port.disconnect()}catch{}};return}
    const old=documents.get(tabId);if(old!==undefined&&old!==documentId)invalidate(tabId);documents.set(tabId,documentId)
    const created=clock.nowMs(),deadline=created+120_000,epoch=deps.epoch()
    let lastNow=created,clockInvalid=false,live=true,used=false,running=false,timer:unknown,source:FeedProjectionSource|undefined,controller:ReturnType<typeof createFeedProjectionController>|undefined
    let cancelChoice:()=>void=()=>{},cancelConsent:()=>void=()=>{}
    const popupIDs=new Set<string>(),windowIDs=new Set<number>()
    function current(){const now=clock.nowMs();if(clockInvalid||!Number.isSafeInteger(now)||!Number.isSafeInteger(deadline)||created<0||now<lastNow||now>=deadline){clockInvalid=true;return false};lastNow=now;return live&&!disposed&&deps.epoch()===epoch&&documents.get(tabId)===documentId}
    function check(){if(!current())throw Error('feed_projection_expired')}
    async function verify(){check();const tab=await chrome.tabs.get(tabId);check();if(tab?.url!==url||tab.status==='loading')throw Error('feed_projection_context_changed');return {origin,tabId,documentId}}
    function checkPolicy(state:State|null){check();if(!qualified()||policy.supportsDestination(origin)!==true)throw Error('feed_projection_unsupported');if(!state?.approvedOrigins.has(origin))throw Error('origin_not_approved');if(!state.setupComplete||!state.unlocked||!/^[a-f0-9]{64}$/.test(state.memberKey))throw Error('wallet_locked');return state}
    const onRemoved=(id:number)=>{if(windowIDs.has(id))owner.cancel()}
    const owner:Owner={tabId,documentId,url,cancel(){
      const wasLive=live;live=false;clock.clearTimeout(timer)
      try{cancelChoice()}catch{};try{cancelConsent()}catch{};try{controller?.invalidate()}catch{}
      const captured=source;source=undefined;try{captured?.dispose()}catch{}
      for(const id of popupIDs)popups.delete(id);popupIDs.clear()
      for(const id of windowIDs)void chrome.windows.remove(id).catch(()=>{});windowIDs.clear()
      if(wasLive){try{port.disconnect()}catch{}}
      if(!running){active.delete(owner);chrome.windows.onRemoved.removeListener(onRemoved)}
    }}
    active.add(owner)
    function reply(result:unknown){try{if(live)port.postMessage(result)}finally{owner.cancel()}}
    timer=clock.setTimeout(()=>{reply({ok:false,error:'feed_projection_expired'})},120_000)
    port.onDisconnect.addListener(()=>owner.cancel())
    async function openPopup(path:string,id:string,handle:Popup['handle']){
      check();const page=chrome.runtime.getURL(path)+'?request='+encodeURIComponent(id)
      let opened!:()=>void;const ready=new Promise<void>(resolve=>{opened=resolve})
      let createdWindow:number|undefined
      const popup:Popup={url:page,claimed:false,open:ready,owner,handle:message=>{try{return handle(message)}catch(error){if(failure(error)==='feed_projection_expired')reply({ok:false,error:'feed_projection_expired'});throw error}}};popups.set(id,popup);popupIDs.add(id)
      try{
        const window=await chrome.windows.create({url:page,type:'popup',width:640,height:780,focused:true})
        if(typeof window?.id!=='number')throw Error('approval_unavailable')
        createdWindow=window.id;popup.windowId=window.id;windowIDs.add(window.id)
        const tab=window.tabs?.[0]??(await chrome.windows.get(window.id,{populate:true})).tabs?.[0]
        if(!Number.isSafeInteger(tab?.id))throw Error('approval_unavailable');popup.tabId=tab.id
        check();return window.id as number
      }catch(error){popups.delete(id);popupIDs.delete(id);if(createdWindow!==undefined){windowIDs.delete(createdWindow);void chrome.windows.remove(createdWindow).catch(()=>{})};throw error}
      finally{opened()}
    }
    chrome.windows.onRemoved.addListener(onRemoved)
    port.onMessage.addListener((payload:unknown)=>{
      if(used||!live)return;used=true;running=true
      void(async()=>{
        if(!closed(payload,[]))throw Error('invalid_feed_request')
        const selected=await deps.run(async()=>{
          await verify();const state=checkPolicy(await deps.state());source=await deps.source();check()
          if(source.owner!==state.memberKey||source.epoch!==epoch)throw Error('feed_projection_context_changed')
          await verify();checkPolicy(state)
          const bytes=source.copySource();try{return JSON.parse(new TextDecoder().decode(bytes)) as FeedSection}finally{bytes.fill(0)}
        })
        check()
        // Choices reveal no data to the page. The exact snapshot remains held.
        let resolveChoices!:(value:string|null)=>void
        const choices=new Promise<string|null>(resolve=>{resolveChoices=resolve});cancelChoice=()=>resolveChoices(null)
        const choiceID=crypto.randomUUID();let choiceWindow:number|undefined
        choiceWindow=await openPopup('src/selected-feeds-choice.html',choiceID,message=>{
          check()
          if(message.type==='GET_SELECTED_FEEDS_CHOICES'&&closed(message,['type','requestId']))return {origin,section:selected,expiresAt:Math.floor(deadline/1000)}
          if(message.type==='CANCEL_SELECTED_FEEDS_CHOICES'&&closed(message,['type','requestId'])){resolveChoices(null);return {}}
          if(message.type!=='SUBMIT_SELECTED_FEEDS_CHOICES'||!closed(message,['type','requestId','selection'])||typeof message.selection!=='string'||new TextEncoder().encode(message.selection).length>262144)throw Error('invalid_feed_selection')
          // Only the strict Rust selection parser decides eligibility/closure.
          resolveChoices(message.selection);popups.delete(choiceID);return {}
        })
        const selection=await choices;check();if(selection===null)throw Error('approval_denied')
        popups.delete(choiceID);popupIDs.delete(choiceID);windowIDs.delete(choiceWindow);void chrome.windows.remove(choiceWindow).catch(()=>{})
        const broker:ReturnType<typeof createOperationConfirmationBroker<FeedProjectionSummary>>=createOperationConfirmationBroker<FeedProjectionSummary>({
          confirmationUrl:id=>id,
          createWindow:id=>openPopup('src/selected-feeds-confirmation.html',id,message=>{
            check()
            if(message.type==='GET_SELECTED_FEEDS_CONFIRMATION'&&closed(message,['type','requestId'])){const pending=broker.claimPending(id);if(!pending)throw Error('approval_unavailable');return {summary:pending.summary}}
            if(message.type!=='RESOLVE_SELECTED_FEEDS_CONFIRMATION'||!closed(message,['type','requestId','approved'])||typeof message.approved!=='boolean')throw Error('invalid_feed_request')
            if(!broker.resolve(id,message.approved))throw Error('approval_unavailable');popups.delete(id);return {}
          }),
          closeWindow:async id=>{windowIDs.delete(id);await chrome.windows.remove(id)},addWindowRemovedListener:cb=>chrome.windows.onRemoved.addListener(cb),removeWindowRemovedListener:cb=>chrome.windows.onRemoved.removeListener(cb),
          nowMs:clock.nowMs,setTimeout:clock.setTimeout,clearTimeout:clock.clearTimeout,randomId:()=>crypto.randomUUID(),
        })
        const consentOwner={};cancelConsent=()=>broker.cancelForOwner(consentOwner)
        controller=createFeedProjectionController({run:deps.run,state:deps.state,epoch:deps.epoch,nowMs:clock.nowMs,supportsDestination:destination=>policy.qualified&&destination===origin&&policy.supportsDestination(destination),source:async()=>{check();if(!source)throw Error('feed_projection_context_changed');return source},confirmation:{confirm:input=>{check();return broker.confirm({...input,owner:consentOwner,summary:{...input.summary,expiresAt:Math.floor(deadline/1000)}})},cancelForOwner:()=>broker.cancelForOwner(consentOwner)}})
        await controller.reviewAndDeliver(new TextEncoder().encode(selection),{current,verify,deliver:raw=>{check();port.postMessage({ok:true,result:raw});return true}})
      })().catch(error=>reply({ok:false,error:failure(error)})).finally(()=>{owner.cancel();chrome.windows.onRemoved.removeListener(onRemoved);active.delete(owner)})
    })
  }
  chrome.runtime.onConnect.addListener(onConnect)
  return {capabilities:()=>qualified()?[SELECTED_FEEDS_CAPABILITY]:[],dispose(){if(disposed)return;disposed=true;invalidate();unsubscribe();chrome.runtime.onConnect.removeListener(onConnect);chrome.runtime.onMessage.removeListener(onMessage);chrome.tabs.onUpdated.removeListener(updated);chrome.tabs.onRemoved.removeListener(removed)}}
}
