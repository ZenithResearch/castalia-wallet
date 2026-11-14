import { WasmFeedProjectionV1 } from './generated/castalia-wallet-core/bindings.js'
import type { FeedProjectionSource } from './wallet-identities-store.js'
import type { FeedSection } from './wallet-feeds.js'

export type FeedProjectionDocument={origin:string;tabId:number;documentId:string}
/** Trusted host object, not a page request or serializable approval. verify must
 * obtain actual browser/native destination identity, never echo page input.
 * The fixed deliver callback sends only to that verified request owner. */
export type FeedProjectionContext={
  current():boolean
  verify():Promise<FeedProjectionDocument>
  deliver(selectedSection:string):boolean
}
type Immutable<T>=T extends object?{readonly [K in keyof T]:Immutable<T[K]>}:T
export type FeedProjectionSummary=Immutable<{kind:'selected_feeds';origin:string;section:FeedSection;expiresAt:number}>
/** Freeze only the bounded, Rust-produced data tree. A later message/UI adapter
 * must render its serialized copy read-only; changed choices need preparation. */
function freezeSummary(summary:{kind:'selected_feeds';origin:string;section:FeedSection;expiresAt:number}):FeedProjectionSummary{
  for(const source of summary.section.subscriptions){Object.freeze(source.collectionIds);Object.freeze(source)}
  for(const collection of summary.section.collections)Object.freeze(collection)
  Object.freeze(summary.section.subscriptions);Object.freeze(summary.section.collections)
  Object.freeze(summary.section.preferences);Object.freeze(summary.section)
  return Object.freeze(summary)
}
type State={setupComplete:boolean;unlocked:boolean;memberKey:string;approvedOrigins:ReadonlySet<string>}
type Dependencies={
  run<T>(operation:()=>Promise<T>):Promise<T>
  state():Promise<State|null>;epoch():number;nowMs():number
  supportsDestination?(origin:string):boolean
  source():Promise<FeedProjectionSource>
  confirmation:{
    confirm(input:{summary:FeedProjectionSummary;tabId:number;owner:object}):Promise<boolean>
    cancelForOwner(owner:object):void
  }
}
/** Unregistered Wallet-private controller. This adds no provider method, grant,
 * session capability or production enablement. Selection comes from a trusted
 * host UI, source from Wallet storage, destination from the trusted context.
 * All authority/source mutations must use this FIFO or synchronously invalidate
 * epoch/context. Human consent occurs outside the FIFO. No approval is returned.
 */
export function createFeedProjectionController(deps:Dependencies){
  const used=new WeakSet<FeedProjectionContext>()
  const active=new Set<{cancel():void}>()
  const invalid=()=>Error('feed_projection_context_changed')
  return {
    invalidate(){for(const entry of [...active])entry.cancel()},
    async reviewAndDeliver(selection:Uint8Array,context:FeedProjectionContext):Promise<void>{
      if(used.has(context))throw Error('feed_projection_consumed')
      used.add(context)
      if(active.size>=16)throw Error('feed_projection_capacity')
      if(!(selection instanceof Uint8Array)||selection.length===0||selection.length>262144)throw Error('invalid_feed_selection')
      const choices=selection.slice(),epoch=deps.epoch(),createdAt=deps.nowMs()
      if(!Number.isSafeInteger(createdAt)||createdAt<0||createdAt>Number.MAX_SAFE_INTEGER-120_000)throw Error('invalid_clock')
      const expiresAt=Math.floor(createdAt/1000)+120,deadline=expiresAt*1000
      const current=context.current.bind(context),verify=context.verify.bind(context),deliver=context.deliver.bind(context)
      let lastObservedNow=createdAt
      let cancelled=false,source:FeedProjectionSource|undefined,prepared:WasmFeedProjectionV1|undefined
      const disposeProjection=()=>{const p=prepared;prepared=undefined;if(p){try{p.dispose()}finally{p.free()}}}
      let signalCancellation!:()=>void
      const cancellation=new Promise<false>(resolve=>{signalCancellation=()=>resolve(false)})
      const owner={cancel(){
        cancelled=true;choices.fill(0);signalCancellation()
        // A faulty host cleanup must not mask refusal, strand consent awaits,
        // or retain the other independent resources.
        try{deps.confirmation.cancelForOwner(owner)}catch{}
        const captured=source;source=undefined
        try{captured?.dispose()}catch{}
        try{disposeProjection()}catch{}
      }}
      active.add(owner)
      function live(){
        const now=deps.nowMs()
        if(cancelled||!current()||deps.epoch()!==epoch)throw invalid()
        // Refuse every observed rollback, including one still above creation.
        // No claim is made about clock changes between these observations.
        if(!Number.isSafeInteger(now)||now<lastObservedNow||now>=deadline)throw Error('feed_projection_expired')
        lastObservedNow=now
      }
      async function document(expected?:FeedProjectionDocument){
        live();const actual=await verify();live()
        if(!actual||typeof actual.origin!=='string'||!actual.origin||actual.origin.length>2048||
          !Number.isSafeInteger(actual.tabId)||actual.tabId<0||typeof actual.documentId!=='string'||!actual.documentId||actual.documentId.length>256)throw invalid()
        if(expected&&(actual.origin!==expected.origin||actual.tabId!==expected.tabId||actual.documentId!==expected.documentId))throw invalid()
        return Object.freeze({origin:actual.origin,tabId:actual.tabId,documentId:actual.documentId})
      }
      function policy(state:State|null,origin:string,expectedOwner?:string):asserts state is State{
        live()
        if(!state?.setupComplete||!state.unlocked||! /^[a-f0-9]{64}$/.test(state.memberKey))throw Error('wallet_locked')
        if(expectedOwner!==undefined&&state.memberKey!==expectedOwner)throw invalid()
        if(deps.supportsDestination?.(origin)!==true)throw Error('feed_projection_unsupported')
        if(!state.approvedOrigins.has(origin))throw Error('origin_not_approved')
        live()
      }
      try{
        const initial=await deps.run(async()=>{
          const target=await document();const state=await deps.state();policy(state,target.origin)
          source=await deps.source();live()
          if(source.owner!==state.memberKey||source.epoch!==epoch)throw invalid()
          await document(target);policy(state,target.origin,source.owner)
          const raw=source.copySource()
          try{prepared=new WasmFeedProjectionV1(raw,choices,target.origin)}
          finally{raw.fill(0);choices.fill(0)}
          return {target,owner:source.owner,section:JSON.parse(prepared.previewJson()) as FeedSection}
        })
        live() // cancellation while leaving the queue cannot open a new popup
        const summary=freezeSummary({kind:'selected_feeds',origin:initial.target.origin,section:initial.section,expiresAt})
        const approved=await Promise.race([deps.confirmation.confirm({summary,tabId:initial.target.tabId,owner}),cancellation])
        if(approved!==true)throw Error('approval_denied')
        await deps.run(async()=>{
          live();const state=await deps.state();policy(state,initial.target.origin,initial.owner)
          await document(initial.target);policy(state,initial.target.origin,initial.owner)
          if(!source||!prepared)throw invalid()
          await source.consumeCurrent(raw=>{
            // Last awaited operation was the source's exact encrypted-record
            // fence. Recheck synchronous policy/lifetime before consume+send.
            policy(state,initial.target.origin,initial.owner)
            if(!prepared)throw invalid()
            const selected=prepared.confirm(raw,initial.target.origin)
            disposeProjection() // consumed/disposed even if delivery throws
            if(deliver(selected)!==true)throw Error('feed_projection_delivery_failed')
            return true
          })
        })
      }finally{
        choices.fill(0);owner.cancel()
        // Cancellation frees sensitive resources immediately, but queued or
        // in-flight work keeps its capacity slot until this actual unwind.
        active.delete(owner)
      }
    },
  }
}
