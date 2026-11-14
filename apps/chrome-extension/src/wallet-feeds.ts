/** Data-only host projection. The Rust core validates every complete candidate. */
export type FeedCollection={id:string;title:string}
export type FeedSubscription={id:string;url:string;format:'auto'|'rss'|'atom';title:string;enabled:boolean;collectionIds:string[];disclosure:'private'|'selected'}
export type FeedSection={schema:'castalia.feeds-section.v1';version:1;subscriptions:FeedSubscription[];collections:FeedCollection[];preferences:{order:'newest-first'}}
export type FeedReview={incoming:FeedSection|null;preserved:FeedSection|null;combined:FeedSection|null}

function stable(value:any):string{return JSON.stringify(value&&typeof value==='object'?Array.isArray(value)?value.map(v=>JSON.parse(stable(v))):Object.fromEntries(Object.keys(value).sort().map(k=>[k,JSON.parse(stable(value[k]))])):value)}

/** Absent/empty imports never delete. Preserve order and fail the whole candidate
 * when an existing ID describes different values, including collection labels. */
export function mergeFeedSections(current:FeedSection|null,incoming:FeedSection|null):FeedSection|null{
  if(!current)return structuredClone(incoming)
  if(!incoming)return structuredClone(current)
  const merged=structuredClone(current)
  for(const field of ['collections','subscriptions'] as const){
    const records=merged[field] as (FeedCollection|FeedSubscription)[]
    for(const record of incoming[field]){
      const old=records.find(value=>value.id===record.id)
      if(old&&stable(old)!==stable(record))throw Error('feed_conflict')
      if(!old)records.push(structuredClone(record))
    }
  }
  return merged
}

/** Plain text only: no anchors, HTML, requests, activation or provider actions. */
export function feedReviewRows(section:FeedSection|null):string[]{
  if(!section)return ['No feed section.']
  return [
    `${section.subscriptions.length} source(s), ${section.collections.length} collection(s); order: ${section.preferences.order}.`,
    ...section.collections.map(c=>`Collection ${c.id} · title ${JSON.stringify(c.title)}`),
    ...section.subscriptions.map(s=>`Source ${s.id} · title ${JSON.stringify(s.title)} · ${s.url} · format ${s.format} · enabled preference ${s.enabled} · disclosure ${s.disclosure} · collections ${s.collectionIds.map(id=>`${id} (${JSON.stringify(section.collections.find(c=>c.id===id)?.title??'')})`).join(', ')||'none'}`),
  ]
}

export function walletDataError(message:string):string{
  const text:Record<string,string>={
    feed_conflict:'A source or collection ID has different saved values. Nothing was imported.',
    feed_storage_not_qualified:'Feed import is not enabled in this Wallet yet. Existing data was preserved.',
    feed_writer_not_qualified:'Saving a feed-bearing Castaway file is not enabled yet. Existing data was preserved.',
    file_too_large:'The complete encrypted Castaway file would exceed 1 MiB. Existing data was preserved.',
    feeds_too_large:'Feed configuration exceeds 256 KiB. Existing data was preserved.',
    invalid_wallet_file:'The file or combined Wallet data is invalid or exceeds a supported limit. Existing data was preserved.',
    identities_changed:'Saved Wallet data changed. Refresh and review the import again.',
    import_review_expired:'This import review expired or was cancelled. Review the file again.',
  }
  return text[message]??message
}
