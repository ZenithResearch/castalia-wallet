import assert from 'node:assert/strict'
import test from 'node:test'
import {readFileSync} from 'node:fs'
import {feedReviewRows,mergeFeedSections,walletDataError} from '../src/wallet-feeds.js'

const section=JSON.parse(readFileSync(new URL('../../../contracts/feeds/v1/section.json',import.meta.url),'utf8'))
test('review text retains all inert source and collection metadata including exact empty/whitespace labels',()=>{
  const rows=feedReviewRows(section)
  for(const value of [section.subscriptions[0].id,section.subscriptions[0].url,JSON.stringify(section.subscriptions[0].title),'format atom','enabled preference true','disclosure selected',section.collections[0].id,JSON.stringify(section.collections[0].title),'newest-first'])assert.ok(rows.join('\n').includes(value),value)
  const empty=structuredClone(section);empty.subscriptions[0].title='';empty.collections[0].title='  ';assert.ok(feedReviewRows(empty).join('\n').includes('title ""'));assert.ok(feedReviewRows(empty).join('\n').includes('title "  "'))
  assert.deepEqual(feedReviewRows(null),['No feed section.'])
})
test('additive merging preserves both namespaces, order and exact values; conflicting collection or source IDs fail',()=>{
  assert.deepEqual(mergeFeedSections(section,section),section)
  assert.deepEqual(mergeFeedSections(section,{...section,subscriptions:[],collections:[]}),section)
  assert.deepEqual(mergeFeedSections(section,null),section)
  const next=structuredClone(section);next.collections[0].id=next.subscriptions[0].collectionIds[0]='31807664-3afb-43e2-98c4-1b6264c8ff0e';next.subscriptions[0].id='cf2b3f20-6dbe-402c-a7a2-bae3fb26deaf'
  const merged=mergeFeedSections(section,next)!
  assert.deepEqual(merged.collections,[...section.collections,...next.collections]);assert.deepEqual(merged.subscriptions,[...section.subscriptions,...next.subscriptions])
  for(const field of ['subscriptions','collections']){const conflicting=structuredClone(section);conflicting[field][0].title+='different';assert.throws(()=>mergeFeedSections(section,conflicting),/feed_conflict/)}
  merged.subscriptions[0].title='mutated';assert.notEqual(merged.subscriptions[0].title,section.subscriptions[0].title)
})
test('feed failures explain preserved data and closed rollout gates without suggesting login or fetching',()=>{
  for(const code of ['feed_conflict','feed_storage_not_qualified','feed_writer_not_qualified','feeds_too_large','file_too_large','identities_changed','import_review_expired']){const text=walletDataError(code);assert.notEqual(text,code);assert.doesNotMatch(text,/https?:\/\//)}
  assert.match(walletDataError('file_too_large'),/1 MiB/);assert.match(walletDataError('feeds_too_large'),/256 KiB/);assert.equal(walletDataError('wallet_changed_or_locked'),'wallet_changed_or_locked')
})
