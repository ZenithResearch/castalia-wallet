import type {FeedSection} from './wallet-feeds.js'
/** Presentation only: nonblank original strings and all payload bytes survive. */
export const sourceTitle=(title:string)=>title.trim()?title:'Untitled source'
export const collectionTitle=(title:string)=>title.trim()?title:'Unnamed collection'
/** Chooser convenience only; the shared Rust parser remains authoritative. */
export function selectionForChoices(section:FeedSection,sources:Set<string>,labels:Set<string>,members:Set<string>){
  const subscriptions=section.subscriptions.filter(s=>s.disclosure==='selected'&&sources.has(s.id))
  const collectionIds=section.collections.filter(c=>labels.has(c.id)).map(c=>c.id)
  return {schema:'castalia.feed-projection-selection.v1',subscriptionIds:subscriptions.map(s=>s.id),collectionIds,memberships:subscriptions.map(s=>{const ids=s.collectionIds.filter(id=>collectionIds.includes(id)&&members.has(JSON.stringify([s.id,id])));return {subscriptionId:s.id,collectionIds:ids}})}
}
export function text(document:Document,parent:HTMLElement,tag:string,value:string){const node=document.createElement(tag);node.textContent=value;parent.appendChild(node);return node}
export function showSection(document:Document,parent:HTMLElement,section:FeedSection){
  if(section.subscriptions.length===0)text(document,parent,'p','No sources selected.')
  for(const source of section.subscriptions){const row=text(document,parent,'section','');text(document,row,'h2',sourceTitle(source.title));text(document,row,'p',source.url);text(document,row,'p',`Source ID: ${source.id} · ${source.format} · ${source.enabled?'enabled setting':'disabled setting'}`);const labels=source.collectionIds.map(id=>{const label=section.collections.find(c=>c.id===id);return `${collectionTitle(label?.title??'')} (${id})`});text(document,row,'p',labels.length?'Selected memberships: '+labels.join('; '):'No collection memberships selected.')}
}
