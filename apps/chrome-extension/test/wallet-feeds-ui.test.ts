import assert from 'node:assert/strict'
import test from 'node:test'
import {readFileSync} from 'node:fs'

test('Wallet UI displays incoming and preserved feed metadata as text and clears it on cancellation or lock',async()=>{
  const section=JSON.parse(readFileSync(new URL('../../../contracts/feeds/v1/section.json',import.meta.url),'utf8'))
  class Element{
    children:Element[]=[];textContent='';hidden=false;disabled=false;value='';files:any[]=[];type='';onclick:any;onsubmit:any
    constructor(readonly tag='div'){}
    replaceChildren(){this.children=[];this.textContent=''}
    append(...children:Element[]){this.children.push(...children)}
    querySelectorAll(tag:string){return this.children.filter(c=>c.tag===tag)}
    reset(){}
    get text():string{return this.textContent+this.children.map(c=>c.text).join('\n')}
  }
  const html=readFileSync(new URL('../src/wallet-identities.html',import.meta.url),'utf8')
  const elements=new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]))
  const get=(id:string)=>{const element=elements.get(id);assert.ok(element,`UI element ${id}`);return element}
  const messages:any[]=[],listeners:any[]=[],events=new Map<string,()=>void>()
  const identities={accounts:[]},preserved=structuredClone(section)
  preserved.subscriptions[0].title='Already stored'
  let error:string|null=null,holdRead=false,heldRead:((value:unknown)=>void)|null=null
  const globals={document:globalThis.document,window:globalThis.window,chrome:(globalThis as any).chrome}
  Object.assign(globalThis,{
    document:{getElementById:get,createElement:(tag:string)=>new Element(tag),querySelectorAll:()=>[]},
    window:{addEventListener:(name:string,callback:()=>void)=>events.set(name,callback)},
    chrome:{runtime:{onMessage:{addListener:(listener:any)=>listeners.push(listener)},sendMessage:(message:any,callback:any)=>{
      messages.push(message)
      if(message.type==='WALLET_IDENTITIES_REVIEW')callback(error?{ok:false,error}:{ok:true,token:'review-1',identities,proofCount:0,profileReplaced:false,feeds:{incoming:section,preserved,combined:section}})
      else if(message.type==='WALLET_IDENTITIES_READ'){if(holdRead)heldRead=callback;else callback({ok:true,revision:1,identities,feeds:preserved})}
      else callback({ok:true})
    }}},
  })
  const settle=async()=>{for(let n=0;n<4;n++)await new Promise(resolve=>setImmediate(resolve))}
  try{
    await import('../src/wallet-identities.js?feed-ui-test')
    await settle()
    assert.ok(get('saved-feeds').text.includes('Already stored'))
    get('file').files=[{size:100,text:async()=>'synthetic encrypted file'}]
    get('import-password').value='synthetic public password'
    get('import-form').onsubmit({preventDefault(){}});await settle()
    assert.ok(get('review-incoming-feeds').text.includes(section.subscriptions[0].url))
    assert.ok(get('review-incoming-feeds').text.includes(JSON.stringify(section.subscriptions[0].title)))
    assert.ok(get('review-preserved-feeds').text.includes('Already stored'))
    assert.equal(get('review').hidden,false)
    get('cancel').onclick();await settle()
    assert.equal(get('review').hidden,true);assert.equal(get('review-incoming-feeds').text,'');assert.equal(get('review-preserved-feeds').text,'')
    // A later failed review must not leave the previous approval or metadata live.
    error='feed_conflict';get('import-form').onsubmit({preventDefault(){}});await settle()
    assert.equal(get('review').hidden,true);assert.match(get('notice').text,/different saved values/)
    holdRead=true;get('refresh').onclick();await settle();assert.ok(heldRead)
    listeners[0]({type:'WALLET_IDENTITIES_INVALIDATED'})
    ;(heldRead as (value:unknown)=>void)({ok:true,revision:1,identities,feeds:preserved});await settle()
    assert.equal(get('saved-feeds').text,'');assert.equal(get('review-incoming-feeds').text,'');assert.equal(get('review-preserved-feeds').text,'')
    for(const message of messages)assert.match(message.type,/^WALLET_IDENTITIES_(READ|REVIEW|CANCEL)$/)
    // Sources are text nodes; no URL anchor, HTML insertion or activation UI.
    for(const id of ['saved-feeds','review-incoming-feeds','review-preserved-feeds'])for(const row of get(id).children)assert.equal(row.tag,'li')
  }finally{Object.assign(globalThis,globals)}
})
