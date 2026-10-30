import test from 'node:test';import assert from 'node:assert/strict';
import {installHolderGrantForgetRuntime} from '../src/holder-grants-forget-runtime.js';
function fixture(){let listener:any,changed:any,epoch=1,now=0,owner='owner',locked=false,removed=0,revision=4,tokens=0;
 const sender={id:'wallet',url:'chrome-extension://wallet/src/holder-grants.html',frameId:0,documentId:'one'};
 const chrome={runtime:{id:'wallet',getURL:(p:string)=>'chrome-extension://wallet/'+p,onMessage:{addListener:(f:any)=>listener=f}}};
 installHolderGrantForgetRuntime(chrome,{run:async f=>f(),state:async()=>locked?null:{owner},epoch:()=>epoch,now:()=>now,randomId:()=> 'token'+tokens++,onChange:f=>changed=f,store:{reviewForget:async(service:string)=>({owner,service,revision,record:'exact',grant:{service}}),forget:async(p:any)=>{if(p.revision!==revision)throw Error('grant_storage_changed');removed++;revision++;}} as any});
 const send=(message:any,from:any=sender)=>new Promise<any>(resolve=>{if(!listener(message,from,resolve))resolve({unhandled:true})});
 return{send,sender,removed:()=>removed,change:(kind:string)=>{if(kind==='lock'){locked=true;epoch++;changed();}if(kind==='owner'){owner='other';epoch++;}if(kind==='expire')now=120000;if(kind==='store')revision++;}};
}
test('exact Wallet document gets a one-shot local review token; sites cannot clear grants',async()=>{
 const f=fixture();const p=await f.send({type:'HOLDER_GRANTS_FORGET_REVIEW',service:'one'});assert.equal(p.ok,true);assert.equal(f.removed(),0);
 assert.equal((await f.send({type:'HOLDER_GRANTS_FORGET_CONFIRM',token:p.token})).ok,true);assert.equal(f.removed(),1);
 assert.equal((await f.send({type:'HOLDER_GRANTS_FORGET_CONFIRM',token:p.token})).ok,false);
 for(const sender of [{...f.sender,url:'https://site.test'},{...f.sender,frameId:1},{...f.sender,frameId:undefined},{...f.sender,url:f.sender.url+'?service=one'},{...f.sender,id:'other'},{...f.sender,documentId:undefined}])assert.equal((await f.send({type:'HOLDER_GRANTS_FORGET_REVIEW',service:'one'},sender)).ok,false);
 assert.equal((await f.send({type:'HOLDER_GRANTS_FORGET_REVIEW',service:'one',all:true})).ok,false);
});
for(const kind of ['lock','owner','expire','store','cancel','document'])test('forget confirmation rejects '+kind+' change without mutation',async()=>{
 const f=fixture(),p=await f.send({type:'HOLDER_GRANTS_FORGET_REVIEW',service:'one'});
 if(kind==='cancel')await f.send({type:'HOLDER_GRANTS_FORGET_CANCEL'});else f.change(kind);
 const result=await f.send({type:'HOLDER_GRANTS_FORGET_CONFIRM',token:p.token},kind==='document'?{...f.sender,documentId:'two'}:f.sender);
 assert.equal(result.ok,false);assert.equal(f.removed(),0);
});

test('a second review replaces the first and page-close cancellation cannot be replayed',async()=>{
 const f=fixture(),first=await f.send({type:'HOLDER_GRANTS_FORGET_REVIEW',service:'one'}),second=await f.send({type:'HOLDER_GRANTS_FORGET_REVIEW',service:'two'});
 assert.notEqual(first.token,second.token);assert.equal((await f.send({type:'HOLDER_GRANTS_FORGET_CONFIRM',token:first.token})).ok,false);assert.equal(f.removed(),0);
 const third=await f.send({type:'HOLDER_GRANTS_FORGET_REVIEW',service:'one'});await f.send({type:'HOLDER_GRANTS_FORGET_CANCEL'});
 assert.equal((await f.send({type:'HOLDER_GRANTS_FORGET_CONFIRM',token:third.token})).ok,false);
});
