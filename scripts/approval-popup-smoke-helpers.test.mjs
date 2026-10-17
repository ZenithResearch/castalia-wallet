import test from 'node:test'
import assert from 'node:assert/strict'
import {clickClosingApproval} from './approval-popup-smoke-helpers.mjs'
const closedError = new Error('locator.click: Target page, context or browser has been closed')
function popup(closed, error) {
 return {isClosed:()=>closed,getByRole:(role,options)=>{
  assert.equal(role,'button');assert.deepEqual(options,{name:'Approve',exact:true})
  return {click:async()=>{if(error)throw error}}
 }}
}
test('completed approval clicks may close their own popup while caller remains live',async()=>{
 await clickClosingApproval(popup(false), 'Approve', {isClosed:()=>false})
 await clickClosingApproval(popup(true,closedError), 'Approve', {isClosed:()=>false})
})
test('popup helper preserves real click failures and caller/browser loss',async()=>{
 for(const [closed,callerClosed,error] of [[false,false,closedError],[true,true,closedError],[true,false,new Error('click timed out')]]){
  await assert.rejects(clickClosingApproval(popup(closed,error),'Approve',{isClosed:()=>callerClosed}),e=>e===error)
 }
})
