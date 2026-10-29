import assert from 'node:assert/strict'
import test from 'node:test'
import { installCustodyPanelRuntime, observeCustodyPanel } from '../src/custody-panel-state.js'
function event(){const listeners=new Set<(...args:any[])=>void>();return{addListener:(f:any)=>listeners.add(f),removeListener:(f:any)=>listeners.delete(f),emit:(...a:any[])=>{for(const f of [...listeners])f(...a)},count:()=>listeners.size}}
const ready={state:{setupComplete:true,unlocked:true,publicKey:'a'.repeat(64)},chainAccounts:[{networkId:'eip155:1',address:'0x123'}]}
function port(sender:any={id:'id',url:'chrome-extension://id/src/sidepanel.html',frameId:0}){const messages:any[]=[];let disconnected=false;return{name:'castalia-custody-panel-v1',sender,onMessage:event(),onDisconnect:event(),postMessage:(m:any)=>messages.push(m),disconnect:()=>{disconnected=true},messages,disconnected:()=>disconnected}}
const tick=()=>new Promise(resolve=>setImmediate(resolve))
test('only exact extension-owned top-level panels may subscribe to public custody state',async()=>{
 const onConnect=event(),changes=event();let reads=0;
 installCustodyPanelRuntime({runtime:{id:'id',getURL:(p:string)=>'chrome-extension://id/'+p,onConnect}},{snapshot:async()=>{reads++;return ready},subscribe:f=>{changes.addListener(f);return()=>changes.removeListener(f)}})
 for(const sender of [{id:'other',url:'chrome-extension://id/src/sidepanel.html'},{id:'id',url:'https://site.example/'},{id:'id',url:'chrome-extension://id/src/sidepanel.html?x=1'},{id:'id',url:'chrome-extension://id/src/sidepanel.html',frameId:1}]){const p=port(sender);onConnect.emit(p);assert.equal(p.disconnected(),true)}
 assert.equal(reads,0);const p=port();onConnect.emit(p);await tick();assert.equal(reads,1);assert.equal(p.messages[0].state.unlocked,true);
 changes.emit();await tick();assert.equal(reads,2);p.onDisconnect.emit();assert.equal(changes.count(),0)
})
test('state channel never forwards extra custody fields or accepts page commands',async()=>{
 const onConnect=event();const p=port();let reads=0;
 installCustodyPanelRuntime({runtime:{id:'id',getURL:(p:string)=>'chrome-extension://id/'+p,onConnect}},{snapshot:async()=>{reads++;return{...ready,secret:'must-not-leak',state:{...ready.state,encryptedRecord:'must-not-leak'}}},subscribe:()=>()=>{}})
 onConnect.emit(p);await tick();assert.equal(JSON.stringify(p.messages).includes('must-not-leak'),false);
 p.onMessage.emit({command:'unlock',password:'not-a-real-password'});await tick();assert.equal(reads,1)
})
test('later custody change wins over an older snapshot and disconnected panels receive nothing',async()=>{
 const onConnect=event(),changes=event(),pending:Array<(v:any)=>void>=[];const p=port();
 installCustodyPanelRuntime({runtime:{id:'id',getURL:(p:string)=>'chrome-extension://id/'+p,onConnect}},{snapshot:()=>new Promise(resolve=>pending.push(resolve)),subscribe:f=>{changes.addListener(f);return()=>changes.removeListener(f)}})
 onConnect.emit(p);changes.emit();pending[1]({...ready,state:{...ready.state,unlocked:false},chainAccounts:[]});await tick();pending[0](ready);await tick();assert.equal(p.messages.length,1);assert.equal(p.messages[0].state.unlocked,false);
 changes.emit();p.onDisconnect.emit();pending[2](ready);await tick();assert.equal(p.messages.length,1)
})
test('panel immediately stops asserting Ready after worker disconnect without reconnecting itself',()=>{
 const ports:any[]=[],snapshots:any[]=[],unavailable:any[]=[];const runtime={connect:()=>{const p=port();ports.push(p);return p}};
 const observer=observeCustodyPanel(runtime,{snapshot:v=>snapshots.push(v),unavailable:()=>unavailable.push(true)});
 observer.refresh();ports[0].onMessage.emit({type:'CUSTODY_PANEL_STATE',...ready});assert.equal(snapshots[0].state.unlocked,true);
 ports[0].onDisconnect.emit();assert.equal(unavailable.length,2);assert.equal(ports.length,1);
 observer.refresh();assert.equal(ports.length,2);ports[1].onMessage.emit({type:'CUSTODY_PANEL_STATE',state:{...ready.state,unlocked:false},chainAccounts:[]});assert.equal(snapshots.at(-1).state.unlocked,false)
})
test('old worker snapshots cannot revive Ready after reconnect, failure, or page close',()=>{
 const ports:any[]=[],snapshots:any[]=[];const observer=observeCustodyPanel({connect:()=>{const p=port();ports.push(p);return p}},{snapshot:v=>snapshots.push(v),unavailable:()=>{}});
 observer.refresh();observer.refresh();ports[0].onMessage.emit({type:'CUSTODY_PANEL_STATE',...ready});assert.equal(snapshots.length,0);
 ports[1].onMessage.emit({type:'CUSTODY_PANEL_STATE',state:{...ready.state,unlocked:false},chainAccounts:[]});assert.equal(snapshots.length,1);
 observer.dispose();ports[1].onMessage.emit({type:'CUSTODY_PANEL_STATE',...ready});observer.refresh();assert.equal(snapshots.length,1);assert.equal(ports.length,2)
})
test('malformed snapshots fail closed without exposing provider diagnostics',()=>{
 const p=port(),snapshots:any[]=[],unavailable:any[]=[];const observer=observeCustodyPanel({connect:()=>p},{snapshot:v=>snapshots.push(v),unavailable:()=>unavailable.push(true)});observer.refresh();
 p.onMessage.emit({type:'CUSTODY_PANEL_STATE',state:{setupComplete:true,unlocked:true,publicKey:'<script>'},chainAccounts:[]});assert.equal(snapshots.length,0);assert.equal(unavailable.length,2);assert.equal(p.disconnected(),true)
})
test('snapshot failure closes subscription and never leaves an available stream',async()=>{
 const onConnect=event(),changes=event(),p=port();installCustodyPanelRuntime({runtime:{id:'id',getURL:(p:string)=>'chrome-extension://id/'+p,onConnect}},{snapshot:async()=>{throw Error('private failure')},subscribe:f=>{changes.addListener(f);return()=>changes.removeListener(f)}});onConnect.emit(p);await tick();assert.equal(p.disconnected(),true);assert.equal(changes.count(),0);assert.deepEqual(p.messages,[])
})
