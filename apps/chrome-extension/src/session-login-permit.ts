import {loginFailure} from './session-login-errors.js';
/** A short, memory-only permit for one explicit private phase. No lease is held
 * while the human reads or types. A broken control channel destroys the signer. */
export function createSessionLoginPermit(chrome:any,loginId:string,snapshotDigest:()=>Promise<string>,fence:()=>void){
 let current:{leaseId:string;expiresAtMs:number}|null=null,busy=false;
 const random=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('');
 const failure=()=>loginFailure('session_login_context_changed','authorization');
 return {
  current(){if(!current||Date.now()>=current.expiresAtMs)throw failure();return current;},
  check(leaseId?:string){if(!current||current.leaseId!==leaseId||Date.now()>=current.expiresAtMs)throw failure();return current;},
  async run<T>(operation:(permit:{leaseId:string;expiresAtMs:number})=>Promise<T>):Promise<T>{
   if(busy)throw failure();busy=true;
   let port:any,timer:any,normal=false,resolveReleased!:()=>void;
   const released=new Promise<void>(r=>resolveReleased=r);
   try{
    const expectedSnapshot=await snapshotDigest(),leaseId=random();
    port=chrome.runtime.connect({name:'castalia-session-login-critical-v1'});
    const granted=new Promise<{leaseId:string;expiresAtMs:number}>((resolve,reject)=>{
     port.onMessage.addListener((m:any)=>{
      if(m?.kind==='granted'&&m.leaseId===leaseId&&Number.isSafeInteger(m.expiresAtMs)&&m.expiresAtMs>Date.now()&&m.expiresAtMs<=Date.now()+20000)resolve({leaseId,expiresAtMs:m.expiresAtMs});
      else if(m?.kind==='released'&&m.leaseId===leaseId)resolveReleased();
      else if(m?.kind==='failed')reject(failure());
     });
     port.onDisconnect.addListener(()=>{if(!normal){current=null;fence();reject(failure());}});
     timer=setTimeout(()=>{current=null;fence();reject(failure());},22000);
     port.postMessage({kind:'acquire',loginId,leaseId,expectedSnapshot});
    });
    current=await granted;
    clearTimeout(timer);timer=setTimeout(()=>{current=null;fence();},Math.max(0,current.expiresAtMs-Date.now()));
    let result:T;
    try{result=await operation(current);}
    catch(error){
     // A returned private failure has consumed the phase. Transport loss/timeouts
     // are handled by the caller's fence, never by optimistic queue release.
     if(!current)throw error;
     current=null;port.postMessage({kind:'complete',leaseId,phase_closed:true});
     await Promise.race([released,new Promise((_,reject)=>setTimeout(()=>reject(failure()),2000))]);normal=true;throw error;
    }
    if(!current)throw failure();
    current=null;port.postMessage({kind:'complete',leaseId,phase_closed:true});
    await Promise.race([released,new Promise((_,reject)=>setTimeout(()=>reject(failure()),2000))]);normal=true;return result;
   }catch(error){if(!normal){current=null;fence();}throw error;}
   finally{clearTimeout(timer);current=null;busy=false;try{port?.disconnect();}catch{}}
  },
 };
}
