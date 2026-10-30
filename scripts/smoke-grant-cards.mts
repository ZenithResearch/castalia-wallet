/** Actual grant page in an isolated browser, synthetic runtime only; no Wallet or service access. */
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {build} from 'esbuild';
import {readFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
const root=resolve(import.meta.dirname,'..'),src=resolve(root,'apps/chrome-extension/src');
const packaged=process.env.GRANT_CARDS_EXTENSION_DIRECTORY?resolve(process.env.GRANT_CARDS_EXTENSION_DIRECTORY):null;
const uiRoot=packaged?resolve(packaged,'src'):src;
const js=packaged?await readFile(resolve(packaged,'dist/holder-grants.js'),'utf8'):(await build({entryPoints:[resolve(src,'holder-grants.ts')],bundle:true,write:false,format:'iife',platform:'browser'})).outputFiles[0].text;
if(packaged)await(await import('./extension-package-digest.mjs')).verifyExtensionPackageDigest(packaged,packaged+'.contents.sha256');
const browser=await chromium.launch({headless:true,executablePath:process.env.CASTALIA_CHROMIUM_EXECUTABLE??'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
try{
 const context=await browser.newContext({viewport:{width:1100,height:1000}}),page=await context.newPage();
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 await context.route('https://wallet-ui.invalid/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  const file=path.endsWith('.css')?'holder-grants.css':path.endsWith('.html')?'holder-grants.html':null;
  await route.fulfill({status:200,contentType:path.endsWith('.js')?'text/javascript':path.endsWith('.css')?'text/css':'text/html',body:file?await readFile(resolve(uiRoot,file),'utf8'):js});
 });
 const installRuntime=()=>{
  const w=window as any;
  const grant=(service:string)=>({service,grant:{schema:'secs.holder-grant.v2',service,issuer:'Example provider',key_id:'example-key',grant_id:'fixture-'+service,revision:'example-revision',holder_public_key:'synthetic-wallet-identity',installation_id:null,validity:{mode:'until_revoked',not_before:100},max_credential_lifetime_seconds:900,onward_delegation:false,permissions:[{operation:'devgraph.work.list',resource:'work',roles:[{role:'target',selector:{selection:{mode:'all'},kinds:['Task']}}],future_guard:{must_preserve:true}},{operation:'devgraph.arena.list',resource:'arenas'}]}});
  w.records=[grant('devgraph:example-graph'),grant('files:example-library')];w.messages=[];w.held=null;w.holdList=false;w.lostReply=false;
  w.chrome={runtime:{lastError:null,onMessage:{addListener:(f:any)=>w.invalidate=f},sendMessage:(m:any,cb:any)=>{
   w.messages.push(m);let result:any={ok:true};
   if(m.type==='HOLDER_GRANTS_LIST'){result.grants=structuredClone(w.records);if(w.holdList){w.held=()=>cb(result);return;}}
   if(m.type==='HOLDER_GRANTS_FORGET_REVIEW'){w.removing=m.service;result={ok:true,token:'synthetic-one-shot',grant:structuredClone(w.records.find((r:any)=>r.service===m.service).grant)};}
   if(m.type==='HOLDER_GRANTS_FORGET_CONFIRM'){w.records=w.records.filter((r:any)=>r.service!==w.removing);result={ok:!w.lostReply,error:'synthetic_lost_reply'};}
   queueMicrotask(()=>cb(result));
  }}};
 };
 await page.addInitScript({content:'globalThis.__name=(value)=>value;('+installRuntime.toString()+')();'});
 await page.goto('https://wallet-ui.invalid/src/holder-grants.html');
 try{await page.getByText('2 saved services',{exact:true}).waitFor({timeout:5000});}catch(error){console.error(JSON.stringify({errors,body:await page.locator('body').innerText(),messages:await page.evaluate(()=>(window as any).messages)}));throw error;}
 assert.equal(await page.locator('#grants article').count(),2);
 assert.equal(await page.locator('#grants details[open]').count(),0);
 assert.equal(await page.getByText('Saved in Wallet',{exact:true}).count(),2);
 assert.equal(await page.locator('#grants pre:visible').count(),0);
 const first=page.locator('#grants article').first();
 await first.locator('.update-help>summary').click();
 await first.getByText('Choose Check approved access, review the grant, then Save grant in Wallet.',{exact:true}).waitFor();
 assert.deepEqual(await page.evaluate(()=>(window as any).messages.map((m:any)=>m.type)),['HOLDER_GRANTS_LIST'],'update guidance does not contact a service or mutate grants');
 await first.locator('details>summary').first().click();
 await first.getByText('Grant ID',{exact:true}).waitFor();assert.match(await first.locator('.permission').first().innerText(),/must_preserve/);
 await first.locator('details>summary').first().click();await first.locator('.update-help>summary').click();
 const remove=page.getByRole('button',{name:'Remove devgraph grant from Wallet',exact:true});
 await remove.click();await page.getByRole('button',{name:'Keep saved grant',exact:true}).click();
 assert.equal(await page.locator('#forget-review:visible').count(),0);
 assert.equal(await remove.evaluate(node=>node===document.activeElement),true,'cancelling removal restores keyboard focus to its card');
 assert.equal(await page.evaluate(()=>(window as any).records.length),2);
 assert.equal(await page.evaluate(()=>(window as any).messages.filter((m:any)=>m.type==='HOLDER_GRANTS_FORGET_CONFIRM').length),0);
 if(process.env.GRANT_CARDS_SCREENSHOT_DIRECTORY){
  const out=resolve(process.env.GRANT_CARDS_SCREENSHOT_DIRECTORY);await mkdir(out,{recursive:true});
  await page.evaluate(()=>scrollTo(0,0));await page.screenshot({path:resolve(out,'grants-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});await page.evaluate(()=>new Promise<void>(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>{scrollTo(0,0);resolve();}))));await page.screenshot({path:resolve(out,'grants-mobile.png')});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'mobile page does not overflow');
 }
 await remove.click();await page.getByRole('button',{name:'Remove saved grant',exact:true}).click();
 await page.getByText('1 saved service',{exact:true}).waitFor();assert.equal(await page.locator('#grants article').count(),1);
 assert.equal(await page.locator('#grants h2').innerText(),'files');
 await page.evaluate(()=>{const w=window as any;w.lostReply=true;});
 await page.getByRole('button',{name:'Remove files grant from Wallet',exact:true}).click();
 await page.getByRole('button',{name:'Remove saved grant',exact:true}).click();
 await page.getByText('Could not confirm this operation. Unlock the same Wallet and refresh to check the current saved grants.',{exact:true}).waitFor();
 await page.getByRole('button',{name:'Refresh',exact:true}).click();await page.getByRole('heading',{name:'No saved grants',exact:true}).waitFor();
 assert.equal(await page.locator('#grants article').count(),0);
 // A list response that arrives after Wallet lock must not restore private cards.
 await page.evaluate(()=>{const w=window as any;w.holdList=true;w.records=[{service:'private:late'}];});
 await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await page.waitForFunction(()=>Boolean((window as any).held));
 await page.evaluate(()=>{const w=window as any;w.invalidate({type:'HOLDER_GRANTS_INVALIDATED'});w.held();});
 await page.getByText('Wallet changed or locked. Unlock and refresh.',{exact:true}).waitFor();
 assert.equal(await page.locator('#grants').innerText(),'');
 assert.deepEqual(errors,[]);
 // Provider-controlled names/fields are text, never markup or navigable URLs.
 await page.evaluate(()=>{const w=window as any;w.holdList=false;w.records=[{service:'<img src=x onerror=alert(1)>',grant:{service:'<img src=x onerror=alert(1)>',issuer:'untrusted',validity:{mode:'until_revoked',not_before:1},permissions:[{operation:'custom.write',guard:'<script>bad</script>'}]}}];});
 await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await page.getByRole('heading',{name:'<img src=x onerror=alert(1)>',exact:true}).waitFor();
 assert.equal(await page.locator('#grants img,#grants script,#grants a').count(),0);
 console.log(JSON.stringify({passed:true,cases:['collapsed cards','canonical service identity','full permission restrictions','non-mutating update guidance','cancel removal','remove exact service','lost confirmation reply','late list after lock','untrusted text','mobile layout'],actualPackagedUi:Boolean(packaged),realWalletAccess:false,realServiceAccess:false}));
 await context.close();
}finally{await browser.close();}
