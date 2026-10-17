import {clickClosingApproval} from './approval-popup-smoke-helpers.mjs'
import {importProfile} from './provider-profile-smoke-helpers.mts'
import assert from 'node:assert/strict'
import {chromium,type Page} from 'playwright-core'
import {mkdtemp,rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join,resolve} from 'node:path'
import {createPrivateKey,createPublicKey,createHash,sign,verify,randomBytes} from 'node:crypto'
import {canonicalPresentationJson,credentialTranscript,presentationTranscript} from '@castalia-wallet/provider-types'
import {verifyExtensionPackageDigest} from './extension-package-digest.mjs'
const directory=process.env.CASTALIA_EXTENSION_DIRECTORY
assert.ok(directory,'CASTALIA_EXTENSION_DIRECTORY must identify the exact packaged artifact')
const root=resolve(directory),before=await verifyExtensionPackageDigest(root,`${root}.contents.sha256`)
const profile=await mkdtemp(join(tmpdir(),'castalia-credential-profile-'))
const issuerKey=createPrivateKey({key:Buffer.from('302e020100300506032b657004220420'+'0b'.repeat(32),'hex'),format:'der',type:'pkcs8'})
const hash=(value:unknown)=>createHash('sha256').update(canonicalPresentationJson(value)).digest('hex')
const context=await chromium.launchPersistentContext(profile,{
 headless:false,executablePath:process.env.CASTALIA_CHROMIUM_EXECUTABLE??chromium.executablePath(),ignoreDefaultArgs:['--disable-extensions'],
 args:['--disable-features=DisableLoadExtensionCommandLineSwitch',`--disable-extensions-except=${root}`,`--load-extension=${root}`],
})
const body='<!doctype html><button id="request">Approve application request</button><script>document.getElementById("request").onclick=()=>{window.outcome=null;window.castaliaWallet.presentCredential(window.request).then(result=>window.outcome={ok:true,result},error=>window.outcome={ok:false,error:error.message})}</script>'
await context.route('https://credentials.test/**',route=>route.fulfill({contentType:'text/html',body}))
await context.route('https://departure.test/**',route=>route.fulfill({contentType:'text/html',body:'<p>Departed</p>'}))
async function outcome(page:Page){await page.waitForFunction(()=>(window as any).outcome!=null);return page.evaluate(()=>(window as any).outcome)}
try{
 let worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker')
 const extensionId=new URL(worker.url()).host
 const developer=await context.newPage();await developer.goto('chrome://extensions/');const developerMode=developer.locator('#devMode');if(!await developerMode.evaluate((e:any)=>e.checked))await developerMode.click();assert.equal(await developerMode.evaluate((e:any)=>e.checked),true);await developer.close()
 let custody=await context.newPage();await custody.goto(`chrome-extension://${extensionId}/src/sidepanel.html`)
 await custody.getByLabel('Passphrase').fill('disposable credential acceptance recovery')
 await custody.getByRole('button',{name:'Create wallet',exact:true}).click();await custody.getByText('Wallet ready').waitFor()
 const owner=await custody.locator('#public-member-key').inputValue();assert.match(owner,/^[0-9a-f]{64}$/)
 const approved=await custody.evaluate(()=>new Promise<any>(resolve=>(window as any).chrome.runtime.sendMessage({type:'APPROVE_ORIGIN',origin:'https://credentials.test'},resolve)))
 assert.equal(approved.ok,true)
 const configured=await importProfile(context,extensionId,{schema:'castalia.provider-profile.v1',display_name:'Independent fixture authority',origins:['https://credentials.test'],membership:null,presentations:['fixture-service','second-service'].map(audience=>({issuer:'fixture-issuer',key_id:'fixture-key',public_key:createPublicKey(issuerKey).export({format:'der',type:'spki'}).subarray(-32).toString('hex'),audience,callers:[{kind:'browser',id:'https://credentials.test'}]}))},{membership:false,presentations:true});await configured.close()
 const page=await context.newPage();await page.goto('https://credentials.test/application')
 await page.waitForFunction(()=>(window as any).castaliaWallet?.presentCredential)
 assert.ok((await page.evaluate(()=>(window as any).castaliaWallet.getCapabilities())).includes('credential_presentation_v2'))
 function request(audience='fixture-service'){
  const now=Math.floor(Date.now()/1000),bytes=Buffer.from(JSON.stringify({application:audience,operation:'save',revision:7})),disclosure={title:`${audience} request`,statements:['Save revision 7',bytes.toString()]}
  const claims={schema:'castalia.request-credential.v1' as const,issuer:'fixture-issuer',key_id:'fixture-key',holder_public_key:owner,audience,caller:{kind:'browser' as const,id:'https://credentials.test'},request_digest_sha256:createHash('sha256').update(bytes).digest('hex'),disclosure_digest_sha256:hash(disclosure),policy_digest_sha256:'ab'.repeat(32),nonce:randomBytes(16).toString('hex'),issued_at:now,expires_at:now+120}
  return {schema:'castalia.credential-presentation-request.v2',request_bytes_base64:bytes.toString('base64'),disclosure,credential:{claims,signature:sign(null,Buffer.from(credentialTranscript(claims)),issuerKey).toString('hex')}}
 }
 async function start(value:unknown){await page.evaluate(value=>{(window as any).request=value},value);const opened=context.waitForEvent('page');await page.locator('#request').click();const popup=await opened;await popup.waitForURL(`chrome-extension://${extensionId}/src/credential-presentation-confirmation.html?*`);await popup.waitForFunction(()=>!(document.getElementById('approve') as HTMLButtonElement).disabled);return popup}
 for(const audience of ['fixture-service','second-service']){
  const value=request(audience),popup=await start(value)
  assert.equal(await popup.locator('#issuer').innerText(),'fixture-issuer');assert.equal(await popup.locator('#statements').innerText(),value.disclosure.statements.join('\n\n'))
  await clickClosingApproval(popup, 'Approve this request', page)
  const result=await outcome(page);assert.equal(result.ok,true,result.error);assert.equal(result.result.state,'approved')
  const presentation=result.result.presentation
  assert.equal(presentation.audience,audience);assert.equal(presentation.credential_digest_sha256,hash(value.credential));assert.equal(presentation.request_digest_sha256,value.credential.claims.request_digest_sha256)
  const holder=createPublicKey({key:Buffer.from('302a300506032b6570032100'+owner,'hex'),format:'der',type:'spki'})
  assert(verify(null,Buffer.from(presentationTranscript(presentation)),holder,Buffer.from(presentation.signature,'hex')))
  await page.locator('#request').click();assert.match((await outcome(page)).error,/replay/)
 }
 // A second document must not steal or replace the first document's approval.
 const concurrentPage=await context.newPage();await concurrentPage.goto('https://credentials.test/concurrent')
 await concurrentPage.waitForFunction(()=>(window as any).castaliaWallet?.presentCredential)
 const concurrentFirst=await start(request()),concurrentSecond=request('second-service')
 await concurrentPage.evaluate(value=>{(window as any).request=value},concurrentSecond)
 await concurrentPage.locator('#request').click()
 const concurrentResult=await outcome(concurrentPage)
 assert.equal(concurrentResult.ok,false);assert.match(concurrentResult.error,/already pending/)
 assert.equal(context.pages().filter(p=>p.url().startsWith(`chrome-extension://${extensionId}/src/credential-presentation-confirmation.html?`)).length,1)
 assert.equal(await page.evaluate(()=>(window as any).outcome),null)
 await clickClosingApproval(concurrentFirst, 'Don’t sign', page)
 assert.equal((await outcome(page)).result.state,'denied');await concurrentPage.close()
 const denied=await start(request());await clickClosingApproval(denied, 'Don’t sign', page);assert.equal((await outcome(page)).result.state,'denied')
 const dismissed=await start(request());await dismissed.close();assert.equal((await outcome(page)).result.state,'denied')
 const altered=request();altered.disclosure.title='Page-substituted disclosure';await page.evaluate(value=>{(window as any).request=value},altered);await page.locator('#request').click();assert.equal((await outcome(page)).ok,false)
 const pending=await start(request());const closed=pending.waitForEvent('close');await page.goto('https://departure.test/');await closed
 await page.goto('https://credentials.test/application');await page.waitForFunction(()=>(window as any).castaliaWallet?.presentCredential)
 const reloading=await start(request());const reloadClosed=reloading.waitForEvent('close');await page.reload();await reloadClosed;await page.waitForFunction(()=>(window as any).castaliaWallet?.presentCredential)
 const revoked=await start(request());const revokeClosed=revoked.waitForEvent('close');assert.equal((await custody.evaluate(()=>new Promise<any>(resolve=>(window as any).chrome.runtime.sendMessage({type:'REVOKE_ORIGIN',origin:'https://credentials.test'},resolve)))).ok,true);await revokeClosed
 assert.equal((await custody.evaluate(()=>new Promise<any>(resolve=>(window as any).chrome.runtime.sendMessage({type:'APPROVE_ORIGIN',origin:'https://credentials.test'},resolve)))).ok,true)
 // Stop only this disposable extension's worker. The pending document port
 // must fail closed, the old popup must lose its approval, and session replay
 // protection must survive without erasing the durable identity.
 const restartRequest=request(),stalePopup=await start(restartRequest)
 const cdp=await context.newCDPSession(custody)
 let workerTimeout:ReturnType<typeof setTimeout>|undefined
 const versionId=new Promise<string>((resolve,reject)=>{
  workerTimeout=setTimeout(()=>reject(new Error('Extension service-worker version was not reported')),10000)
  cdp.on('ServiceWorker.workerVersionUpdated',({versions})=>{
   const version=versions.find(v=>v.scriptURL.startsWith(`chrome-extension://${extensionId}/`) && v.runningStatus==='running')
   if(version){clearTimeout(workerTimeout);resolve(version.versionId)}
  })
 })
 await cdp.send('ServiceWorker.enable')
 try{await cdp.send('ServiceWorker.stopWorker',{versionId:await versionId})}finally{clearTimeout(workerTimeout);await cdp.detach()}
 const interrupted=await outcome(page)
 assert.equal(interrupted.ok,false);assert.match(interrupted.error,/presentation_context_changed/)
 await stalePopup.getByRole('button',{name:'Approve this request',exact:true}).click()
 await stalePopup.getByText('confirmation_unavailable',{exact:true}).waitFor()
 assert.equal(await stalePopup.locator('#approve').isDisabled(),true)
 assert.deepEqual(await outcome(page),interrupted);await stalePopup.close()
 await custody.reload();await custody.getByText('Wallet locked',{exact:true}).waitFor()
 assert.equal(await custody.locator('#public-member-key').inputValue(),owner)
 await custody.getByLabel('Passphrase').fill('disposable credential acceptance recovery')
 await custody.getByRole('button',{name:'Unlock',exact:true}).click();await custody.getByText('Wallet ready',{exact:true}).waitFor()
 assert.equal((await custody.evaluate(()=>new Promise<any>(resolve=>(window as any).chrome.runtime.sendMessage({type:'APPROVE_ORIGIN',origin:'https://credentials.test'},resolve)))).ok,true)
 await page.evaluate(value=>{(window as any).request=value},restartRequest);await page.locator('#request').click()
 assert.match((await outcome(page)).error,/replay/)
 const renewedRequest=request(),renewedPopup=await start(renewedRequest)
 await clickClosingApproval(renewedPopup, 'Approve this request', page)
 const renewed=await outcome(page);assert.equal(renewed.ok,true,renewed.error);assert.equal(renewed.result.state,'approved')
 assert.equal(renewed.result.presentation.holder_public_key,owner)
 assert.equal(renewed.result.presentation.credential_digest_sha256,hash(renewedRequest.credential))
 const renewedHolder=createPublicKey({key:Buffer.from('302a300506032b6570032100'+owner,'hex'),format:'der',type:'spki'})
 assert(verify(null,Buffer.from(presentationTranscript(renewed.result.presentation)),renewedHolder,Buffer.from(renewed.result.presentation.signature,'hex')))
 // A live extension reload must invalidate a supported pending generic ceremony.
 // This complements the archived main-package upgrade without relying on a retired method.
 const reloadRequest=request(),updatePopup=await start(reloadRequest),staleConfirmationUrl=updatePopup.url()
 const stopped=new Promise<void>(resolve=>worker.once('close',()=>resolve()))
 const restarted=context.waitForEvent('serviceworker').then(worker=>({worker}),error=>({error}))
 await worker.evaluate(()=>{setTimeout(()=>(globalThis as any).chrome.runtime.reload(),0)})
 await stopped
 const interruptedByReload=await outcome(page);assert.equal(interruptedByReload.ok,false)
 assert.match(interruptedByReload.error,/presentation_context_changed/)
 custody=await context.newPage()
 for(let attempt=0;;attempt++){try{await custody.goto(`chrome-extension://${extensionId}/src/sidepanel.html`);break}catch(error){if(attempt>=30)throw error;await new Promise(r=>setTimeout(r,100))}}
 const restartedResult=await restarted;if(!('worker' in restartedResult))throw restartedResult.error;worker=restartedResult.worker
 assert.equal(new URL(worker.url()).host,extensionId)
 await custody.getByText('Wallet locked',{exact:true}).waitFor()
 await custody.getByLabel('Passphrase').fill('disposable credential acceptance recovery')
 await custody.getByRole('button',{name:'Unlock',exact:true}).click();await custody.getByText('Wallet ready',{exact:true}).waitFor()
 assert.equal(await custody.locator('#public-member-key').inputValue(),owner)
 const staleConfirmation=await context.newPage();await staleConfirmation.goto(staleConfirmationUrl)
 await staleConfirmation.getByText('confirmation_unavailable',{exact:true}).waitFor()
 assert.equal(await staleConfirmation.locator('#approve').isDisabled(),true);await staleConfirmation.close()
 assert.deepEqual(await outcome(page),interruptedByReload)
 assert.equal((await custody.evaluate(()=>new Promise<any>(resolve=>(window as any).chrome.runtime.sendMessage({type:'APPROVE_ORIGIN',origin:'https://credentials.test'},resolve)))).ok,true)
 await page.reload();await page.waitForFunction(()=>(window as any).castaliaWallet?.presentCredential)
 const afterUpdate=request(),freshUpdatePopup=await start(afterUpdate)
 await clickClosingApproval(freshUpdatePopup, 'Approve this request', page)
 const freshUpdate=await outcome(page);assert.equal(freshUpdate.ok,true,freshUpdate.error);assert.equal(freshUpdate.result.state,'approved')
 assert.equal(freshUpdate.result.presentation.credential_digest_sha256,hash(afterUpdate.credential))
 assert(verify(null,Buffer.from(presentationTranscript(freshUpdate.result.presentation)),renewedHolder,Buffer.from(freshUpdate.result.presentation.signature,'hex')))
 const locking=await start(request());const lockClosed=locking.waitForEvent('close');assert.equal((await custody.evaluate(()=>new Promise<any>(resolve=>(window as any).chrome.runtime.sendMessage({type:'CUSTODY_LOCK'},resolve)))).ok,true);await lockClosed
 const after=await verifyExtensionPackageDigest(root,`${root}.contents.sha256`);assert.equal(after.digest,before.digest)
 console.log(JSON.stringify({schema:'castalia.credential-presentation-chrome-acceptance.v2',packageDigest:before.digest,files:before.fileCount,browser:context.browser()?.version(),cases:['fresh disposable identity','two independent applications without Wallet adapters','issuer-authenticated complete disclosure','holder signature verified independently','credential replay denied','explicit denial','altered disclosure rejected','navigation cancellation','same-URL document reload cancellation','popup-close denial','origin revocation cancellation','concurrent documents cannot replace approval','worker restart cancels pending presentation','stale confirmation cannot approve after restart','replay reservation survives worker restart','same identity and fresh approval after restart','live extension reload invalidates pending generic ceremony','stale confirmation unavailable after reload and unlock','fresh generic approval after extension reload','lock cancellation'],realWallets:'untouched',installedSecS:'not exercised'}))
}finally{await context.close();await rm(profile,{recursive:true,force:true})}
