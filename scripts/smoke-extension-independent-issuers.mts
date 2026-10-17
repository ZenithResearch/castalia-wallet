import {clickClosingApproval} from './approval-popup-smoke-helpers.mjs'
import assert from 'node:assert/strict'
import {chromium, type Page} from 'playwright-core'
import {mkdtemp,readFile,rm,mkdir,writeFile} from 'node:fs/promises'
import {join,resolve} from 'node:path'
import {tmpdir} from 'node:os'
import {execFileSync} from 'node:child_process'
import {createServer} from 'node:https'
import {createPrivateKey,createPublicKey,sign,verify} from 'node:crypto'
import {deriveZenithMembershipId,zenithMembershipCredentialTranscript,zenithMembershipJoinTranscript} from '@castalia-wallet/zenith-membership'
import {verifyExtensionPackageDigest} from './extension-package-digest.mjs'
import {importProfile} from './provider-profile-smoke-helpers.mts'
assert.ok(process.env.CASTALIA_EXTENSION_DIRECTORY,'Exact package is required')
const root=resolve(process.env.CASTALIA_EXTENSION_DIRECTORY!),before=await verifyExtensionPackageDigest(root,`${root}.contents.sha256`)
const directory=await mkdtemp(join(tmpdir(),'castalia-neutral-chrome-')),app='https://neutral.test'
assert.equal(process.platform,'linux','TLS qualification runs only in a disposable Linux environment')
const browserHome=join(directory,'browser-home');await mkdir(join(browserHome,'.pki/nssdb'),{recursive:true})
function openssl(args:string[]){execFileSync('openssl',args,{cwd:directory,stdio:'ignore'})}
openssl(['req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.crt','-days','1','-subj','/CN=Disposable Castalia Qualification CA','-addext','basicConstraints=critical,CA:TRUE'])
execFileSync('certutil',['-N','--empty-password','-d','sql:'+join(browserHome,'.pki/nssdb')])
execFileSync('certutil',['-A','-d','sql:'+join(browserHome,'.pki/nssdb'),'-n','Disposable qualification CA','-t','C,,','-i',join(directory,'ca.crt')])
const hosts=['issuer-a.castalia.test','issuer-b.castalia.test','issuer-untrusted.castalia.test','issuer-mismatch.castalia.test']
for(let n=0;n<3;n++){
 openssl(['req','-new','-newkey','rsa:2048','-nodes','-keyout',`tls-${n}.key`,'-out',`tls-${n}.csr`,'-subj',`/CN=${hosts[n]}`])
 await writeFile(join(directory,`tls-${n}.ext`),`subjectAltName=DNS:${hosts[n]}\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n`)
 openssl(['x509','-req','-in',`tls-${n}.csr`,...(n===2?['-signkey',`tls-${n}.key`]:['-CA','ca.crt','-CAkey','ca.key','-CAcreateserial']),'-out',`tls-${n}.crt`,'-days','1','-extfile',`tls-${n}.ext`])
}
const keys=[13,14].map(n=>createPrivateKey({key:Buffer.from('302e020100300506032b657004220420'+n.toString(16).padStart(2,'0').repeat(32),'hex'),format:'der',type:'pkcs8'}))
let requests=0,redirect=false,mode='valid';const issued:any[]=[]
const servers=[];const issuerOrigins:string[]=[]
for(let endpoint=0;endpoint<4;endpoint++){const issuing=endpoint===1?1:0;const certificate=endpoint===3?0:endpoint
const server=createServer({key:await readFile(join(directory,`tls-${certificate}.key`)),cert:await readFile(join(directory,`tls-${certificate}.crt`))},(req,res)=>{void(async()=>{
 assert.equal(req.headers.cookie,undefined);assert.equal(req.headers.authorization,undefined)
 if(redirect){res.writeHead(302,{location:'https://untrusted.test/v3/memberships'});res.end();return}
 assert.equal(req.method,'POST');assert.equal(req.url,'/v3/memberships');let raw='';for await(const chunk of req){raw+=chunk;assert.ok(raw.length<8192)}const body=JSON.parse(raw)
 const publicKey=createPublicKey({key:Buffer.from('302a300506032b6570032100'+body.ownerPublicKey,'hex'),format:'der',type:'spki'})
 assert.ok(verify(null,zenithMembershipJoinTranscript(body.ownerPublicKey),publicKey,Buffer.from(body.signature,'base64url')))
 const holder=mode==='wrong-holder'?createPublicKey(keys[0]).export({format:'der',type:'spki'}).subarray(-32).toString('hex'):body.ownerPublicKey
 const claims={schema:'castalia.zenith-membership-credential.v3',version:3,membershipId:await deriveZenithMembershipId(holder),ownerPublicKey:holder,status:'active',issuerId:mode==='wrong-issuer'?'untrusted-issuer':`independent-${issuing}`,issuerKeyId:'key-1',signatureSuite:'Ed25519'}
 requests++;const proof={...claims,issuerSignature:sign(null,zenithMembershipCredentialTranscript(claims),keys[mode==='wrong-key'?1-issuing:issuing]).toString('base64url')};if(mode==='valid')issued[issuing]=proof;res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(mode==='substitute'?issued[0]:proof))
})().catch(e=>{res.writeHead(500);res.end(String(e))})})
await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const address=server.address();assert.ok(address&&typeof address==='object');issuerOrigins.push(`https://${hosts[endpoint]}:${address.port}`);servers.push(server)
}
const context=await chromium.launchPersistentContext(join(directory,'profile'),{headless:false,executablePath:process.env.CASTALIA_CHROMIUM_EXECUTABLE??chromium.executablePath(),ignoreDefaultArgs:['--disable-extensions'],env:{...process.env,HOME:browserHome,ACCESSIBILITY_ENABLED:'1',NO_AT_BRIDGE:'0'},args:['--force-renderer-accessibility','--no-proxy-server',`--host-resolver-rules=${hosts.map(host=>'MAP '+host+' 127.0.0.1').join(', ')}`,'--disable-features=DisableLoadExtensionCommandLineSwitch',`--disable-extensions-except=${root}`,`--load-extension=${root}`]})
const html='<!doctype html><button id="call">Request</button><script>document.getElementById("call").onclick=()=>{window.result=null;window.castaliaWallet[window.method](window.input).then(v=>window.result={ok:true,value:v},e=>window.result={ok:false,error:e.message})}</script>'
await context.route(app+'/**',r=>r.fulfill({contentType:'text/html',body:html}))
async function result(page:Page){await page.waitForFunction(()=>(window as any).result!==null);return page.evaluate(()=>(window as any).result)}
try{
 const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker'),id=new URL(worker.url()).host
 const access=await context.newPage();await access.goto(`chrome://extensions/?id=${id}`);await access.locator('#hostAccess').selectOption({label:'On specific sites'});await access.getByRole('textbox',{name:'Site',exact:true}).fill(app);await access.locator('#submit').click()
 const custody=await context.newPage();await custody.goto(`chrome-extension://${id}/src/sidepanel.html`);await custody.getByLabel('Passphrase').fill('disposable neutral acceptance wallet');await custody.getByRole('button',{name:'Create wallet',exact:true}).click();await custody.getByText('Wallet ready',{exact:true}).waitFor()
 const page=await context.newPage();await page.goto(app+'/files');await page.waitForFunction(()=>(window as any).castaliaWallet?.requestConnection)
 async function call(method:string,input:unknown,approve?:string){
  await page.evaluate(({method,input})=>{Object.assign(window,{method,input,result:null})},{method,input})
  const opened=approve?context.waitForEvent('page'):null
  await page.locator('#call').click()
  if(opened){
   const p=await opened;await p.waitForURL(`chrome-extension://${id}/src/provider-settings.html?*`)
   await clickClosingApproval(p, approve, page)
  }
  return result(page) // A lost caller/browser or absent result still fails.
 }
 assert.equal((await call('requestConnection',{},'Connect')).ok,true);assert.deepEqual((await call('listMembershipProfiles',{})).value,[]);assert.equal(requests,0)
 assert.equal((await call('getMembership',{})).ok,false)
 const approveHostPermission=async(n:number)=>{const output=execFileSync('/usr/bin/python3',['scripts/approve-test-host-permission.py',hosts[n]],{encoding:'utf8',timeout:25000});console.log(output.trim())}
 const settings:Page[]=[]
 for(let n=0;n<2;n++){const profile={schema:'castalia.provider-profile.v1',display_name:`Independent ${n}`,origins:[app],membership:{protocol:'castalia.zenith-membership.v3',issuer_origin:issuerOrigins[n],roots:[{issuerId:`independent-${n}`,keyId:'key-1',signatureSuite:'Ed25519',publicKey:createPublicKey(keys[n]).export({format:'der',type:'spki'}).subarray(-32).toString('hex')}]},presentations:[]};settings.push(await importProfile(context,id,profile,{membership:true,presentations:false},()=>approveHostPermission(n)))}
 const profiles=(await call('listMembershipProfiles',{})).value;assert.equal(profiles.length,2)
 const proofs=[];for(let n=0;n<2;n++){const r=await call('requestMembership',{profileId:profiles[n].profileId},'Join membership');assert.equal(r.ok,true,r.error);proofs.push(r.value)}
 assert.equal(proofs[0].membershipId,proofs[1].membershipId);assert.notEqual(proofs[0].issuerSignature,proofs[1].issuerSignature);assert.equal(requests,2)
 for(let n=0;n<2;n++){const r=await call('getMembershipCredential',{profileId:profiles[n].profileId});assert.equal(r.ok,true,r.error);assert.deepEqual(r.value,proofs[n])}
 assert.equal((await call('getMembership',{})).ok,false)
 await settings[1].getByRole('button',{name:'Use for: '+app,exact:true}).first().click()
 assert.deepEqual((await call('getMembership',{})).value,proofs[0])
 // Each granted host is independent, with ordinary TLS chain/hostname checks.
 const permission=async(n:number)=>worker.evaluate(async origin=>(globalThis as any).chrome.permissions.contains({origins:[new URL(origin).origin+'/*']}),issuerOrigins[n])
 assert.equal(await permission(0),true);assert.equal(await permission(1),true)
 for(const [invalid,expectedError] of [
  ['wrong-holder',/owner does not match this Member Key/],
  ['wrong-issuer',/issuer is not trusted/],
  ['wrong-key',/signature is invalid/],
 ] as const){
  mode=invalid;const beforeRequests=requests
  const rejected=await call('requestMembership',{profileId:profiles[0].profileId},'Join membership')
  assert.equal(rejected.ok,false,invalid);assert.match(rejected.error,expectedError,invalid)
  assert.equal(requests,beforeRequests+1,'The invalid proof must reach Wallet verification')
 }
 mode='substitute';assert.equal((await call('requestMembership',{profileId:profiles[1].profileId},'Join membership')).ok,false,'cross-profile credential substitution');mode='valid'
 const countBeforeCancel=requests;assert.equal((await call('requestMembership',{profileId:profiles[0].profileId},'Cancel')).ok,false);assert.equal(requests,countBeforeCancel)
 for(let n=2;n<4;n++){
  const profile={schema:'castalia.provider-profile.v1',display_name:'Certificate negative '+n,origins:[app],membership:{protocol:'castalia.zenith-membership.v3',issuer_origin:issuerOrigins[n],roots:[{issuerId:'independent-0',keyId:'key-1',signatureSuite:'Ed25519',publicKey:createPublicKey(keys[0]).export({format:'der',type:'spki'}).subarray(-32).toString('hex')}]},presentations:[]}
  await importProfile(context,id,profile,{membership:true,presentations:false},()=>approveHostPermission(n))
  const all=(await call('listMembershipProfiles',{})).value,negative=all.find((x:any)=>x.displayName==='Certificate negative '+n||x.display_name==='Certificate negative '+n)
  assert.ok(negative,'Certificate profile must be listed')
  const beforeRequests=requests;assert.equal((await call('requestMembership',{profileId:negative.profileId},'Join membership')).ok,false,n===2?'untrusted certificate':'certificate hostname mismatch');assert.equal(requests,beforeRequests,'TLS failure must precede HTTP issuer request')
 }
 redirect=true;assert.equal((await call('requestMembership',{profileId:profiles[0].profileId},'Join membership')).ok,false);redirect=false
 const pending=context.waitForEvent('page');await page.evaluate(profileId=>Object.assign(window,{method:'requestMembership',input:{profileId},result:null}),profiles[0].profileId);await page.locator('#call').click();const stale=await pending;await stale.getByRole('button',{name:'Join membership',exact:true}).waitFor()
 await access.reload();const siteRow=access.locator('extensions-runtime-host-permissions li').filter({hasText:hosts[0]});await siteRow.waitFor();const menu=siteRow.locator('.open-edit-host');if(await menu.isVisible()){await menu.click();await access.locator('#action-menu-remove').click()}else{await siteRow.locator('.remove-host').click()}assert.equal((await result(page)).ok,false,'Host permission revocation cancels pending approval');await settings[1].reload();await settings[1].getByText('Trust removed · retained proofs are preserved',{exact:true}).waitFor()
 assert.equal((await call('getMembershipCredential',{profileId:profiles[0].profileId})).ok,false);assert.deepEqual((await call('getMembershipCredential',{profileId:profiles[1].profileId})).value,proofs[1])
 assert.equal(await permission(0),false);assert.equal(await permission(1),true)
 const remaining=await call('requestMembership',{profileId:profiles[1].profileId},'Join membership');assert.equal(remaining.ok,true,remaining.error)
 await settings[1].getByRole('button',{name:'Review replacement',exact:true}).first().click()
 await settings[1].getByLabel('Trust this provider for membership enrollment and proof verification').check()
 await settings[1].getByRole('button',{name:'Approve selected purposes',exact:true}).click()
 await approveHostPermission(0)
 await settings[1].getByText('Provider trust saved.',{exact:true}).waitFor()
 const restored=await call('getMembershipCredential',{profileId:profiles[0].profileId});assert.equal(restored.ok,true,restored.error);assert.deepEqual(restored.value,proofs[0])
 const state=await worker.evaluate(async()=>(await(globalThis as any).chrome.storage.local.get('castalia-provider-profiles-v1'))['castalia-provider-profiles-v1']);assert.equal(state.credentials.length,2)
 const after=await verifyExtensionPackageDigest(root,`${root}.contents.sha256`);assert.equal(after.digest,before.digest)
 console.log(JSON.stringify({schema:'castalia.independent-issuer-tls-chrome.v1',qualification:'test-CA only; real production issuers not qualified',certificateValidation:'enabled',hostTrustStore:'unchanged',packageDigest:before.digest,browser:context.browser()?.version(),cases:['zero-trust connection without enrollment','two unrelated issuers imported through Wallet settings','real HTTPS host permission','fixed holder enrollment signature independently verified','same-ID credentials coexist','no automatic legacy selection','explicit per-origin compatibility selection','redirect rejected','trust removal retains proofs and blocks use','explicit reapproval restores retained proof without reissuance','same package digest before and after','distinct HTTPS hostnames and independent host permissions','removing one host leaves the other usable','wrong holder/issuer/key','cross-profile substitution','untrusted certificate','certificate hostname mismatch','cancelled enrollment','host permission removal invalidates pending approval'],realWallets:'untouched'}))
}finally{await context.close();for(const server of servers)await new Promise<void>(r=>server.close(()=>r()));await rm(directory,{recursive:true,force:true})}
