import {clickClosingApproval} from './approval-popup-smoke-helpers.mjs'
import assert from 'node:assert/strict'
import {chromium, type Page} from 'playwright-core'
import {mkdtemp,readFile,rm} from 'node:fs/promises'
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
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(directory,'tls.key'),'-out',join(directory,'tls.crt'),'-days','1','-subj','/CN=127.0.0.1'],{stdio:'ignore'})
const keys=[13,14].map(n=>createPrivateKey({key:Buffer.from('302e020100300506032b657004220420'+n.toString(16).padStart(2,'0').repeat(32),'hex'),format:'der',type:'pkcs8'}))
let issuing=0,requests=0,redirect=false
const server=createServer({key:await readFile(join(directory,'tls.key')),cert:await readFile(join(directory,'tls.crt'))},(req,res)=>{void(async()=>{
 assert.equal(req.headers.cookie,undefined);assert.equal(req.headers.authorization,undefined)
 if(redirect){res.writeHead(302,{location:'https://untrusted.test/v3/memberships'});res.end();return}
 assert.equal(req.method,'POST');assert.equal(req.url,'/v3/memberships');let raw='';for await(const chunk of req){raw+=chunk;assert.ok(raw.length<8192)}const body=JSON.parse(raw)
 const publicKey=createPublicKey({key:Buffer.from('302a300506032b6570032100'+body.ownerPublicKey,'hex'),format:'der',type:'spki'})
 assert.ok(verify(null,zenithMembershipJoinTranscript(body.ownerPublicKey),publicKey,Buffer.from(body.signature,'base64url')))
 const claims={schema:'castalia.zenith-membership-credential.v3',version:3,membershipId:await deriveZenithMembershipId(body.ownerPublicKey),ownerPublicKey:body.ownerPublicKey,status:'active',issuerId:`independent-${issuing}`,issuerKeyId:'key-1',signatureSuite:'Ed25519'}
 requests++;res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({...claims,issuerSignature:sign(null,zenithMembershipCredentialTranscript(claims),keys[issuing]).toString('base64url')}))
})().catch(e=>{res.writeHead(500);res.end(String(e))})})
await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const address=server.address();assert.ok(address&&typeof address==='object');const issuerOrigin=`https://127.0.0.1:${address.port}`
const context=await chromium.launchPersistentContext(join(directory,'profile'),{headless:false,executablePath:process.env.CASTALIA_CHROMIUM_EXECUTABLE??chromium.executablePath(),ignoreDefaultArgs:['--disable-extensions'],args:[...(process.env.CASTALIA_NATIVE_PERMISSION_TEST==='1'?['--force-renderer-accessibility']:[]),'--ignore-certificate-errors','--disable-features=DisableLoadExtensionCommandLineSwitch',`--disable-extensions-except=${root}`,`--load-extension=${root}`]})
const html='<!doctype html><button id="call">Request</button><script>document.getElementById("call").onclick=()=>{window.result=null;window.castaliaWallet[window.method](window.input).then(v=>window.result={ok:true,value:v},e=>window.result={ok:false,error:e.message})}</script>'
await context.route(app+'/**',r=>r.fulfill({contentType:'text/html',body:html}))
async function result(page:Page){await page.waitForFunction(()=>(window as any).result!==null);return page.evaluate(()=>(window as any).result)}
try{
 const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker'),id=new URL(worker.url()).host
 const custody=await context.newPage();await custody.goto(`chrome-extension://${id}/src/sidepanel.html`);await custody.getByLabel('Passphrase').fill('disposable neutral acceptance wallet');await custody.getByRole('button',{name:'Create wallet',exact:true}).click();await custody.getByText('Wallet ready',{exact:true}).waitFor()
 const page=await context.newPage();await page.goto(app+'/files');await page.waitForFunction(()=>(window as any).castaliaWallet?.requestConnection)
 async function call(method:string,input:unknown,approve?:string){await page.evaluate(({method,input})=>{Object.assign(window,{method,input,result:null})},{method,input});const opened=approve?context.waitForEvent('page'):null;await page.locator('#call').click();if(opened){const p=await opened;await p.waitForURL(`chrome-extension://${id}/src/provider-settings.html?*`);await clickClosingApproval(p, approve, page)}return result(page)}
 assert.equal((await call('requestConnection',{},'Connect')).ok,true);assert.deepEqual((await call('listMembershipProfiles',{})).value,[]);assert.equal(requests,0)
 assert.equal((await call('getMembership',{})).ok,false)
 const settings:Page[]=[]
 for(let n=0;n<2;n++){const profile={schema:'castalia.provider-profile.v1',display_name:`Independent ${n}`,origins:[app],membership:{protocol:'castalia.zenith-membership.v3',issuer_origin:issuerOrigin,roots:[{issuerId:`independent-${n}`,keyId:'key-1',signatureSuite:'Ed25519',publicKey:createPublicKey(keys[n]).export({format:'der',type:'spki'}).subarray(-32).toString('hex')}]},presentations:[]};settings.push(await importProfile(context,id,profile,{membership:true,presentations:false}))}
 const profiles=(await call('listMembershipProfiles',{})).value;assert.equal(profiles.length,2)
 const proofs=[];for(let n=0;n<2;n++){issuing=n;const r=await call('requestMembership',{profileId:profiles[n].profileId},'Join membership');assert.equal(r.ok,true,r.error);proofs.push(r.value)}
 assert.equal(proofs[0].membershipId,proofs[1].membershipId);assert.notEqual(proofs[0].issuerSignature,proofs[1].issuerSignature);assert.equal(requests,2)
 for(let n=0;n<2;n++){const r=await call('getMembershipCredential',{profileId:profiles[n].profileId});assert.equal(r.ok,true,r.error);assert.deepEqual(r.value,proofs[n])}
 assert.equal((await call('getMembership',{})).ok,false)
 await settings[1].getByRole('button',{name:'Use for: '+app,exact:true}).first().click()
 assert.deepEqual((await call('getMembership',{})).value,proofs[0])
 redirect=true;assert.equal((await call('requestMembership',{profileId:profiles[0].profileId},'Join membership')).ok,false);redirect=false
 await settings[1].getByRole('button',{name:'Remove trust',exact:true}).first().click();await settings[1].getByText('Trust removed · retained proofs are preserved',{exact:true}).waitFor()
 assert.equal((await call('getMembershipCredential',{profileId:profiles[0].profileId})).ok,false);assert.deepEqual((await call('getMembershipCredential',{profileId:profiles[1].profileId})).value,proofs[1])
 await settings[1].getByRole('button',{name:'Review replacement',exact:true}).first().click()
 await settings[1].getByLabel('Trust this provider for membership enrollment and proof verification').check()
 await settings[1].getByRole('button',{name:'Approve selected purposes',exact:true}).click()
 await settings[1].getByText('Provider trust saved.',{exact:true}).waitFor()
 const restored=await call('getMembershipCredential',{profileId:profiles[0].profileId});assert.equal(restored.ok,true,restored.error);assert.deepEqual(restored.value,proofs[0])
 const state=await worker.evaluate(async()=>(await(globalThis as any).chrome.storage.local.get('castalia-provider-profiles-v1'))['castalia-provider-profiles-v1']);assert.equal(state.credentials.length,2)
 const after=await verifyExtensionPackageDigest(root,`${root}.contents.sha256`);assert.equal(after.digest,before.digest)
 console.log(JSON.stringify({schema:'castalia.provider-neutrality-chrome.v1',packageDigest:before.digest,browser:context.browser()?.version(),cases:['zero-trust connection without enrollment','two unrelated issuers imported through Wallet settings','real HTTPS host permission','fixed holder enrollment signature independently verified','same-ID credentials coexist','no automatic legacy selection','explicit per-origin compatibility selection','redirect rejected','trust removal retains proofs and blocks use','explicit reapproval restores retained proof without reissuance','same package digest before and after'],realWallets:'untouched'}))
}finally{await context.close();await new Promise<void>(r=>server.close(()=>r()));await rm(directory,{recursive:true,force:true})}
