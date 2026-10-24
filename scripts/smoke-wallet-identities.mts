/** Disposable custody only; native-session -> packaged Chrome -> native-session. */
import assert from 'node:assert/strict'
import {chromium} from 'playwright-core'
import {mkdtemp,readFile,rm,mkdir} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join,resolve} from 'node:path'
import {initSync,WasmRecoverySession} from '../apps/chrome-extension/src/generated/castalia-wallet-core/bindings.js'
import {CASTALIA_WALLET_CORE_WASM} from '../apps/chrome-extension/src/generated/castalia-wallet-core/wasm-bytes.js'
import {verifyExtensionPackageDigest} from './extension-package-digest.mjs'

assert.ok(process.env.CASTALIA_EXTENSION_DIRECTORY,'Use the exact production package')
const root=resolve(process.env.CASTALIA_EXTENSION_DIRECTORY),directory=await mkdtemp(join(tmpdir(),'castalia-identities-'))
const before=await verifyExtensionPackageDigest(root,`${root}.contents.sha256`)
initSync({module:CASTALIA_WALLET_CORE_WASM})
const session=new WasmRecoverySession()
const invoke=(value:unknown)=>JSON.parse(session.invoke(JSON.stringify(value)))
const commit=(preview:any)=>{const saved=invoke({operation:'commit_candidate',token:preview.token,expected_revision:preview.expected_revision});invoke({operation:'confirm_commit',token:preview.token,snapshot:saved.snapshot})}
commit(invoke({operation:'prepare_create',password:'synthetic local password',created_at:1,expected_revision:0}))
const owner=invoke({operation:'identity'}).ownerPublicKey
const identities=JSON.parse(await readFile(new URL('../contracts/wallet-identities/v1/section.json',import.meta.url),'utf8'))
identities.ownerMemberKey=owner
commit(invoke({operation:'prepare_wallet_identities',identities,expected_revision:1}))
const recovery=invoke({operation:'export_recovery',password:'synthetic recovery password'}).file
const file=invoke({operation:'export_data',password:'synthetic data password',exported_at:2}).file
const context=await chromium.launchPersistentContext(join(directory,'profile'),{headless:process.env.CASTALIA_HEADLESS==='1',executablePath:process.env.CASTALIA_CHROMIUM_EXECUTABLE??chromium.executablePath(),ignoreDefaultArgs:['--disable-extensions'],args:['--disable-features=DisableLoadExtensionCommandLineSwitch',`--disable-extensions-except=${root}`,`--load-extension=${root}`]})
try{
  const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker')
  const id=new URL(worker.url()).host
  const popup=await context.newPage()
  popup.on('pageerror',error=>console.log('popup_error:',error.message))
  popup.on('console',message=>console.log('popup_console:',message.type(),message.text()))
  await popup.goto(`chrome-extension://${id}/src/sidepanel.html`)
  await popup.locator('#import').setInputFiles({name:'Synthetic.castalia-recovery',mimeType:'application/json',buffer:Buffer.from(recovery)})
  popup.once('dialog',dialog=>dialog.accept('synthetic recovery password'))
  await popup.locator('#confirm-import').click()
  await popup.locator('#public-member-key').waitFor()
  assert.equal(await popup.locator('#public-member-key').inputValue(),owner)
  await popup.locator('#unlock-passphrase').fill('synthetic recovery password')
  await popup.locator('#unlock-form button').click()
  await popup.getByText('Wallet ready',{exact:true}).waitFor()
  const pagePromise=context.waitForEvent('page',{timeout:10000}).catch(()=>null)
  await popup.locator('#wallet-identities').click({timeout:5000})
  const page=await pagePromise;assert.ok(page,'Wallet identities page must open');await page.waitForLoadState('domcontentloaded')
  await page.getByText('No saved account descriptions.',{exact:true}).waitFor()
  const review=async()=>{await page.locator('#file').setInputFiles({name:'Synthetic.castaway',mimeType:'application/json',buffer:Buffer.from(file)});await page.locator('#import-password').fill('synthetic data password');await page.locator('#import-form button').click();await page.locator('#review:not([hidden])').waitFor()}
  await review()
  assert.equal(await page.locator('#review-accounts li').count(),4)
  assert.match(await page.locator('#identities').innerText(),/No saved/)
  await page.locator('#cancel').click();assert.match(await page.locator('#identities').innerText(),/No saved/)
  await review();await page.locator('#confirm').click()
  await page.locator('#notice').filter({hasText:'Reviewed data imported'}).waitFor()
  assert.equal(await page.locator('#identities li').count(),4)
  await page.reload();await page.locator('#identities li').first().waitFor()
  assert.equal(await page.locator('#identities li').count(),4)
  await page.locator('#export-password').fill('synthetic export password')
  const downloadPromise=page.waitForEvent('download');await page.locator('#export-form button').click()
  const download=await downloadPromise,path=await download.path();assert.ok(path)
  const exported=await readFile(path,'utf8')
  assert.equal(JSON.parse(exported).schema,'castalia.castaway.v2')
  const preview=invoke({operation:'prepare_data',file:exported,password:'synthetic export password'})
  assert.deepEqual(preview.wallet_identities,identities)
  assert.equal(preview.imported_wallet_identities,4)
  if(process.env.CASTALIA_IDENTITY_SCREENSHOT){const output=resolve(process.env.CASTALIA_IDENTITY_SCREENSHOT);await mkdir(resolve(output,'..'),{recursive:true});await page.screenshot({path:output,fullPage:true})}
  assert.equal((await verifyExtensionPackageDigest(root,`${root}.contents.sha256`)).digest,before.digest)
  console.log(JSON.stringify({result:'passed',synthetic:true,accounts:4,nativeToChrome:true,chromeToNative:true,cancelPreserved:true,reloadPreserved:true,existingProfilesTouched:false,packageDigest:before.digest}))
}finally{await context.close();session.free();await rm(directory,{recursive:true,force:true})}
