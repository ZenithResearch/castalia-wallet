/** Disposable custody/UI lifecycle qualification; never uses a personal browser profile. */
import assert from 'node:assert/strict'
import { chromium } from 'playwright-core'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { digestExtensionPackage } from './extension-package-digest.mjs'

assert.ok(process.env.CASTALIA_EXTENSION_DIRECTORY, 'Pass the reviewed extension package')
const extension=resolve(process.env.CASTALIA_EXTENSION_DIRECTORY)
const before=await digestExtensionPackage(extension)
const profile=await mkdtemp(join(tmpdir(),'castalia-lifecycle-'))
let context:Awaited<ReturnType<typeof chromium.launchPersistentContext>>|undefined
try{
  context=await chromium.launchPersistentContext(profile,{
    headless:process.env.CASTALIA_HEADLESS==='1',executablePath:process.env.CASTALIA_CHROMIUM_EXECUTABLE??chromium.executablePath(),
    ignoreDefaultArgs:['--disable-extensions'],args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`],
  })
  context.setDefaultTimeout(10000)
  const worker=context.serviceWorkers()[0]??await context.waitForEvent('serviceworker')
  const id=new URL(worker.url()).host,password='Disposable lifecycle test only'
  const panel=await context.newPage()
  await panel.goto(`chrome-extension://${id}/src/sidepanel.html`)
  await panel.getByLabel('Passphrase').fill(password)
  await panel.getByRole('button',{name:'Create wallet',exact:true}).click()
  await panel.getByRole('heading',{name:'Wallet ready',exact:true}).waitFor()
  const identity=await panel.locator('#public-member-key').inputValue()
  const second=await context.newPage()
  await second.goto(`chrome-extension://${id}/src/popup.html`)
  await second.getByRole('heading',{name:'Wallet ready',exact:true}).waitFor()
  await panel.locator('details.advanced summary').click()
  await panel.getByRole('button',{name:'Lock wallet',exact:true}).click()
  await second.getByRole('heading',{name:'Wallet locked',exact:true}).waitFor()
  await second.getByLabel('Passphrase').fill(password)
  await second.getByRole('button',{name:'Unlock',exact:true}).click()
  await panel.getByRole('heading',{name:'Wallet ready',exact:true}).waitFor()
  await second.close()

  // Stop only this disposable extension worker. The root must remain memory-only.
  const cdp=await context.newCDPSession(panel),versions=new Map<string,any>()
  cdp.on('ServiceWorker.workerVersionUpdated',({versions:items})=>{for(const item of items)versions.set(item.versionId,item)})
  await cdp.send('ServiceWorker.enable')
  await panel.waitForTimeout(250)
  const version=[...versions.values()].find(v=>v.scriptURL===worker.url())
  assert.ok(version,'extension worker version discovered')
  await cdp.send('ServiceWorker.stopWorker',{versionId:version.versionId})
  await panel.getByRole('heading',{name:'Check Wallet',exact:true}).waitFor()
  assert.equal(await panel.getByRole('heading',{name:'Wallet ready',exact:true}).isVisible(),false)
  assert.equal(await panel.getByRole('button',{name:'Saved grants & backup',exact:true}).isVisible(),false)
  await panel.getByRole('button',{name:'Check Wallet',exact:true}).click()
  await panel.getByRole('heading',{name:'Wallet locked',exact:true}).waitFor()
  assert.equal(await panel.locator('#public-member-key').inputValue(),identity)
  await panel.getByLabel('Passphrase').fill(password)
  await panel.getByRole('button',{name:'Unlock',exact:true}).click()
  await panel.getByRole('heading',{name:'Wallet ready',exact:true}).waitFor()
  assert.equal(await panel.locator('#public-member-key').inputValue(),identity)
  assert.deepEqual(await digestExtensionPackage(extension),before,'test never modifies package bytes')
  console.log(JSON.stringify({qualification:'actual packaged extension, disposable Wallet only',package_digest:before.digest,
    worker_stop_invalidates_ready:true,explicit_check_reports_locked:true,explicit_unlock_restores_same_identity:true,
    two_panel_lock_and_unlock_sync:true,decrypted_root_not_restored_after_worker_stop:true}))
}finally{
  await context?.close()
  await rm(profile,{recursive:true,force:true})
}
