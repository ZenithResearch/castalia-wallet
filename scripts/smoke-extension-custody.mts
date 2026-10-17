import { chromium } from 'playwright-core'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const sourceExtension = process.env.CASTALIA_EXTENSION_DIRECTORY ?? join(process.cwd(), 'apps/chrome-extension')
const extensionPath = await mkdtemp(join(tmpdir(), 'castalia-wallet-extension-'))
await (await import('node:fs/promises')).cp(sourceExtension, extensionPath, {
  recursive: true,
  filter: source => !source.includes('/node_modules') && !source.includes('/generated'),
})
const userDataDir = await mkdtemp(join(tmpdir(), 'castalia-wallet-smoke-'))
const launchOptions = {
  headless: false,
  executablePath: process.env.CASTALIA_CHROMIUM_EXECUTABLE ?? chromium.executablePath(),
  ignoreDefaultArgs: ['--disable-extensions'],
  args: [
    '--disable-features=DisableLoadExtensionCommandLineSwitch',
    `--disable-extensions-except=${extensionPath}`,
    `--load-extension=${extensionPath}`,
  ],
}
let context = await chromium.launchPersistentContext(userDataDir, launchOptions)
try {
  let worker = context.serviceWorkers()[0]
  if (!worker) {
    const diagnostics = await context.newPage()
    await diagnostics.goto('chrome://extensions/')
    await diagnostics.waitForTimeout(2000)
    const extensions = await diagnostics.evaluate(() => {
      const manager = document.querySelector('extensions-manager') as HTMLElement & { shadowRoot: ShadowRoot }
      const list = manager?.shadowRoot?.querySelector('extensions-item-list') as HTMLElement & { shadowRoot: ShadowRoot }
      const items = [...(list?.shadowRoot?.querySelectorAll('extensions-item') ?? [])] as Array<HTMLElement & { shadowRoot: ShadowRoot }>
      return items.map(item => ({
        id: item.getAttribute('id'),
        text: item.shadowRoot?.textContent ?? '',
      }))
    })
    const castalia = extensions.find(item => item.text.includes('Castalia'))
    if (!castalia) throw new Error(`extension did not load: ${JSON.stringify(extensions)}`)
    worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker', { timeout: 5000 })
  }
  const extensionId = new URL(worker.url()).host
  let page = await context.newPage()
  const openRecovery = async () => {
    const recoveryDetails = page.locator('details.advanced')
    if (!(await recoveryDetails.evaluate(element => (element as HTMLDetailsElement).open))) {
      await recoveryDetails.locator('summary').click()
    }
  }
  const errors: string[] = []
  const workerErrors: string[] = []
  const attachPageErrors = () => {
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    page.on('pageerror', error => errors.push(error.message))
  }
  attachPageErrors()
  worker.on('console', message => { if (message.type() === 'error') workerErrors.push(message.text()) })
  await page.goto(`chrome-extension://${extensionId}/src/sidepanel.html`)
  try {
    await page.getByLabel('Passphrase').waitFor({ timeout: 5000 })
  } catch {
    throw new Error(`custody UI did not initialize: body=${JSON.stringify(await page.locator('body').innerText())} pageErrors=${JSON.stringify(errors)} workerErrors=${JSON.stringify(workerErrors)}`)
  }
  await page.getByLabel('Passphrase').fill('browser smoke passphrase')
  await page.getByRole('button', { name: 'Create wallet' }).click()
  await page.getByText('Wallet ready').waitFor()
  const identity = await page.getByText(/^Identity /).textContent()
  await openRecovery()
  await page.getByRole('button', { name: 'Lock wallet' }).click()
  await page.getByText('Wallet locked').waitFor()
  await page.getByLabel('Passphrase').fill('browser smoke passphrase')
  await page.getByRole('button', { name: 'Unlock' }).click()
  await page.getByText('Wallet ready').waitFor()
  if (await page.getByText(/^Identity /).textContent() !== identity) throw new Error('identity changed after unlock')
  await openRecovery()
  page.once('dialog', dialog => dialog.accept('browser smoke passphrase'))
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export recovery file' }).click()
  const download = await downloadPromise
  if (!/^Castalia-Recovery-\d+\.castalia-recovery$/.test(download.suggestedFilename())) {
    throw new Error(`unexpected recovery filename: ${download.suggestedFilename()}`)
  }
  const recoveryPath = await download.path()
  if (!recoveryPath) throw new Error('encrypted recovery download has no path')
  const recoveryBytes = await readFile(recoveryPath)
  await context.close()
  context = await chromium.launchPersistentContext(userDataDir, launchOptions)
  worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker', { timeout: 5000 })
  page = await context.newPage()
  attachPageErrors()
  await page.goto(`chrome-extension://${extensionId}/src/sidepanel.html`)
  await page.getByText('Wallet locked').waitFor()
  if (await page.getByText(/^Identity /).textContent() !== identity) throw new Error('identity changed after reload')
  await page.getByLabel('Passphrase').fill('browser smoke passphrase')
  await page.getByRole('button', { name: 'Unlock' }).click()
  await page.getByText('Wallet ready').waitFor()
  await openRecovery()
  await page.locator('#import').setInputFiles({
    name: download.suggestedFilename(),
    mimeType: 'application/json',
    buffer: recoveryBytes,
  })
  await page.getByRole('button', { name: 'Import encrypted recovery file' }).waitFor()
  await page.locator('#replacement-confirm').check()
  page.once('dialog', dialog => dialog.accept('browser smoke passphrase'))
  await page.getByRole('button', { name: 'Import encrypted recovery file' }).click()
  await page.getByText('Wallet locked').waitFor()
  if (await page.getByText(/^Identity /).textContent() !== identity) throw new Error('identity changed after import')
  await page.getByLabel('Passphrase').fill('browser smoke passphrase')
  await page.getByRole('button', { name: 'Unlock' }).click()
  await page.getByText('Wallet ready').waitFor()
  if (errors.length) throw new Error(`browser console errors: ${errors.join('; ')}`)
  console.log(`LOADED_BROWSER_CUSTODY_SMOKE_OK extension=${extensionId} identity=${identity} export=ok import=ok`)
} finally {
  await context.close()
  await rm(userDataDir, { recursive: true, force: true })
  await rm(extensionPath, { recursive: true, force: true })
}
