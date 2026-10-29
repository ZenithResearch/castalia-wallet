/** Exact packaged extension + real disposable HTTPS issuer/receiver; no user data. */
import assert from 'node:assert/strict'
import { chromium } from 'playwright-core'
import { spawn, spawnSync } from 'node:child_process'
import { createInterface } from 'node:readline'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createHash, X509Certificate } from 'node:crypto'
import https from 'node:https'
import { verifyExtensionPackageDigest } from './extension-package-digest.mjs'
import { importProfile } from './provider-profile-smoke-helpers.mts'
import { clickClosingApproval } from './approval-popup-smoke-helpers.mjs'

function selected(name: string) { assert.ok(process.env[name], 'Pass ' + name); return resolve(process.env[name]!) }
const extension = selected('CASTALIA_EXTENSION_DIRECTORY'), receiver = selected('DEVGRAPH_SOURCE_DIRECTORY')
const python = selected('DEVGRAPH_TEST_PYTHON'), holder = selected('SECS_HOLDER_TEST_BINARY'), read = selected('SECS_READ_TEST_BINARY')
const packageBefore = await verifyExtensionPackageDigest(extension, `${extension}.contents.sha256`)
const directory = await mkdtemp(join(tmpdir(), 'castalia-holder-browser-'))
const env = { ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONPATH: join(receiver, 'src') + ':' + receiver }
const fixture = join(directory, 'issuer'), tls = join(directory, 'tls')
await (await import('node:fs/promises')).mkdir(tls, { mode: 0o700 })
const certificates = spawnSync(python, ['-c', 'from tests.native_read.holder_session_fixture import tls_files; import sys; tls_files(sys.argv[1])', tls], { cwd: receiver, env, encoding: 'utf8' })
assert.equal(certificates.status, 0, certificates.stderr)
const certificate = await readFile(join(tls, 'tls.crt')), key = await readFile(join(tls, 'tls.key'))
const spki = createHash('sha256').update(new X509Certificate(certificate).publicKey.export({ type: 'spki', format: 'der' })).digest('base64')
let server: ReturnType<typeof spawn> | undefined, agent: https.Agent | undefined, context: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined
let upstream = '', profile: any, parent: any, exchanges = 0, reads = 0, statuses = 0, dropExchangeReply = false
const requests: Array<{path:string;status:number}> = []
const request = (path: string, raw?: Buffer, headers: Record<string, any> = {}): Promise<{ status: number; headers: any; body: Buffer }> => new Promise((accept, reject) => {
  const req = https.request(new URL(path, upstream), { agent, method: raw === undefined ? 'GET' : 'POST', headers }, res => {
    const chunks: Buffer[] = []; let size = 0
    res.on('data', b => { size += b.length; if (size > 262144) req.destroy(Error('fixture response capacity')); else chunks.push(b) })
    res.on('end', () => accept({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks) }))
  }); req.on('error', reject); req.end(raw)
})
const body = `<!doctype html><meta charset="utf-8"><button id="connect">Connect Wallet</button><button id="save">Save fixture grant</button><button id="prepare">Prepare session</button><button id="open">Start session</button><button id="read">Read</button><button id="status">Check original</button><a id="topology" href="#topology">Topology</a><script type="module">
import {createBrowserHolderSession} from '/assets/credential-v2/holder-session.mjs';
const configuration=await(await fetch('/fixture')).json();window.fixture=configuration;
window.result=null;window.ready=true;window.ttl=8;
const run=f=>{window.result=null;Promise.resolve().then(f).then(value=>window.result={ok:true,value},error=>window.result={ok:false,error:error.code??error.message})};
const gesture=f=>{window.result=null;f().then(value=>window.result={ok:true,value},error=>window.result={ok:false,error:error.code??error.message})};
document.querySelector('#connect').onclick=()=>gesture(()=>castaliaWallet.requestConnection());
document.querySelector('#save').onclick=()=>gesture(()=>castaliaWallet.readAccess({operation:'save_grant',service:configuration.service,grant:configuration.parent}));
document.querySelector('#prepare').onclick=()=>run(async()=>{
 const identity=await castaliaWallet.readAccess({operation:'identity'});
 window.session=await createBrowserHolderSession({origin:location.origin,service:configuration.service,holderPublicKey:identity.subject_public_key,installationId:identity.installation_id,profile:configuration.profile,ttlSeconds:window.ttl});
 window.prepared=await castaliaWallet.readAccess({operation:'prepare_holder_session',service:configuration.service,session_public_key:session.publicKey,session_installation_id:session.installationId,requested_ttl_seconds:window.ttl});
 window.possession=await session.prepare(prepared.challenge);return prepared;
});
document.querySelector('#open').onclick=()=>gesture(()=>castaliaWallet.readAccess({operation:'open_holder_session',preparationId:prepared.preparationId,challenge:prepared.challenge,session_signature:possession}).then(async result=>{await session.accept(result.credential);window.credential=result.credential;return{expires_at:session.expiresAt}}));
window.call={operation:'devgraph.work.list',resource:'https://work.zenith-research.ca/devgraph',parameters:{path:'/todos/v2?kind=Task'}};
document.querySelector('#read').onclick=()=>run(async()=>{const proof=await session.present(call);window.lastProof=proof;const response=await fetch('/monitor/wallet-access/v1/requests',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(proof)});return{status:response.status,value:await response.json()}});
document.querySelector('#status').onclick=()=>run(async()=>{const proof=await session.status();const result=await(await fetch('/holder-sessions/v1/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(proof)})).json();if(result.state==='issued'&&!session.active){await session.accept(result.credential);window.credential=result.credential;}return result;});
</script>`
const edge = https.createServer({ cert: certificate, key }, async (req, res) => {
  try {
    const path = req.url!.split('?')[0]
    if (path === '/') { res.setHeader('Content-Type', 'text/html'); res.end(body); return }
    if (path === '/fixture') { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ service: profile.presentations[0].service, profile: { ...profile, presentations: profile.presentations.map(({ service, ...pin }: any) => pin) }, parent })); return }
    if (path === '/assets/credential-v2/holder-session.mjs') { res.setHeader('Content-Type', 'text/javascript'); res.end(await readFile(join(receiver, 'src/devgraph/frontend/static/credential-v2/holder-session.mjs'))); return }
    if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST, GET, OPTIONS', 'Access-Control-Allow-Headers': 'content-type' }); res.end(); return }
    if (path === '/favicon.ico') { res.writeHead(204); res.end(); return }
    assert.ok(path.startsWith('/holder-sessions/v1/') || path === '/monitor/wallet-access/v1/requests', 'unexpected route ' + path)
    const chunks: Buffer[] = []; let bytes = 0
    for await (const b of req) { bytes += b.length; assert.ok(bytes <= 131072); chunks.push(b) }
    if (path.endsWith('/exchange')) exchanges++
    if (path.endsWith('/requests')) reads++
    if (path.endsWith('/status')) statuses++
    const raw = req.method === 'GET' ? undefined : Buffer.concat(chunks)
    const result = await request(req.url!, raw, { ...(raw ? { 'Content-Type': 'application/json', 'Content-Length': raw.length } : {}), ...(req.headers.origin ? { Origin: req.headers.origin } : {}) })
    requests.push({path,status:result.status})
    if(path.endsWith('/exchange')&&dropExchangeReply){dropExchangeReply=false;res.writeHead(502,{'Access-Control-Allow-Origin':'*','Content-Type':'application/json'});res.end('{"error":"disposable_lost_committed_reply"}');return}
    res.writeHead(result.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' }); res.end(result.body)
  } catch (error) { console.error(error); res.writeHead(500); res.end('disposable fixture failed') }
})
try {
  await new Promise<void>(accept => edge.listen(0, '127.0.0.1', accept))
  const origin = 'https://127.0.0.1:' + (edge.address() as import('node:net').AddressInfo).port
  context = await chromium.launchPersistentContext(join(directory, 'profile'), { headless: process.env.CASTALIA_HEADLESS === '1', executablePath: process.env.CASTALIA_CHROMIUM_EXECUTABLE ?? chromium.executablePath(), ignoreDefaultArgs: ['--disable-extensions'], args: ['--disable-features=DisableLoadExtensionCommandLineSwitch', `--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--ignore-certificate-errors-spki-list=' + spki] })
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker'), id = new URL(worker.url()).host
  const custody = await context.newPage(); await custody.goto(`chrome-extension://${id}/src/sidepanel.html`)
  await custody.getByLabel('Passphrase').fill('Disposable browser session password')
  await custody.getByRole('button', { name: 'Create wallet', exact: true }).click(); await custody.getByText('Wallet ready', { exact: true }).waitFor()
  const identity = await custody.evaluate(() => new Promise<string>((accept, reject) => (globalThis as any).chrome.runtime.sendMessage({ type: 'CUSTODY_GET_STATE' }, (r: any) => r?.ok ? accept(r.state.publicKey) : reject(Error('disposable public identity unavailable')))))
  assert.match(identity, /^[a-f0-9]{64}$/)
  const created = spawnSync(python, ['-m', 'tests.native_read.holder_session_fixture', '--directory', fixture, '--holder-public-key', identity, '--holder-binary', holder, '--read-binary', read, '--origin', origin], { cwd: receiver, env, encoding: 'utf8' })
  assert.equal(created.status, 0, created.stderr)
  const metadata = JSON.parse(created.stdout.trim())
  server = spawn(python, ['-m', 'tests.native_read.holder_session_fixture', '--profile-file', metadata.profile, '--https'], { cwd: receiver, env, stdio: ['ignore', 'pipe', 'pipe'] })
  let diagnostics = ''; server.stderr!.on('data', b => diagnostics = (diagnostics + b).slice(-3000))
  const lines = createInterface({ input: server.stdout! })
  const ready: any = await Promise.race([new Promise((accept, reject) => { lines.once('line', line => { try { accept(JSON.parse(line)) } catch (error) { reject(error) } }); server!.once('exit', code => reject(Error('fixture exited ' + code + ': ' + diagnostics))) }), new Promise((_, reject) => { const t = setTimeout(() => reject(Error('fixture startup timeout')), 15000); t.unref() })])
  lines.close(); upstream = ready.base_url; agent = new https.Agent({ ca: await readFile(ready.certificate) })
  parent = JSON.parse(await readFile(metadata.parent, 'utf8'))
  profile = { schema: 'castalia.provider-profile.v1', display_name: 'Disposable session receiver', origins: [origin], membership: null, presentations: [{ ...metadata.provider, audience: 'devgraph', callers: [{ kind: 'browser', id: origin }] }] }
  for (let n = 0; n < 40; n++) { try { if ((await request('/holder-sessions/v1/capabilities')).status === 200) break } catch {} await new Promise(r => setTimeout(r, 50)) }
  await importProfile(context, id, { ...profile, presentations: profile.presentations.map(({ service, ...pin }: any) => pin) }, { membership: false, presentations: true })
  const page = await context.newPage(); await page.goto(origin); await page.waitForFunction(() => (window as any).ready && (window as any).castaliaWallet?.readAccess)
  const capabilities = await page.evaluate(() => (window as any).castaliaWallet.getCapabilities())
  assert.ok(capabilities.includes('holder_session_exchange_v1'), 'qualified package must advertise the actual session bridge')
  const result = async () => { await page.waitForFunction(() => (window as any).result !== null); return page.evaluate(() => (window as any).result) }
  const approve = async (button: string, title: string) => { const opened = context!.waitForEvent('page'); await page.locator(button).click(); const popup = await opened; await clickClosingApproval(popup, title, page); const r = await result(); assert.equal(r.ok, true, r.error); return r.value }
  await approve('#connect', 'Connect')
  await approve('#save', 'Save grant and connect')
  await page.locator('#prepare').click(); const prepared = await result(); assert.equal(prepared.ok, true, prepared.error + ' ' + JSON.stringify(requests)); assert.equal(exchanges, 0)
  const opened = await approve('#open', 'Start temporary session'), expiry = opened.expires_at
  assert.equal(exchanges, 1)
  await page.locator('#read').click(); let value = await result(); assert.equal(value.ok, true, value.error); assert.equal(value.value.status, 200); assert.deepEqual(value.value.value.items.map((v: any) => v.key), ['Task/allowed-1'])
  await custody.getByText('Recovery', { exact: true }).click(); await custody.getByRole('button', { name: 'Lock wallet', exact: true }).click(); await custody.getByText('Wallet locked', { exact: true }).waitFor()
  await page.locator('#topology').click(); await page.locator('#read').click(); value = await result(); assert.equal(value.ok, true, value.error); assert.equal(value.value.status, 200)
  assert.equal(await page.evaluate(() => (window as any).session.expiresAt), expiry); assert.equal(exchanges, 1)
  await page.locator('#status').click(); const status = await result(); assert.equal(status.value.state, 'issued'); assert.equal(status.value.expires_at, expiry)
  const activeProof = await page.evaluate(() => (window as any).lastProof)
  assert.equal((await request('/monitor/wallet-access/v1/requests', Buffer.from(JSON.stringify(activeProof)), { Origin: origin, 'Content-Type': 'application/json' })).status, 401, 'replay denied')
  const expiryProof=await page.evaluate(()=>(window as any).session.present((window as any).call))
  while(Math.floor(Date.now()/1000)<expiry)await new Promise(r=>setTimeout(r,100))
  await page.locator('#read').click();value=await result();assert.equal(value.ok,false);assert.match(value.error,/holder_session_(expired|closed)/)
  assert.equal((await request('/monitor/wallet-access/v1/requests',Buffer.from(JSON.stringify(expiryProof)),{Origin:origin,'Content-Type':'application/json'})).status,401,'unused proof rejected after hard expiry')
  assert.equal(exchanges,1,'expiry never renews access')
  await custody.getByLabel('Passphrase').fill('Disposable browser session password');await custody.getByRole('button',{name:'Unlock',exact:true}).click();await custody.getByText('Wallet ready',{exact:true}).waitFor()
  await page.evaluate(()=>{(window as any).ttl=30});await page.locator('#prepare').click();value=await result();assert.equal(value.ok,true,value.error)
  const secondExpiry=await page.evaluate(()=>(window as any).prepared.challenge.expires_at)
  dropExchangeReply=true
  const secondPopup=context.waitForEvent('page');await page.locator('#open').click();await clickClosingApproval(await secondPopup,'Start temporary session',page);value=await result();assert.equal(value.ok,false);assert.equal(value.error,'holder_session_outcome_unknown')
  await page.locator('#status').click();value=await result();assert.equal(value.value.state,'issued');assert.equal(value.value.expires_at,secondExpiry);assert.equal(exchanges,2,'status recovers original without another exchange')
  await page.locator('#read').click();value=await result();assert.equal(value.value.status,200)
  await writeFile(join(fixture, 'REVOKE'), 'disposable fixture only\n', { mode: 0o600 })
  await page.locator('#read').click(); value = await result(); assert.equal(value.value.status, 401)
  await page.locator('#status').click(); value = await result(); assert.equal(value.value.state, 'revoked'); assert.equal(value.value.credential, null); assert.equal(exchanges, 2)
  assert.equal((await verifyExtensionPackageDigest(extension, `${extension}.contents.sha256`)).digest, packageBefore.digest)
  console.log(JSON.stringify({ qualification: 'Actual packaged extension + temporary browser key + native-backed HTTPS receiver', disposable_data: true, package_digest: packageBefore.digest, explicit_session_approvals: 2, approvals_per_session: 1, exchanges, reads, statuses, reads_after_wallet_lock: true, same_document_expiry_unchanged: true, original_status_only: true, dropped_committed_reply_recovered: true, hard_expiry_client_and_receiver: true, replay_denied: true, current_revocation_denied: true }))
} finally {
  await context?.close(); agent?.destroy(); edge.closeAllConnections(); await new Promise<void>(accept => edge.close(() => accept()))
  if (server?.pid && server.exitCode === null) { server.kill('SIGTERM'); await Promise.race([new Promise(r => server!.once('exit', r)), new Promise(r => { const t = setTimeout(() => { server!.kill('SIGKILL'); r(null) }, 3000); t.unref() })]) }
  await rm(directory, { recursive: true, force: true })
}
