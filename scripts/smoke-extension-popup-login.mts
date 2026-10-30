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
const python = selected('DEVGRAPH_TEST_PYTHON'), holder = selected('SECS_HOLDER_TEST_BINARY'), read = selected('SECS_READ_TEST_BINARY'), consumer = selected('DEVGRAPH_CONSUMER_DIRECTORY')
const packageBefore = await verifyExtensionPackageDigest(extension, `${extension}.contents.sha256`)
function sourcePin(directory:string){
 const git=(args:string[])=>{const result=spawnSync('git',args,{cwd:directory,encoding:'utf8'});assert.equal(result.status,0);return result.stdout.trim();};
 const origin=git(['remote','get-url','origin']);assert.ok(['git@github.com:ZenithResearch/devgraph.git','https://github.com/ZenithResearch/devgraph.git','https://github.com/ZenithResearch/devgraph'].includes(origin),'canonical receiver source required');
 assert.equal(git(['status','--porcelain']),'','freeze the selected consumer/fixture source before qualification');
 return {revision:git(['rev-parse','HEAD']),tree:git(['rev-parse','HEAD^{tree}'])};
}
const receiverBefore=sourcePin(receiver),consumerBefore=sourcePin(consumer);
const native={holder_sha256:createHash('sha256').update(await readFile(holder)).digest('hex'),read_sha256:createHash('sha256').update(await readFile(read)).digest('hex')};

// Fixture-only policy storage and canonical validity, before native signing.
// No production API, CORS behavior, signed output or verification is replaced.
const fixtureSetup=`from pathlib import Path
from devgraph.auth.holder_grants import HolderGrantHost
from devgraph.auth.monitor_read import MemberMonitorReadEnrollment
from devgraph.auth.delegated_contract import canonical_json
from tests.native_read import holder_session_fixture
# This monitor fixture explicitly approves its one synthetic Arena before native
# issuance. Keep the canonical validators, signatures and scope checks unchanged.
from devgraph.auth.arena_access import ArenaAccessDraft, ArenaMemberPolicy, compile_arena_read
from devgraph.auth.arena_activation import ArenaMonitorReadEnrollment
class MonitorFixtureDraft:
    @staticmethod
    def model_validate(raw):
        assert raw['receiver'] == 'https://fixture.invalid'
        raw=dict(raw, schema='devgraph.access-draft.v6',read_grants=[*raw['read_grants'],{'scope':'devgraph.arena.read','arena_ids':['fixture-arena']}])
        raw['validity']={'schema':'castalia.grant-validity.v1','mode':'dated','not_before':raw.pop('not_before'),'not_after':raw.pop('not_after')}
        return ArenaAccessDraft.model_validate(raw)
class MonitorFixtureRegistry:
    @staticmethod
    def model_validate(raw):
        return ArenaMemberPolicy.model_validate(dict(raw,schema='devgraph.member-access-policy.v5'))
class MonitorFixtureEnrollment(MemberMonitorReadEnrollment):
    _decode_enrollment_ceiling=ArenaMonitorReadEnrollment._decode_enrollment_ceiling
    _decode_grants=ArenaMonitorReadEnrollment._decode_grants
    _policy_for=ArenaMonitorReadEnrollment._policy_for
    def _details(self,policy):
        return dict(super()._details(policy),schema='devgraph.native-read-scope.v5')
    def _result(self,credential,manifest):
        return dict(super()._result(credential,manifest),schema='devgraph.native-read-result.v5')
holder_session_fixture.AccessDraftV2=MonitorFixtureDraft
holder_session_fixture.MemberAccessPolicyV2=MonitorFixtureRegistry
holder_session_fixture.MemberMonitorReadEnrollment=MonitorFixtureEnrollment
holder_session_fixture.compile_monitor_read=compile_arena_read
from devgraph.arenas import ArenaMutations
from tests.model.test_arena_runtime import add_arena
OriginalStorage=holder_session_fixture.MemoryGraphStorage
class MonitorFixtureStorage(OriginalStorage):
    def __init__(self):
        super().__init__()
        add_arena(ArenaMutations(self),'fixture-arena')
holder_session_fixture.MemoryGraphStorage=MonitorFixtureStorage
original_invoke=HolderGrantHost.invoke
def invoke(self, operation, **fields):
    if operation == 'issue_v2':
        claims=dict(fields['claims'])
        claims['validity']={'schema':'castalia.grant-validity.v1','mode':'until_revoked','not_before':claims['validity']['not_before']}
        fields=dict(fields,claims=claims)
    return original_invoke(self, operation, **fields)
HolderGrantHost.invoke=invoke
original_init=MemberMonitorReadEnrollment.__init__
def initialize(self, **kwargs):
    path=Path(kwargs['path']).parent/'browser-member-policy.json'
    if not path.exists():
        path.write_bytes(canonical_json(kwargs['members']()))
        path.chmod(0o600)
    kwargs['members']=lambda: ArenaMemberPolicy.model_validate_json(path.read_bytes())
    original_init(self, **kwargs)
MemberMonitorReadEnrollment.__init__=initialize
`;
const directory = await mkdtemp(join(tmpdir(), 'castalia-holder-browser-'))
const env = { ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONPATH: join(receiver, 'src') + ':' + receiver }
const fixture = join(directory, 'issuer'), tls = join(directory, 'tls')
await (await import('node:fs/promises')).mkdir(tls, { mode: 0o700 })
const certificates = spawnSync(python, ['-c', 'from tests.native_read.holder_session_fixture import tls_files; import sys; tls_files(sys.argv[1])', tls], { cwd: receiver, env, encoding: 'utf8' })
assert.equal(certificates.status, 0, certificates.stderr)
const certificate = await readFile(join(tls, 'tls.crt')), key = await readFile(join(tls, 'tls.key'))
const spki = createHash('sha256').update(new X509Certificate(certificate).publicKey.export({ type: 'spki', format: 'der' })).digest('base64')
let server: ReturnType<typeof spawn> | undefined, agent: https.Agent | undefined, context: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined
let upstream = '', profile: any, parent: any, exchanges = 0, reads = 0, statuses = 0, dropExchangeReply = false,dropGrantReply=false,grantIssues=0,denyPrepare=false,denyAccessPrepare=false,accessActions=0
const enrollments:string[]=[];const accessIds:string[]=[];let lastIssuedParent:any=null
const nextPopup=()=>{assert.ok(context);const pending=context.waitForEvent('page');void pending.catch(()=>{});return pending;};
const requests: Array<{path:string;status:number;method?:string;origin?:string}> = []
const request = (path: string, raw?: Buffer, headers: Record<string, any> = {},method?:string): Promise<{ status: number; headers: any; body: Buffer }> => new Promise((accept, reject) => {
  const req = https.request(new URL(path, upstream), { agent, method: method??(raw === undefined ? 'GET' : 'POST'), headers:{...(profile?{Host:new URL(profile.origins[0]).host}:{}),...headers} }, res => {
    const chunks: Buffer[] = []; let size = 0
    res.on('data', b => { size += b.length; if (size > 262144) req.destroy(Error('fixture response capacity')); else chunks.push(b) })
    res.on('end', () => accept({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks) }))
  }); req.on('error', reject); req.end(raw)
})
const actualBody=`<!doctype html><meta charset='utf-8'><button id='login' disabled>Log in with Wallet</button><button id='read'>Read</button><button id='logout'>Log out</button><script type='module' nonce='cG9wdXAtZml4dHVyZQ=='>
import{WalletLoginClient}from'/assets/credential-v2/session-login.mjs';
window.result=null;window.actual=new WalletLoginClient({onChange:c=>{window.stage=c.stage;}});await actual.initialize();
while(!window.castaliaWallet)await new Promise(r=>setTimeout(r,20));
if(!await actual.resumeLogin())await actual.prepareLogin(castaliaWallet);window.ready=true;document.querySelector('#login').disabled=actual.stage!=='login_ready';
const run=f=>{window.result=null;f().then(v=>window.result={ok:true,value:v??null},e=>window.result={ok:false,error:e.code??e.message});};
document.querySelector('#login').onclick=()=>run(()=>actual.login());
document.querySelector('#read').onclick=()=>run(()=>actual.read('/todos/v2?kind=Task'));
document.querySelector('#logout').onclick=()=>run(()=>actual.logout());
</script>`;
const body = `<!doctype html><meta charset="utf-8"><button id="connect">Connect Wallet</button><button id="save">Save fixture grant</button><button id="login">Log in with Wallet</button><button id="read">Read</button><button id="status">Check original</button><script type="module">
import {createBrowserHolderSession} from '/assets/credential-v2/holder-session.mjs';
const configuration=await(await fetch('/fixture')).json();window.fixture=configuration;window.result=null;window.ready=true;window.ttl=12;
const run=f=>{window.result=null;Promise.resolve().then(f).then(value=>window.result={ok:true,value},error=>window.result={ok:false,error:error.code??error.message,dispatched:error.dispatched})};
const gesture=f=>{window.result=null;f().then(value=>window.result={ok:true,value},error=>window.result={ok:false,error:error.code??error.message,dispatched:error.dispatched})};
document.querySelector('#connect').onclick=()=>gesture(()=>castaliaWallet.requestConnection());
document.querySelector('#save').onclick=()=>gesture(()=>castaliaWallet.readAccess({operation:'save_grant',service:configuration.service,grant:configuration.parent}));
window.setupChild=async()=>{window.identity??=await castaliaWallet.readAccess({operation:'identity'});window.session?.dispose();window.session=await createBrowserHolderSession({origin:location.origin,service:configuration.service,holderPublicKey:identity.subject_public_key,installationId:identity.installation_id,profile:configuration.profile,ttlSeconds:window.ttl});window.loginId=crypto.randomUUID().replaceAll('-','');};
document.querySelector('#login').onclick=()=>gesture(()=>castaliaWallet.readAccess({operation:'open_session_login',loginId,service:configuration.service,session_public_key:session.publicKey,session_installation_id:session.installationId,requested_ttl_seconds:window.ttl,profile:configuration.profile}).then(async p=>{window.prepared=p;const signature=await session.prepare(p.challenge);const result=await castaliaWallet.readAccess({operation:'complete_session_login',loginId:p.loginId,challenge:p.challenge,session_signature:signature});await session.accept(result.credential);window.credential=result.credential;return {expires_at:session.expiresAt};}));
window.call={operation:'devgraph.work.list',resource:'https://work.zenith-research.ca/devgraph',parameters:{path:'/todos/v2?kind=Task'}};
document.querySelector('#read').onclick=()=>run(async()=>{const proof=await session.present(call);window.lastProof=proof;const response=await fetch('/monitor/wallet-access/v1/requests',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(proof)});return{status:response.status,value:await response.json()}});
document.querySelector('#status').onclick=()=>run(async()=>{const proof=await session.status();const result=await(await fetch('/holder-sessions/v1/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(proof)})).json();if(result.state==='issued'&&!session.active){await session.accept(result.credential);window.credential=result.credential;}return result;});
</script>`
const edge = https.createServer({ cert: certificate, key }, async (req, res) => {
  try {
    const path = req.url!.split('?')[0]
    if(path==='/actual'){res.setHeader('Content-Type','text/html');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self' 'nonce-cG9wdXAtZml4dHVyZQ==' chrome-extension: moz-extension: safari-web-extension:; connect-src 'self'; object-src 'none'; base-uri 'none'");res.end(actualBody);return;}
    if (path === '/') { res.setHeader('Content-Type', 'text/html'); res.end(body); return }
    if (path === '/fixture') { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ service: profile.presentations[0].service, profile: { ...profile, presentations: profile.presentations.map(({ service, ...pin }: any) => pin) }, parent })); return }
    if(/^\/assets\/credential-v2\/[a-z0-9-]+\.mjs$/.test(path)){res.setHeader('Content-Type','text/javascript');res.end(await readFile(join(consumer,'src/devgraph/frontend/static/credential-v2',path.split('/').at(-1)!)));return;}
    if(path==='/monitor/wallet-access/v1'){const config=JSON.parse((await request(path)).body.toString());config.provider_profile={...profile,presentations:profile.presentations.map(({service,...pin}:any)=>pin)};config.membership_requirement='optional';res.setHeader('Content-Type','application/json');res.end(JSON.stringify(config));return;}
    if(path==='/devgraph/access-requests/v2/challenges'&&denyAccessPrepare){res.writeHead(401,{'Content-Type':'application/json'});res.end('{"error":"synthetic_access_denial"}');return;}
    if(path.endsWith('/holder-sessions/v1/challenges')&&denyPrepare){res.writeHead(401,{'Content-Type':'application/json'});res.end('{"error":"synthetic_challenge_denial"}');return;}
    if (path === '/favicon.ico') { res.writeHead(204); res.end(); return }
    assert.ok(path.startsWith('/holder-sessions/v1/') || ['/devgraph/access-requests/v2/challenges','/devgraph/access-requests/v2/actions','/monitor/wallet-access/v1/requests','/monitor/wallet-access/v1/challenges','/monitor/wallet-access/v1/grants/v2'].includes(path), 'unexpected route ' + path)
    const chunks: Buffer[] = []; let bytes = 0
    for await (const b of req) { bytes += b.length; assert.ok(bytes <= 131072); chunks.push(b) }
    if (path.endsWith('/exchange')) exchanges++
    if (path.endsWith('/requests')) reads++
    if (path.endsWith('/status')) statuses++
    const raw = req.method === 'POST' ? Buffer.concat(chunks) : undefined
    if(path==='/devgraph/access-requests/v2/challenges')assert.equal(JSON.parse(raw!).request.intent,null,'general resource request has no preset');
    if(path==='/monitor/wallet-access/v1/grants/v2'){grantIssues++;enrollments.push(createHash('sha256').update(raw!).digest('hex'));}
    const result = await request(req.url!, raw, { ...(raw ? { 'Content-Type': 'application/json', 'Content-Length': raw.length } : {}), Host:new URL(profile.origins[0]).host,...(req.headers.origin ? { Origin: req.headers.origin } : {}),...(req.headers['access-control-request-method']?{'Access-Control-Request-Method':req.headers['access-control-request-method']}:{}),...(req.headers['access-control-request-headers']?{'Access-Control-Request-Headers':req.headers['access-control-request-headers']}:{}),},req.method)
    requests.push({path,status:result.status,method:req.method,origin:req.headers.origin});if(path==='/devgraph/access-requests/v2/actions'){assert.equal(result.status,200,result.body.toString());accessActions++;accessIds.push(JSON.parse(result.body.toString()).request_id);}if(path==='/monitor/wallet-access/v1/grants/v2'&&result.status===200)lastIssuedParent=JSON.parse(result.body.toString()).grant;
    if(path==='/monitor/wallet-access/v1/grants/v2'&&dropGrantReply){dropGrantReply=false;const headers={...result.headers};delete headers['content-length'];res.writeHead(502,headers);res.end('{"error":"disposable_lost_parent_reply"}');return;}
    if(path.endsWith('/exchange')&&dropExchangeReply){dropExchangeReply=false;const headers={...result.headers};delete headers['content-length'];res.writeHead(502,headers);res.end('{"error":"disposable_lost_committed_reply"}');return}
    res.writeHead(result.status,result.headers);res.end(result.body)
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
  // Disposable issuer assignment uses this installation; no real device data.
  await custody.evaluate(()=>new Promise<void>(r=>(globalThis as any).chrome.storage.local.set({'castalia-read-installation-v1':'aa'.repeat(16)},r)))
  const created = spawnSync(python, ['-c',fixtureSetup+'from tests.native_read.holder_session_fixture import main; raise SystemExit(main())', '--directory', fixture, '--holder-public-key', identity, '--holder-binary', holder, '--read-binary', read, '--origin', origin], { cwd: receiver, env, encoding: 'utf8' })
  assert.equal(created.status, 0, created.stderr)
  const metadata = JSON.parse(created.stdout.trim())
  const requestFixture=fixtureSetup+`import sys, os
from pathlib import Path
from devgraph.api import wallet_monitor
from devgraph.api.access_requests import register_access_request_routes
from devgraph.auth.access_requests import AccessRequestInbox
from tests.native_read import holder_session_fixture
from devgraph.public_read_runtime import PublicReadBoundary
import uvicorn,time
OriginalServer=uvicorn.Server
class BoundedServer(OriginalServer):
    def __init__(self,config):
        config.app=PublicReadBoundary(config.app,origin=os.environ['CASTALIA_TEST_ORIGIN'],expires_at=int(time.time())+600)
        super().__init__(config)
uvicorn.Server=BoundedServer
original=wallet_monitor.register_wallet_monitor
def register(target, **kwargs):
    enrollment=kwargs['enrollment']
    inbox=AccessRequestInbox(path=Path(os.environ['CASTALIA_TEST_PROFILE']).parent/'access.sqlite',issuer=enrollment.policy().issuer,receiver=os.environ['CASTALIA_TEST_ORIGIN'],membership_check=lambda proof, owner: proof == {})
    register_access_request_routes(target,inbox)
    original(target, **kwargs)
wallet_monitor.register_wallet_monitor=register
raise SystemExit(holder_session_fixture.main())
`;
  server = spawn(python, ['-c',requestFixture,'--profile-file',metadata.profile,'--https'], { cwd: receiver, env:{...env,CASTALIA_TEST_PROFILE:metadata.profile,CASTALIA_TEST_ORIGIN:origin}, stdio: ['ignore', 'pipe', 'pipe'] })
  let diagnostics = ''; server.stderr!.on('data', b => diagnostics = (diagnostics + b).slice(-3000))
  const lines = createInterface({ input: server.stdout! })
  const ready: any = await Promise.race([new Promise((accept, reject) => { lines.once('line', line => { try { accept(JSON.parse(line)) } catch (error) { reject(error) } }); server!.once('exit', code => reject(Error('fixture exited ' + code + ': ' + diagnostics))) }), new Promise((_, reject) => { const t = setTimeout(() => reject(Error('fixture startup timeout')), 15000); t.unref() })])
  lines.close(); upstream = ready.base_url; agent = new https.Agent({ ca: await readFile(ready.certificate) })
  parent = JSON.parse(await readFile(metadata.parent, 'utf8'))
  assert.equal(parent.claims.validity.mode,'until_revoked');assert.equal(Object.hasOwn(parent.claims.validity,'not_after'),false);
  profile = { schema: 'castalia.provider-profile.v1', display_name: 'Disposable session receiver', origins: [origin], membership: null, presentations: [{ ...metadata.provider, audience: 'devgraph', callers: [{ kind: 'browser', id: origin }] }] }
  for (let n = 0; n < 40; n++) { try { if ((await request('/holder-sessions/v1/capabilities')).status === 200) break } catch {} await new Promise(r => setTimeout(r, 50)) }
  const extensionOrigin='chrome-extension://'+id;
  for(const path of ['/monitor/wallet-access/v1/requests','/devgraph/access-operator/v1/challenges']){
    const blocked=await request(path,undefined,{Origin:extensionOrigin,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'content-type'},'OPTIONS');
    assert.ok([404,421].includes(blocked.status),'extension preflight must stay closed outside signed acquisition/session protocols');assert.equal(blocked.headers['access-control-allow-origin'],undefined);
  }
  await importProfile(context, id, { ...profile, presentations: profile.presentations.map(({ service, ...pin }: any) => pin) }, { membership: false, presentations: true })
  const page = await context.newPage(); await page.goto(origin); await page.waitForFunction(() => (window as any).ready && (window as any).castaliaWallet?.readAccess)
  const capabilities = await page.evaluate(() => (window as any).castaliaWallet.getCapabilities())
  assert.ok(capabilities.includes('holder_session_exchange_v1'), 'qualified package must advertise the actual session bridge')
  const result = async () => { await page.waitForFunction(() => (window as any).result !== null); return page.evaluate(() => (window as any).result) }
  const approve = async (button: string, title: string) => { const opened = nextPopup(); await page.locator(button).click(); const popup = await opened; await clickClosingApproval(popup, title, page); const r = await result(); assert.equal(r.ok, true, r.error); return r.value }
  await approve('#connect', 'Connect')
  await approve('#save', 'Save grant and connect')
  let storedParent=await custody.evaluate(owner=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get('castalia-holder-grants-v1:'+owner,r)),identity);
  assert.equal(grantIssues,0,'saving a supplied native-signed fixture grant creates no replacement');
  // Wallet-owned Saved grants confirmation: cancellation preserves the record;
  // a lost confirmation reply must not claim the completed deletion was undone.
  const grantsUi=await context.newPage();await grantsUi.goto('chrome-extension://'+id+'/src/holder-grants.html');
  const removeSavedGrant=()=>grantsUi.locator('#grants>article').filter({has:grantsUi.getByText(parent.claims.service,{exact:true})}).getByRole('button',{name:/^Remove .+ grant from Wallet$/});
  await removeSavedGrant().click();await grantsUi.getByRole('button',{name:'Keep saved grant',exact:true}).click();
  const allBefore=await custody.evaluate(()=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get(null,r)));
  const journalsBefore=await custody.evaluate(()=>new Promise<any>(r=>(globalThis as any).chrome.storage.session.get(null,r)));
  assert.deepEqual(await custody.evaluate(owner=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get('castalia-holder-grants-v1:'+owner,r)),identity),storedParent);
  await grantsUi.evaluate(()=>{const api=(globalThis as any).chrome.runtime,original=api.sendMessage.bind(api);api.sendMessage=(message:any,callback:any)=>message?.type==='HOLDER_GRANTS_FORGET_CONFIRM'?original(message,()=>callback({ok:false,error:'synthetic_lost_confirmation_reply'})):original(message,callback);});
  await removeSavedGrant().click();await grantsUi.getByRole('button',{name:'Remove saved grant',exact:true}).click();
  await grantsUi.getByText('Could not confirm this operation. Unlock the same Wallet and refresh to check the current saved grants.',{exact:true}).waitFor();
  await grantsUi.getByRole('button',{name:'Refresh',exact:true}).click();await grantsUi.getByRole('heading',{name:'No saved grants',exact:true}).waitFor();
  const allAfter=await custody.evaluate(()=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get(null,r)));
  const grantKey='castalia-holder-grants-v1:'+identity;assert.equal(allAfter[grantKey].revision,allBefore[grantKey].revision+1);
  delete allBefore[grantKey];delete allAfter[grantKey];assert.deepEqual(allAfter,allBefore,'identity, accounts, trust and other local data unchanged');
  assert.deepEqual(await custody.evaluate(()=>new Promise<any>(r=>(globalThis as any).chrome.storage.session.get(null,r))),journalsBefore,'pending/recovery journals unchanged');
  await grantsUi.close();await approve('#save','Save grant and connect');
  storedParent=await custody.evaluate(owner=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get('castalia-holder-grants-v1:'+owner,r)),identity);

  await page.evaluate(()=>(window as any).setupChild())
  await custody.close()
  const popupPromise=nextPopup()
  await page.locator('#login').click();const popup=await popupPromise
  await popup.getByLabel('Wallet password').fill('Disposable browser session password')
  await popup.getByRole('button',{name:'Unlock and continue',exact:true}).click()
  await popup.getByRole('button',{name:'Allow this session',exact:true}).waitFor()
  assert.equal(exchanges,0,'unlock and exact review never dispatch the exchange')
  assert.equal(context.pages().some(p=>/src\/(sidepanel|popup)\.html/.test(p.url())),false,'sidebar is closed')
  // Terminate only this disposable extension background worker during review.
  const cdp=await context.newCDPSession(page),versions=new Map<string,any>()
  cdp.on('ServiceWorker.workerVersionUpdated',({versions:items})=>{for(const item of items)versions.set(item.versionId,item)})
  await cdp.send('ServiceWorker.enable');await page.waitForTimeout(250)
  const version=[...versions.values()].find(v=>v.scriptURL===worker.url());assert.ok(version)
  await cdp.send('ServiceWorker.stopWorker',{versionId:version.versionId})
  await popup.getByRole('button',{name:'Allow this session',exact:true}).waitFor()
  await clickClosingApproval(popup,'Allow this session',page)
  let value=await result();assert.equal(value.ok,true,value.error);const expiry=value.value.expires_at
  assert.equal(exchanges,1,'one explicit consent, one exchange after worker stop')
  await page.locator('#read').click();value=await result();assert.equal(value.value.status,200);assert.deepEqual(value.value.value.items.map((v:any)=>v.key),['Task/allowed-1'])
  const activeProof=await page.evaluate(()=>(window as any).lastProof)
  assert.equal((await request('/monitor/wallet-access/v1/requests',Buffer.from(JSON.stringify(activeProof)),{Origin:origin,'Content-Type':'application/json'})).status,401,'replay denied')
  await page.locator('#status').click();value=await result();assert.equal(value.value.state,'issued');assert.equal(value.value.expires_at,expiry)
  const expiryProof=await page.evaluate(()=>(window as any).session.present((window as any).call))
  while(Math.floor(Date.now()/1000)<expiry)await new Promise(r=>setTimeout(r,100))
  assert.equal((await request('/monitor/wallet-access/v1/requests',Buffer.from(JSON.stringify(expiryProof)),{Origin:origin,'Content-Type':'application/json'})).status,401,'hard expiry denied')
  // Reopen from a locked Wallet and a reloaded page using the SAME encrypted parent.
  const publicIdentity=await page.evaluate(()=>(window as any).identity);
  const locked=await context.newPage();await locked.goto('chrome-extension://'+id+'/src/popup.html');
  await locked.evaluate(()=>new Promise<void>((r,reject)=>(globalThis as any).chrome.runtime.sendMessage({type:'CUSTODY_LOCK'},(v:any)=>v?.ok?r():reject(Error('lock failed')))));
  const lockState=await locked.evaluate(()=>new Promise<any>(r=>(globalThis as any).chrome.runtime.sendMessage({type:'CUSTODY_GET_STATE'},r)));
  assert.equal(lockState.state.unlocked,false);await locked.close();
  await page.reload();await page.waitForFunction(()=>(window as any).ready);await page.evaluate(value=>{(window as any).identity=value},publicIdentity);
  // A committed but dropped reply must recover the original child, never re-sign.
  await page.evaluate(async()=>{(window as any).ttl=30;await (window as any).setupChild()})
  dropExchangeReply=true
  const secondPopupPromise=nextPopup();await page.locator('#login').click();const secondPopup=await secondPopupPromise
  await secondPopup.getByLabel('Wallet password').fill('Disposable browser session password');await secondPopup.getByRole('button',{name:'Unlock and continue',exact:true}).click()
  await clickClosingApproval(secondPopup,'Allow this session',page)
  value=await result();assert.equal(value.ok,false);assert.equal(value.error,'holder_session_outcome_unknown');assert.equal(value.dispatched,true);assert.equal(exchanges,2)
  await page.locator('#status').click();value=await result();assert.equal(value.value.state,'issued');assert.equal(exchanges,2)
  await page.locator('#read').click();value=await result();assert.equal(value.value.status,200)
  const savedInspector=await context.newPage();await savedInspector.goto('chrome-extension://'+id+'/src/popup.html');
  assert.deepEqual(await savedInspector.evaluate(owner=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get('castalia-holder-grants-v1:'+owner,r)),identity),storedParent);
  await savedInspector.close();assert.equal(grantIssues,0,'locked/reloaded login uses the exact same parent');
  const oldGenerationProof=await page.evaluate(()=>(window as any).session.present((window as any).call));
  const oldGenerationExpiry=await page.evaluate(()=>(window as any).credential.claims.challenge.expires_at);
  // Explicit global lock is different from worker suspension: it cancels review.
  await page.evaluate(()=>(window as any).setupChild())
  const thirdPopupPromise=nextPopup();await page.locator('#login').click();const thirdPopup=await thirdPopupPromise
  await thirdPopup.getByLabel('Wallet password').fill('Disposable browser session password');await thirdPopup.getByRole('button',{name:'Unlock and continue',exact:true}).click()
  await thirdPopup.getByRole('button',{name:'Allow this session',exact:true}).waitFor()
  const operator=await context.newPage();await operator.goto('chrome-extension://'+id+'/src/popup.html')
  await operator.evaluate(()=>new Promise<void>((accept,reject)=>(globalThis as any).chrome.runtime.sendMessage({type:'CUSTODY_LOCK'},(r:any)=>r?.ok?accept():reject(Error('disposable explicit lock failed')))))
  value=await result();assert.equal(value.ok,false);assert.equal(value.dispatched,false);assert.equal(exchanges,2,'explicit lock blocks dispatch')
  await operator.close();if(!thirdPopup.isClosed())await thirdPopup.close()
  // Negative fault injection in ONE disposable popup, without changing the
  // packaged Worker, issuer, signed bytes or any successful-path behavior.
  await page.evaluate(()=>(window as any).setupChild());
  const fenceLoginId=await page.evaluate(()=>(window as any).loginId);
  await context.addInitScript(({loginId})=>{
    if(location.protocol!=='chrome-extension:'||new URL(location.href).searchParams.get('login')!==loginId)return;
    const NativeWorker=globalThis.Worker;
    (globalThis as any).Worker=class extends NativeWorker{
      pending=new Set<string>();
      constructor(url:string|URL,options?:WorkerOptions){super(url,options);this.addEventListener('message',event=>{
        if(event.data?.kind==='host'&&event.data.method==='beforeSessionDispatch')this.pending.add(event.data.id);
      });}
      postMessage(message:any,options?:any){
        if(message?.kind==='host_result'&&this.pending.delete(message.id)){
          document.documentElement.dataset.finalFenceInjected='true';
          return super.postMessage({kind:'host_result',id:message.id,ok:false,error:{code:'session_login_context_changed',stage:'authorization',dispatched:false}},options);
        }
        return super.postMessage(message,options);
      }
    };
  },{loginId:fenceLoginId});
  const fencedOpening=nextPopup();await page.locator('#login').click();const fencedPopup=await fencedOpening;
  await fencedPopup.getByLabel('Wallet password').fill('Disposable browser session password');await fencedPopup.getByRole('button',{name:'Unlock and continue',exact:true}).click();
  await clickClosingApproval(fencedPopup,'Allow this session',page);value=await result();
  assert.equal(value.ok,false);assert.equal(value.error,'session_login_context_changed');assert.equal(value.dispatched,false);assert.equal(exchanges,2,'final fence rejection sends no exchange POST');
  assert.equal(await fencedPopup.locator('html').getAttribute('data-final-fence-injected'),'true');
  await fencedPopup.close();
  // Advance the disposable registry through its actual model/epoch machinery.
  // Old signed roots remain stored but cannot authorize reads after this change.
  const registryPath=join(fixture,'browser-member-policy.json'),registry=JSON.parse(await readFile(registryPath,'utf8'));
  registry.revision=(registry.revision??1)+1;registry.assignments[0].lifetime_seconds=299;
  await writeFile(registryPath,JSON.stringify(registry),{mode:0o600});
  assert.ok(Math.floor(Date.now()/1000)<oldGenerationExpiry,'old child is still within its time limit');
  const staleRead=await request('/monitor/wallet-access/v1/requests',Buffer.from(JSON.stringify(oldGenerationProof)),{Origin:origin,'Content-Type':'application/json'});
  assert.equal(staleRead.status,401,'the old assignment generation is no longer usable');
  const refreshedPage=await context.newPage();await refreshedPage.goto(origin+'/actual');await refreshedPage.waitForFunction(()=>(window as any).ready);
  const refreshOpening=nextPopup();await refreshedPage.locator('#login').click();const refreshPopup=await refreshOpening;
  await refreshPopup.getByLabel('Wallet password').fill('Disposable browser session password');await refreshPopup.getByText('Saved access help',{exact:true}).click();await refreshPopup.getByRole('button',{name:'Check saved access',exact:true}).click();
  try{await refreshPopup.getByRole('button',{name:'Check approved access',exact:true}).waitFor({timeout:5000});}catch(error){console.error(JSON.stringify({fixture_stage:'changed_assignment_login',popup:await refreshPopup.locator('body').innerText(),requests:requests.slice(-8),diagnostics}));throw error;}assert.equal(grantIssues,0);assert.equal(accessActions,0);
  await refreshPopup.getByText('A grant is saved in this Wallet.',{exact:true}).waitFor();assert.match(await refreshPopup.locator('#access-status').innerText(),/does not confirm/);
  const refreshInspectorSnapshot=()=>refreshPopup.evaluate(owner=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get('castalia-holder-grants-v1:'+owner,r)),identity);
  const popupJournalsBefore=await refreshPopup.evaluate(()=>new Promise<any>(r=>(globalThis as any).chrome.storage.session.get(null,r)));
  await refreshPopup.getByRole('button',{name:'Forget saved grant',exact:true}).click();
  await refreshPopup.getByRole('button',{name:'Keep saved grant',exact:true}).click();
  await refreshPopup.getByRole('button',{name:'Forget saved grant',exact:true}).click();
  await refreshPopup.getByRole('button',{name:'Forget this saved grant',exact:true}).waitFor();
  assert.match(await refreshPopup.locator('#forget-details').innerText(),new RegExp(parent.claims.grant_id));
  assert.equal(await refreshPopup.locator('#status').innerText(),'Review this local removal. No server access is revoked.');
  assert.equal(grantIssues,0);assert.equal(accessActions,0);
  const beforeForget=await refreshInspectorSnapshot();assert.deepEqual(beforeForget,storedParent,'review and cancel preserve old local parent');
  await refreshPopup.getByRole('button',{name:'Forget this saved grant',exact:true}).click();
  await refreshPopup.getByText('Check your approved access.',{exact:true}).waitFor();
  const forgotten=await refreshInspectorSnapshot();assert.equal(forgotten[grantKey].revision,beforeForget[grantKey].revision+1);assert.ok(forgotten[grantKey].ciphertext);assert.equal(grantIssues,0);assert.equal(accessActions,0);
  assert.deepEqual(await refreshPopup.evaluate(()=>new Promise<any>(r=>(globalThis as any).chrome.storage.session.get(null,r))),popupJournalsBefore,'forget preserves pending/uncertain journals');
  await refreshPopup.getByRole('button',{name:'Check approved access',exact:true}).click();
  try{await refreshPopup.getByRole('button',{name:'Obtain approved grant',exact:true}).waitFor({timeout:5000});}
  catch(error){console.error(JSON.stringify({fixture_stage:'updated_assignment_grant_review',popup:await refreshPopup.locator('body').innerText(),requests:requests.slice(-12),diagnostics}));throw error;}
  await refreshPopup.getByRole('button',{name:'Obtain approved grant',exact:true}).click();await refreshPopup.getByRole('button',{name:'Save grant in Wallet',exact:true}).waitFor();
  assert.equal(grantIssues,1);assert.notEqual(lastIssuedParent.claims.revision,parent.claims.revision);assert.equal(lastIssuedParent.claims.validity.mode,'until_revoked');assert.equal(Object.hasOwn(lastIssuedParent.claims.validity,'not_after'),false);
  const refreshInspector=await context.newPage();await refreshInspector.goto('chrome-extension://'+id+'/src/popup.html');
  assert.deepEqual(await refreshInspector.evaluate(owner=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get('castalia-holder-grants-v1:'+owner,r)),identity),forgotten,'forgotten state unchanged until explicit save');
  await refreshPopup.getByRole('button',{name:'Save grant in Wallet',exact:true}).click();

  await clickClosingApproval(refreshPopup,'Allow this session',refreshedPage);
  try{await refreshedPage.waitForFunction(()=>(window as any).stage==='ready');}catch(error){console.error(JSON.stringify({fixture_stage:'updated_parent_session',state:await refreshedPage.evaluate(()=>({stage:(window as any).stage,error:(window as any).result?.error})),requests:requests.slice(-10)}));throw error;}
  await refreshedPage.locator('#read').click();await refreshedPage.waitForFunction(()=>(window as any).result!==null);assert.equal((await refreshedPage.evaluate(()=>(window as any).result)).ok,true);
  const monitor=await refreshedPage.evaluate(()=>(window as any).actual.read('/monitor/topology/v1'));
  assert.ok(JSON.stringify(monitor).includes('allowed-1'),'current monitor projection contains permitted Work');assert.ok(!JSON.stringify(monitor).includes('Task/hidden'),'monitor does not disclose ungranted Work');
  assert.equal(accessActions,0,'existing approval refresh creates no access request');
  assert.equal(grantIssues,1);assert.equal((await readFile(metadata.parent,'utf8')).includes(parent.claims.grant_id),true,'original issued parent retained');
  await refreshedPage.locator('#logout').click();await refreshedPage.waitForFunction(()=>(window as any).stage==='choose'&&(window as any).result?.ok===true);
  await refreshedPage.close();await refreshInspector.close();const baselineGrantIssues=grantIssues;
  // Actual DevGraph consumer, IndexedDB child custody and strict CSP. Remove
  // only the disposable encrypted grant/profile to exercise first-use setup.
  const setup=await context.newPage();await setup.goto('chrome-extension://'+id+'/src/popup.html');
  await setup.evaluate((owner)=>new Promise<void>(r=>(globalThis as any).chrome.storage.local.remove(['castalia-holder-grants-v1:'+owner,'castalia-provider-profiles-v1'],r)),identity);await setup.close();
  const actual=await context.newPage();await actual.goto(origin+'/actual');await actual.waitForFunction(()=>(window as any).ready&&(window as any).stage==='login_ready');
  const firstUsePopup=nextPopup();await actual.locator('#login').click();let enrollmentPopup=await firstUsePopup;
  await enrollmentPopup.getByLabel('Wallet password').fill('Disposable browser session password');await enrollmentPopup.getByRole('button',{name:'Unlock and continue',exact:true}).click();
  await enrollmentPopup.getByRole('button',{name:'Trust provider and continue',exact:true}).click();
  await enrollmentPopup.getByRole('button',{name:'Check approved access',exact:true}).waitFor();
  assert.equal(await enrollmentPopup.locator('#access button:not([hidden])').first().getAttribute('id'),'prepare-grant','existing approved access is primary');
  assert.equal(await enrollmentPopup.locator('#request-access').evaluate(element=>element.classList.contains('secondary')),true);
  assert.match(await enrollmentPopup.locator('#access-status').innerText(),/already have approved access/);
  denyAccessPrepare=true;await enrollmentPopup.getByRole('button',{name:'Send access request',exact:true}).click();
  await enrollmentPopup.getByText('Wallet could not use the available access.',{exact:true}).waitFor();
  await enrollmentPopup.getByRole('button',{name:'Check approved access',exact:true}).waitFor();assert.equal(accessActions,0);denyAccessPrepare=false;
  // Closing before the one send gesture must create no signed request.
  await enrollmentPopup.close();await actual.waitForFunction(()=>(window as any).result!==null);assert.equal(accessActions,0,'cancel before send creates no request');
  await actual.reload();await actual.waitForFunction(()=>(window as any).ready);const accessRetry=nextPopup();await actual.locator('#login').click();enrollmentPopup=await accessRetry;
  await enrollmentPopup.getByLabel('Wallet password').fill('Disposable browser session password');await enrollmentPopup.getByRole('button',{name:'Unlock and continue',exact:true}).click();
  await enrollmentPopup.getByRole('button',{name:'Send access request',exact:true}).click();
  await enrollmentPopup.getByRole('button',{name:'Check original request',exact:true}).waitFor();assert.equal(accessActions,1,'one send gesture submits once');
  await enrollmentPopup.getByRole('button',{name:'Check original request',exact:true}).click();await enrollmentPopup.getByRole('button',{name:'Check original request',exact:true}).waitFor();
  assert.equal(accessActions,2,'the next gesture checks the original request only');assert.equal(new Set(accessIds).size,1,'no replacement request ID');
  await enrollmentPopup.getByRole('button',{name:'Check approved access',exact:true}).click();
  dropGrantReply=true;
  await enrollmentPopup.getByRole('button',{name:'Obtain approved grant',exact:true}).click();
  await enrollmentPopup.getByRole('button',{name:'Check original grant result',exact:true}).click();
  await enrollmentPopup.getByRole('button',{name:'Save grant in Wallet',exact:true}).waitFor();
  assert.equal(grantIssues,baselineGrantIssues+2);assert.equal(enrollments[baselineGrantIssues],enrollments[baselineGrantIssues+1],'lost parent reply reuses exact authorization without re-signing');
  const unresolved=await enrollmentPopup.evaluate(()=>new Promise<any>(r=>(globalThis as any).chrome.storage.session.get('castalia-session-login-enrollment-recovery-v1',r)));
  assert.equal(JSON.stringify(unresolved).includes('signature'),false);assert.equal(JSON.stringify(unresolved).includes('parent_grant'),false);
  // A verified but unsaved parent is lost with this private Worker. Its public
  // unresolved reference must survive popup closure AND challenge expiry.
  await enrollmentPopup.evaluate(()=>new Promise<void>(r=>(globalThis as any).chrome.storage.session.get('castalia-session-login-enrollment-recovery-v1',(values:any)=>{for(const row of Object.values(values['castalia-session-login-enrollment-recovery-v1']) as any[])row.expires_at-=3600;(globalThis as any).chrome.storage.session.set(values,r)})));
  await enrollmentPopup.close();await actual.waitForFunction(()=>(window as any).result!==null);
  await actual.reload();await actual.waitForFunction(()=>(window as any).ready);
  const reopened=nextPopup();await actual.locator('#login').click();const renewed=await reopened;
  await renewed.getByLabel('Wallet password').fill('Disposable browser session password');await renewed.getByRole('button',{name:'Unlock and continue',exact:true}).click();
  await renewed.getByRole('button',{name:'Check approved access',exact:true}).click();
  await renewed.getByRole('button',{name:'Start a new reviewed attempt',exact:true}).waitFor();assert.equal(grantIssues,baselineGrantIssues+2,'no silent issuance after closure');
  await renewed.getByRole('button',{name:'Start a new reviewed attempt',exact:true}).click();
  await renewed.getByRole('button',{name:'Obtain approved grant',exact:true}).click();
  await renewed.getByRole('button',{name:'Save grant in Wallet',exact:true}).click();

  await clickClosingApproval(renewed,'Allow this session',actual);
  await actual.waitForFunction(()=>(window as any).stage==='ready');
  assert.equal(await actual.evaluate(()=>(window as any).actual.clientSession.checkpoint().privateKey.extractable),false);
  await actual.locator('#read').click();await actual.waitForFunction(()=>(window as any).result!==null);
  assert.equal((await actual.evaluate(()=>(window as any).result)).ok,true);
  const persisted=await actual.evaluate(()=>({epoch:(window as any).actual.lease,expires:(window as any).actual.expiresAt}));
  await actual.reload();await actual.waitForFunction(()=>(window as any).ready);assert.equal(await actual.evaluate(()=>(window as any).stage),'ready');
  assert.deepEqual(await actual.evaluate(()=>({epoch:(window as any).actual.lease,expires:(window as any).actual.expiresAt})),persisted,'reload resumes original child');
  await actual.locator('#logout').click();await actual.waitForFunction(()=>(window as any).stage==='choose');
  await actual.reload();await actual.waitForFunction(()=>(window as any).ready);assert.equal(await actual.evaluate(()=>(window as any).stage),'login_ready');
  // Revoke the disposable saved parent through the fixture's actual enrollment
  // API. A local copy must not disappear or silently obtain a replacement.
  assert.ok(lastIssuedParent);
  const revoked=spawnSync(python,['-c',fixtureSetup+'from tests.native_read.holder_session_fixture import fixture_application; import sys; a=fixture_application(sys.argv[1]); a.sessions.host.enrollment.revoke(sys.argv[2]); a.close()',metadata.profile,'dgrg_'+lastIssuedParent.claims.grant_id],{cwd:receiver,env,encoding:'utf8'});assert.equal(revoked.status,0,revoked.stderr);
  const inspect=await context.newPage();await inspect.goto('chrome-extension://'+id+'/src/popup.html');
  const savedBefore=await inspect.evaluate(owner=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get('castalia-holder-grants-v1:'+owner,r)),identity);
  denyPrepare=true;const deniedPopup=nextPopup();await actual.locator('#login').click();const stale=await deniedPopup;
  await stale.getByLabel('Wallet password').fill('Disposable browser session password');await stale.getByRole('button',{name:'Unlock and continue',exact:true}).click();
  await stale.getByRole('button',{name:'Check approved access',exact:true}).waitFor();assert.equal(grantIssues,baselineGrantIssues+3,'denial never auto-issues a grant');
  assert.deepEqual(await inspect.evaluate(owner=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get('castalia-holder-grants-v1:'+owner,r)),identity),savedBefore,'preparation denial preserves encrypted saved parent');
  await stale.close();denyPrepare=false;await actual.waitForFunction(()=>(window as any).result!==null);
  await actual.reload();await actual.waitForFunction(()=>(window as any).ready);
  const revokedPopup=nextPopup();await actual.locator('#login').click();const revokedReview=await revokedPopup;
  await revokedReview.getByLabel('Wallet password').fill('Disposable browser session password');await revokedReview.getByRole('button',{name:'Unlock and continue',exact:true}).click();
  await clickClosingApproval(revokedReview,'Allow this session',actual);await actual.waitForFunction(()=>(window as any).stage==='session_recovery');
  assert.equal(grantIssues,baselineGrantIssues+3);assert.equal(await actual.evaluate(()=>(window as any).actual.clientSession.checkpoint().privateKey.extractable),false,'generic denial keeps original child');
  assert.equal(await actual.evaluate(()=>(window as any).actual.reconcileLogin()),false);assert.equal(await actual.evaluate(()=>(window as any).actual.notice),'read_access_revoked');
  assert.deepEqual(await inspect.evaluate(owner=>new Promise<any>(r=>(globalThis as any).chrome.storage.local.get('castalia-holder-grants-v1:'+owner,r)),identity),savedBefore);
  if(!revokedReview.isClosed())await revokedReview.close();await inspect.close();await actual.close();
  await writeFile(join(fixture,'REVOKE'),'disposable fixture only\n',{mode:0o600})
  await page.locator('#status').click();value=await result();assert.equal(value.value.state,'revoked');assert.equal(value.value.credential,null)
  assert.equal((await verifyExtensionPackageDigest(extension,`${extension}.contents.sha256`)).digest,packageBefore.digest)
  assert.deepEqual(sourcePin(receiver),receiverBefore);assert.deepEqual(sourcePin(consumer),consumerBefore);
  console.log(JSON.stringify({native,fixture_configuration_overrides:['versioned Arena draft/policy/enrollment using canonical validators; one explicit synthetic Arena and its real storage record before native signing','native-signed until_revoked parent validity with not_after absent; disposable member registry stored as model-validated JSON for real assignment-epoch transition','synthetic provider_profile uses the disposable issuer and actual TLS edge caller','optional membership accurately describes fixture proof=={} admission; real holder signatures are still required'],consumer:consumerBefore,receiver:receiverBefore,qualification:'One popup + private dedicated Worker + native-backed disposable HTTPS issuer',disposable_data:true,package_digest:packageBefore.digest,sidebar_required:false,background_stopped_during_review:true,review_survives_background_stop:true,explicit_lock_blocks_dispatch:true,exchanges,reads,statuses,one_consent_one_exchange:true,root_parent_not_page:true,root_closes_with_popup:true,original_lost_reply_recovered:true,hard_expiry_denied:true,replay_denied:true,revocation_denied:true,actual_consumer:true,production_public_boundary:true,upstream_cors_preserved:true,extension_origins_observed:requests.some(r=>r.origin?.startsWith('chrome-extension://')),protected_read_operator_preflight_closed:true,strict_csp:true,first_use_single_popup:true,native_access_request_and_status:true,cancel_before_submit_sends_nothing:true,general_resource_request:true,parent_exact_recovery:true,unsaved_parent_closure_warning:true,expired_parent_challenge_warning_retained:true,provider_trust:true,parent_saved_encrypted:true,automatic_bounded_lifetime:true,indexeddb_reload_resume:true,logout_clears_child:true,stale_parent_explicit_recovery:true,revoked_parent_denial_retains_child_until_authenticated_status:true,stale_parent_preserved:true,no_automatic_regrant:true,canonical_until_revoked:true,locked_wallet_same_parent_reopen:true,assignment_epoch_refresh:true,local_state_preserved_until_explicit_save:true,old_parent_removed_only_after_explicit_forget:true,refresh_without_access_request:true,monitor_projection_after_recovery:true,final_dispatch_fence_known_not_sent:true,post_dispatch_loss_still_unknown:true,wallet_owned_forget_confirmation:true,forget_lost_reply_copy_honest:true,popup_forget_then_current_grant:true,forget_preserves_other_data_and_journals:true}))
} finally {
  await context?.close(); agent?.destroy(); edge.closeAllConnections(); await new Promise<void>(accept => edge.close(() => accept()))
  if (server?.pid && server.exitCode === null) { server.kill('SIGTERM'); await Promise.race([new Promise(r => server!.once('exit', r)), new Promise(r => { const t = setTimeout(() => { server!.kill('SIGKILL'); r(null) }, 3000); t.unref() })]) }
  await rm(directory, { recursive: true, force: true })
}
