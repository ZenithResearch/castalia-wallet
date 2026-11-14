/** Explicit fixture package: production input stays byte-identical. */
import {build} from 'esbuild'
import {cp,mkdir,readFile,writeFile,lstat} from 'node:fs/promises'
import {resolve,join,dirname} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {createHash} from 'node:crypto'
import {verifyExtensionPackageDigest,writeExtensionPackageDigest} from './extension-package-digest.mjs'
const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..')
export async function packageSelectedFeedsFixture(production,output,origin){
  production=resolve(production);output=resolve(output)
  const sourcePaths=['scripts/package-selected-feeds-fixture.mjs','scripts/fixtures/selected-feeds-worker.ts',...['selected-feeds-runtime.ts','selected-feeds-ui.ts','selected-feeds-choice.ts','selected-feeds-choice.html','selected-feeds-confirmation.ts','selected-feeds-confirmation.html','selected-feeds.css','feed-projection-controller.ts','wallet-identities-store.ts'].map(name=>'apps/chrome-extension/src/'+name)]
  const sources=await Promise.all(sourcePaths.map(async path=>({path,sha256:createHash('sha256').update(await readFile(join(repo,path))).digest('hex')})))
  const parsed=new URL(origin);if(parsed.origin!==origin||parsed.protocol!=='http:'||!['localhost','127.0.0.1','[::1]'].includes(parsed.hostname))throw Error('fixture requires an exact disposable loopback origin')
  if(output===production||output.startsWith(production+'/')||production.startsWith(output+'/'))throw Error('fixture output must be separate')
  try{await lstat(output);throw Error('fixture output already exists')}catch(error){if(error.code!=='ENOENT')throw error}
  const before=await verifyExtensionPackageDigest(production,production+'.contents.sha256')
  await mkdir(dirname(output),{recursive:true});await cp(production,output,{recursive:true,errorOnExist:true,force:false})
  const common={bundle:true,platform:'browser',target:'es2022',logLevel:'warning',minifySyntax:true,tsconfig:join(repo,'apps/chrome-extension/tsconfig.json')}
  await build({...common,format:'esm',entryPoints:[join(repo,'scripts/fixtures/selected-feeds-worker.ts')],outfile:join(output,'dist/selected-feeds-fixture.js'),define:{SELECTED_FEEDS_FIXTURE_ORIGIN:JSON.stringify(origin)}})
  for(const name of ['selected-feeds-choice','selected-feeds-confirmation']){await build({...common,format:'iife',entryPoints:[join(repo,`apps/chrome-extension/src/${name}.ts`)],outfile:join(output,`dist/${name}.js`)});await cp(join(repo,`apps/chrome-extension/src/${name}.html`),join(output,`src/${name}.html`))}
  await cp(join(repo,'apps/chrome-extension/src/selected-feeds.css'),join(output,'src/selected-feeds.css'))
  const manifest=JSON.parse(await readFile(join(output,'manifest.json'),'utf8'));manifest.name='Synthetic selected-feeds fixture — NOT production';manifest.background.service_worker='dist/selected-feeds-fixture.js';await writeFile(join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n')
  const actions=['setup','approve','revoke','lock','unlock','reseal','advance90','advance31','reset-clock','guards']
  await writeFile(join(output,'fixture-setup.html'),'<!doctype html><meta charset="utf-8"><title>Synthetic selected-feeds fixture</title><h1>Disposable synthetic fixture only</h1><p>No personal accounts. No production enablement.</p>'+actions.map(action=>`<button id="${action}" data-action="${action}">${action}</button>`).join('')+'<pre id="status"></pre><script src="fixture-setup.js"></script>')
  await writeFile(join(output,'fixture-setup.js'),'for(const button of document.querySelectorAll("button"))button.addEventListener("click",async()=>{document.querySelector("#status").textContent="Working";const result=await chrome.runtime.sendMessage({type:"SELECTED_FEEDS_FIXTURE_CONTROL",action:button.dataset.action});document.querySelector("#status").textContent=JSON.stringify(result)});')
  const after=await verifyExtensionPackageDigest(production,production+'.contents.sha256');if(before.digest!==after.digest)throw Error('production package changed')
  const result=await writeExtensionPackageDigest(output,output+'.contents.sha256')
  for(const source of sources)if(source.sha256!==createHash('sha256').update(await readFile(join(repo,source.path))).digest('hex'))throw Error('fixture source changed during build')
  await writeFile(output+'.provenance.json',JSON.stringify({schema:'castalia.selected-feeds-browser-fixture.v1',synthetic:true,productionQualification:false,productionDigest:before.digest,fixtureDigest:result.digest,origin,sources,wasmSha256:createHash('sha256').update(await readFile(join(repo,'apps/chrome-extension/src/generated/castalia-wallet-core/castalia_wallet_core_bg.wasm'))).digest('hex'),transformations:['Separate fixture service worker with explicit synthetic host policy','Synthetic disposable custody/source seeding','Private chooser and consent assets; production package unchanged']},null,2)+'\n')
  return result
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){const [production,output,origin]=process.argv.slice(2);if(!production||!output||!origin)throw Error('usage: production output loopbackOrigin');console.log(await packageSelectedFeedsFixture(production,output,origin))}
