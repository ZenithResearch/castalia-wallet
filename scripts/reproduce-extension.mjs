import assert from 'node:assert/strict'
import {execFileSync,spawnSync} from 'node:child_process'
import {mkdtemp,rm,writeFile,readFile} from 'node:fs/promises'
import {join,resolve} from 'node:path'
import {tmpdir} from 'node:os'
import {createHash} from 'node:crypto'
import {comparePackages} from './canonical-build.mjs'
assert.equal(process.env.BUILDKITE,'true');assert.equal(process.platform,'linux');assert.equal(process.arch,'x64')
const source=process.cwd(),commit=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim()
assert.equal(commit,process.env.BUILDKITE_COMMIT)
assert.equal(execFileSync('git',['status','--porcelain'],{encoding:'utf8'}).trim(),'')
const work=await mkdtemp(join(tmpdir(),'wallet-reproduction-')),dirs=['first','different-longer-directory'].map(x=>join(work,x))
function run(command,args,cwd){const p=spawnSync(command,args,{cwd,stdio:'inherit',env:{...process.env,CASTALIA_EXTENSION_OUTPUT:'build/reproduced'}});if(p.status!==0)throw Error(`${command} failed: ${p.status??p.error}`)}
try{
 for(const dir of dirs){
  run('git',['clone','--shared','--no-checkout',source,dir],source)
  run('git',['checkout','--detach',commit],dir)
  run('npm',['ci','--no-audit','--no-fund'],dir)
  run('npm',['run','package:production-extension'],dir)
  assert.equal(execFileSync('git',['status','--porcelain'],{cwd:dir,encoding:'utf8'}).trim(),'')
 }
 const packages=dirs.map(x=>join(x,'build/reproduced'))
 const identity=await comparePackages(...packages)
 await comparePackages(packages[0],resolve('build/castalia-wallet-v3-ci-contract'))
 const hashes={};for(const path of ['Cargo.lock','package-lock.json','.buildkite/canonical-tools.json'])hashes[path]=createHash('sha256').update(await readFile(path)).digest('hex')
 await writeFile('build/buildkite-verify/reproduction.json',JSON.stringify({schema:'castalia.wallet-reproduction.v1',commit,platform:'linux-x64',...identity,builds:dirs,lockAndToolHashes:hashes,comparison:'two clean independent source/target directories and delivered package'},null,2)+'\n')
}finally{await rm(work,{recursive:true,force:true})}
