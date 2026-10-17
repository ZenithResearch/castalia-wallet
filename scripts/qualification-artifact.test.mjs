import test from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp, mkdir, writeFile, readFile, rm} from 'node:fs/promises'
import {spawnSync} from 'node:child_process'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {tmpdir} from 'node:os'
import {writeExtensionPackageDigest} from './extension-package-digest.mjs'
const restore=fileURLToPath(new URL('./restore-qualification-archive.py',import.meta.url))
const check=fileURLToPath(new URL('./check-browser-artifact.mjs',import.meta.url))
test('qualification restore rejects altered archives, traversal, links, duplicate paths and oversized payloads',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'qualification-archive-'))
 try {
  const script=`import tarfile, io, hashlib, sys, pathlib
root=pathlib.Path(sys.argv[1])
for kind in ['valid','traversal','absolute','symlink','hardlink','duplicate','oversized']:
 p=root/(kind+'.tar')
 with tarfile.open(p,'w') as t:
  item=tarfile.TarInfo('../escape' if kind=='traversal' else '/escape' if kind=='absolute' else 'package/file')
  item.size=1
  if kind in ['symlink','hardlink']:
   item.type=tarfile.SYMTYPE if kind=='symlink' else tarfile.LNKTYPE
   item.linkname='../escape'
   item.size=0
  if kind=='oversized':
   item.size=129*1024*1024
   t.fileobj.write(item.tobuf())
  else:
   t.addfile(item,io.BytesIO(b'x'))
   if kind=='duplicate': t.addfile(item,io.BytesIO(b'x'))
 (root/(kind+'.sha')).write_text(hashlib.sha256(p.read_bytes()).hexdigest())
`
  const generated=spawnSync('python3',['-c',script,dir],{encoding:'utf8'});assert.equal(generated.status,0,generated.stderr)
  for(const kind of ['valid','traversal','absolute','symlink','hardlink','duplicate','oversized']){
   const result=spawnSync('python3',[restore,join(dir,kind+'.tar'),await readFile(join(dir,kind+'.sha'),'utf8'),join(dir,kind)],{encoding:'utf8'})
   if(kind==='valid'){assert.equal(result.status,0,result.stderr);assert.equal(await readFile(join(dir,kind,'package/file'),'utf8'),'x')}
   else assert.notEqual(result.status,0,kind)
  }
  const altered=spawnSync('python3',[restore,join(dir,'valid.tar'),'0'.repeat(64),join(dir,'altered')],{encoding:'utf8'});assert.notEqual(altered.status,0);assert.match(altered.stderr,/digest mismatch/)
  await assert.rejects(readFile(join(dir,'escape')))
 } finally {await rm(dir,{recursive:true,force:true})}
})
test('downloaded browser artifact must match its source, package sidecar and reproduction result',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'qualification-identity-')),root=join(dir,'package'),source='a'.repeat(40)
 try {
  await mkdir(root);await mkdir(join(dir,'build/buildkite-verify'),{recursive:true});await writeFile(join(root,'manifest.json'),'{}')
  const identity=await writeExtensionPackageDigest(root,root+'.contents.sha256')
  const provenance={sourceRevision:source,sourcePackageDigest:identity.digest,sourcePackageFileCount:identity.fileCount}
  await writeFile(root+'.provenance.json',JSON.stringify(provenance));await writeFile(join(dir,'build/buildkite-verify/reproduction.json'),JSON.stringify(identity))
  const run=revision=>spawnSync(process.execPath,[check,'b'.repeat(64)],{cwd:dir,encoding:'utf8',env:{...process.env,CASTALIA_EXTENSION_DIRECTORY:root,BUILDKITE_COMMIT:revision}})
  assert.equal(run(source).status,0)
  assert.notEqual(run('c'.repeat(40)).status,0,'wrong source revision')
  await writeFile(join(dir,'build/buildkite-verify/reproduction.json'),JSON.stringify({...identity,digest:'d'.repeat(64)}));assert.notEqual(run(source).status,0,'different reproduction')
  await writeFile(join(dir,'build/buildkite-verify/reproduction.json'),JSON.stringify(identity));await writeFile(join(root,'manifest.json'),'changed');assert.notEqual(run(source).status,0,'altered package')
 } finally {await rm(dir,{recursive:true,force:true})}
})
