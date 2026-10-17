import test from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,writeFile,rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {createHash} from 'node:crypto'
import {verifyTool,comparePackages,normalizedRustFlags} from './canonical-build.mjs'
test('canonical tools reject a different executable even with the right version',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'canonical-tools-'))
 try {const p=join(dir,'binding');await writeFile(p,'good');const sha=createHash('sha256').update('good').digest('hex');await verifyTool(p,sha);await writeFile(p,'bad');await assert.rejects(verifyTool(p,sha))}finally{await rm(dir,{recursive:true,force:true})}
})
test('complete trees reject changed, extra and missing files',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'canonical-trees-'))
 try {const {mkdir}=await import('node:fs/promises');const a=join(dir,'a'),b=join(dir,'b');await mkdir(a);await mkdir(b);await writeFile(join(a,'x'),'same');await writeFile(join(b,'x'),'same');await comparePackages(a,b);await writeFile(join(b,'x'),'different');await assert.rejects(comparePackages(a,b));await writeFile(join(b,'x'),'same');await writeFile(join(b,'extra'),'new');await assert.rejects(comparePackages(a,b));await rm(join(b,'extra'));await rm(join(b,'x'));await assert.rejects(comparePackages(a,b))}finally{await rm(dir,{recursive:true,force:true})}
})
test('different build paths map to stable logical source paths',()=>{
 const flags=normalizedRustFlags('/first/source','/tools/cargo','/tools/rustup');assert.match(flags,/--remap-path-prefix=\/first\/source=\/castalia\/wallet/);assert.match(flags,/\/tools\/cargo=\/castalia\/cargo/);assert.throws(()=>normalizedRustFlags('', '/cargo','/rust'))
})
