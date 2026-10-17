import assert from 'node:assert/strict'
import {readFile,realpath} from 'node:fs/promises'
import {createHash} from 'node:crypto'
import {join} from 'node:path'
import {execFileSync} from 'node:child_process'
import {digestExtensionPackage} from './extension-package-digest.mjs'
export async function verifyTool(path,expected){assert.match(expected,/^[a-f0-9]{64}$/);assert.equal(createHash('sha256').update(await readFile(path)).digest('hex'),expected,'Canonical executable checksum mismatch: '+path)}
export async function comparePackages(a,b){const left=await digestExtensionPackage(a),right=await digestExtensionPackage(b);assert.deepEqual(left,right,'Complete canonical package trees differ');return left}
export function normalizedRustFlags(root,cargo,rustup){for(const path of [root,cargo,rustup])assert.ok(typeof path==='string'&&path.startsWith('/')&&!/\s/.test(path),'Canonical build paths must be absolute and contain no whitespace');return [`--remap-path-prefix=${root}=/castalia/wallet`,`--remap-path-prefix=${cargo}=/castalia/cargo`,`--remap-path-prefix=${rustup}=/castalia/rustup`].join(' ')}
export async function canonicalBuildEnvironment(root){
 if(process.env.BUILDKITE!=='true')return process.env
 assert.equal(process.platform,'linux');assert.equal(process.arch,'x64');assert.equal(process.version,'v20.20.0')
 const bin=await realpath(process.env.CASTALIA_CANONICAL_BIN??'')
 const pins=JSON.parse(await readFile(join(root,'.buildkite/canonical-tools.json'),'utf8'))
 for(const name of ['wasm-bindgen','wasm-opt']){
  const path=join(bin,name);await verifyTool(path,pins[name].executableSha256)
  const selected=execFileSync('which',[name],{encoding:'utf8',env:process.env}).trim();assert.equal(await realpath(selected),await realpath(path),'Uncontrolled '+name+' selection')
  const version=execFileSync(path,['--version'],{encoding:'utf8'});assert.ok(version.includes(pins[name].version))
 }
 assert.match(execFileSync('rustc',['--version'],{encoding:'utf8'}),/^rustc 1\.85\.1 /)
 assert.equal(execFileSync('wasm-pack',['--version'],{encoding:'utf8'}).trim(),'wasm-pack 0.14.0')
 const env={...process.env,RUSTFLAGS:normalizedRustFlags(await realpath(root),await realpath(process.env.CARGO_HOME),await realpath(process.env.RUSTUP_HOME)),CARGO_INCREMENTAL:'0',SOURCE_DATE_EPOCH:execFileSync('git',['show','-s','--format=%ct','HEAD'],{cwd:root,encoding:'utf8'}).trim()}
 delete env.CARGO_ENCODED_RUSTFLAGS
 return env
}
