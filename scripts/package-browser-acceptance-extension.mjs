#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { cp, lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { execFileSync } from 'node:child_process'
import { inspectProductionExtension } from './inspect-production-extension.mjs'
import { digestExtensionPackage, writeExtensionPackageDigest } from './extension-package-digest.mjs'

const hash = value => createHash('sha256').update(value).digest('hex')

function embeddedWasm(worker) {
  const matches = [...worker.matchAll(/atob\((['"])([A-Za-z0-9+/=]+)\1\)/g)]
  if (matches.length !== 1) throw new Error('expected exactly one embedded WASM module')
  const bytes = Buffer.from(matches[0][2], 'base64')
  if (bytes.length < 8 || !bytes.subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]))) {
    throw new Error('invalid embedded WASM module')
  }
  return { bytes: bytes.length, sha256: hash(bytes) }
}

async function files(root, prefix = '') {
  const result = []
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const path = join(prefix, entry.name)
    if (entry.isDirectory()) result.push(...await files(root, path))
    else result.push(path)
  }
  return result
}

async function requireAbsent(path) {
  try { await lstat(path) } catch (error) {
    if (error.code === 'ENOENT') return
    throw error
  }
  throw new Error(`output already exists: ${path}`)
}

export async function createBrowserAcceptancePackage({ sourceRoot, sourceSidecar, outputRoot, sourceRevision }) {
  if (!/^[0-9a-f]{40}$/.test(sourceRevision)) throw new Error('browser acceptance requires an exact source commit')
  const source = resolve(sourceRoot), output = resolve(outputRoot)
  const nested = (parent, child) => {
    const path = relative(parent, child)
    return path === '' || (!path.startsWith(`..${sep}`) && path !== '..' && !path.startsWith(sep))
  }
  if (nested(source, output) || nested(output, source)) throw new Error('fixture output must be separate from the CI package')
  await requireAbsent(output)
  await requireAbsent(`${output}.contents.sha256`)
  await requireAbsent(`${output}.provenance.json`)
  const inspected = await inspectProductionExtension(source, sourceSidecar)
  const workerPath = join(source, 'dist/service-worker.js')
  const originalWorker = await readFile(workerPath, 'utf8')
  const wasm = embeddedWasm(originalWorker)
  const metadata = {schema:'castalia.wallet-browser-acceptance.v2',sourceRevision,sourcePackageDigest:inspected.digest,sourcePackageFileCount:inspected.fileCount,workerSha256:hash(originalWorker),embeddedWasm:wasm,transformations:[]}
  await mkdir(dirname(output), { recursive: true })
  await mkdir(output)
  try {
    for (const name of await readdir(source)) {
      await cp(join(source, name), join(output, name), { recursive: true, force: false, errorOnExist: true })
    }
    for (const path of await files(source)) if (!(await readFile(join(source,path))).equals(await readFile(join(output,path)))) throw new Error(`Acceptance copy changed package bytes: ${path}`)
    if ((await digestExtensionPackage(source)).digest !== inspected.digest) throw new Error('source package changed during acceptance copying')
    const result = await writeExtensionPackageDigest(output, `${output}.contents.sha256`)
    if(result.digest !== inspected.digest) throw new Error('Acceptance package must exactly match production package')
    await writeFile(`${output}.provenance.json`, `${JSON.stringify(metadata,null,2)}\n`, {flag:'wx'})
    return result
  } catch (error) {
    await rm(output, { recursive: true, force: true })
    await rm(`${output}.contents.sha256`, { force: true })
    throw error
  }
}

const invoked = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : ''
if (invoked === import.meta.url) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  const sourceRoot = resolve(root, process.argv[2] ?? 'build/castalia-wallet-v3-ci-contract')
  const outputRoot = resolve(root, process.argv[3] ?? 'build/castalia-wallet-browser-acceptance')
  if (execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: root, encoding: 'utf8' }).trim()) throw new Error('browser acceptance requires a clean source checkout')
  const sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
  if (process.env.BUILDKITE_COMMIT && process.env.BUILDKITE_COMMIT !== sourceRevision) throw new Error('fixture source does not match Buildkite commit')
  const result = await createBrowserAcceptancePackage({ sourceRoot, sourceSidecar: `${sourceRoot}.contents.sha256`, outputRoot, sourceRevision })
  console.log(JSON.stringify({ sourceRevision, outputRoot, ...result }))
}
