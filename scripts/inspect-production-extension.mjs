#!/usr/bin/env node
import { readFile, readdir } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import process from 'node:process'
import { verifyFilesystemNotices } from './filesystem-license-notices.mjs'
import { verifyExtensionPackageDigest } from './extension-package-digest.mjs'

const LOOPBACK_ENDPOINT = /http:\/\/(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?/i

// Scan the module bytes, not random words formed by their base64 encoding.
// Only validated WASM literals are decoded; other executable text stays visible.
function decodedExecutableText(bytes, path) {
  return bytes.toString('utf8').replace(/atob\((['"])([A-Za-z0-9+/=]+)\1\)/g, (literal, _quote, encoded) => {
    const moduleBytes = Buffer.from(encoded, 'base64')
    if (!moduleBytes.subarray(0, 4).equals(Buffer.from([0, 97, 115, 109]))) return literal
    try { new WebAssembly.Module(moduleBytes) } catch {
      throw new Error(`invalid embedded WASM in production extension: ${path}`)
    }
    return moduleBytes.toString('utf8')
  })
}

async function packageFiles(directory) {
  const files = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await packageFiles(path))
    else if (entry.isFile()) files.push(path)
  }
  return files
}

async function readJson(path, label) {
  try {
    return JSON.parse(await readFile(path, 'utf8'))
  } catch (error) {
    throw new Error(`invalid production ${label}: ${error.message}`)
  }
}

export async function inspectProductionExtension(packageRoot, sidecarPath) {
  const root = resolve(packageRoot)
  const manifest = await readJson(join(root, 'manifest.json'), 'manifest')
  const config = await readJson(join(root, 'provider-configuration.json'), 'provider configuration')

  if (
    manifest.manifest_version !== 3 ||
    !Array.isArray(manifest.host_permissions) ||
    manifest.host_permissions.length !== 0 ||
    JSON.stringify(manifest.optional_host_permissions) !== JSON.stringify(['https://*/*'])
  ) {
    throw new Error('production extension host permissions must be optional and have no pregrants')
  }
  if (
    manifest.background?.service_worker !== 'dist/service-worker.js' ||
    manifest.background?.type !== 'module'
  ) {
    throw new Error('production extension must use the reviewed module service worker')
  }
  if (JSON.stringify(Object.keys(config).sort()) !== JSON.stringify(['defaultProfiles','schema','trustSource']) || config.schema !== 'castalia.wallet-runtime-trust.v1' || config.trustSource !== 'wallet-settings' || !Array.isArray(config.defaultProfiles) || config.defaultProfiles.length !== 0) throw new Error('production package must have zero pretrusted provider profiles')

  for (const path of await packageFiles(root)) {
    const bytes = await readFile(path)
    if (/\.(?:js|wasm)$/.test(path) && /\/Users\//.test(decodedExecutableText(bytes, path))) {
      throw new Error(`production extension contains a private build path: ${path}`)
    }
    if (/devgraph|kanban|arena/i.test(path.slice(root.length)) || /\.(?:js|wasm|html)$/.test(path) && /devgraph|kanban|arena|connectNative|nativeMessaging/i.test(decodedExecutableText(bytes, path))) {
      throw new Error(`production extension contains an application adapter: ${path}`)
    }
    if (LOOPBACK_ENDPOINT.test(bytes.toString('utf8'))) {
      throw new Error(`production extension contains a loopback membership issuer: ${path}`)
    }
  }

  await verifyFilesystemNotices(root)
  const result = await verifyExtensionPackageDigest(root, sidecarPath)
  if (result.fileCount === 0) throw new Error('production extension package is empty')
  return result
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : ''
if (invokedPath === import.meta.url) {
  const scriptDir = dirname(fileURLToPath(import.meta.url))
  const repoRoot = resolve(scriptDir, '..')
  const packageRoot = resolve(
    repoRoot,
    process.env.CASTALIA_EXTENSION_OUTPUT ?? 'build/castalia-wallet-production',
  )
  const sidecarPath = `${packageRoot}.contents.sha256`
  const result = await inspectProductionExtension(packageRoot, sidecarPath)
  console.log(`Production extension inspection passed: ${result.fileCount} files`)
  console.log(`Content-tree SHA-256: ${result.digest}`)
}
