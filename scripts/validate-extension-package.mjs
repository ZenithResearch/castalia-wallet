#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const repoRoot = process.cwd()
const extensionRoot = path.join(repoRoot, 'apps/chrome-extension')
const manifestPath = path.join(extensionRoot, 'manifest.json')
const sourceRoot = path.join(extensionRoot, 'src')

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
const errors = []

validateManifestReferences()
validateNoTrackedRuntimeArtifacts()
validateChromeApiPermissions()

if (errors.length > 0) {
  for (const error of errors) {
    console.error(`ERROR: ${error}`)
  }
  process.exit(1)
}

console.log('Castalia extension package/source and manifest/API validation passed.')

function validateManifestReferences() {
  const references = new Set()

  if (manifest.background?.service_worker) {
    references.add(manifest.background.service_worker)
  }

  for (const script of manifest.content_scripts ?? []) {
    for (const js of script.js ?? []) references.add(js)
    for (const css of script.css ?? []) references.add(css)
  }

  if (manifest.action?.default_popup) {
    references.add(manifest.action.default_popup)
  }

  for (const icon of Object.values(manifest.icons ?? {})) {
    references.add(icon)
  }

  const actionIcons = manifest.action?.default_icon
  if (typeof actionIcons === 'string') {
    references.add(actionIcons)
  } else {
    for (const icon of Object.values(actionIcons ?? {})) references.add(icon)
  }

  for (const resourceBlock of manifest.web_accessible_resources ?? []) {
    for (const resource of resourceBlock.resources ?? []) references.add(resource)
  }

  for (const reference of references) {
    if (!referenceExists(reference)) {
      errors.push(`manifest references missing source/build path: ${reference}`)
    }
  }
}

function referenceExists(reference) {
  const direct = path.join(extensionRoot, reference)
  if (fs.existsSync(direct)) return true

  const mappedSource = sourcePathForManifestReference(reference)
  if (mappedSource && fs.existsSync(mappedSource)) return true

  return false
}

function sourcePathForManifestReference(reference) {
  if (reference.startsWith('dist/') && reference.endsWith('.js')) {
    const base = path.basename(reference, '.js')
    return path.join(sourceRoot, `${base}.ts`)
  }

  return null
}

function validateNoTrackedRuntimeArtifacts() {
  let tracked = ''
  try {
    tracked = execFileSync('git', ['ls-files'], { cwd: repoRoot, encoding: 'utf8' })
  } catch (error) {
    errors.push(`could not inspect tracked files with git ls-files: ${error.message}`)
    return
  }

  const forbidden = [
    /^apps\/chrome-extension\/dist\//,
    /^apps\/chrome-extension\/build\//,
    /^apps\/chrome-extension\/profile\//,
    /^apps\/chrome-extension\/\.chrome-profile\//,
    /\.crx$/,
    /\.pem$/,
    /\.zip$/,
  ]

  for (const file of tracked.split('\n').filter(Boolean)) {
    if (forbidden.some((pattern) => pattern.test(file))) {
      errors.push(`runtime/generated extension artifact is tracked: ${file}`)
    }
  }
}

function validateChromeApiPermissions() {
  const permissions = new Set(manifest.permissions ?? [])
  const sourceFiles = collectFiles(sourceRoot, '.ts')
  const requiredPermissions = {
    alarms: 'alarms',
    sidePanel: 'sidePanel',
    storage: 'storage',
    tabs: 'tabs',
    windows: 'windows',
    webNavigation: 'webNavigation',
  }
  const permissionlessApis = new Set([
    // MV3 extension runtime/message APIs do not require declaring a separate permission.
    'runtime',
    // Requests only optional origins from a user gesture; no separate permissions permission.
    'permissions',
    // Used by action popups through manifest.action; no permission key needed for basic popup behavior.
    'action',
  ])

  for (const file of sourceFiles) {
    const text = fs.readFileSync(file, 'utf8')
    if (/\bchrome\.runtime\.connectNative\b/.test(text) && !permissions.has('nativeMessaging')) {
      errors.push(`native messaging is not authorized for ${relative(file)}`)
    }
    const matches = text.matchAll(/\bchrome\.([A-Za-z_][A-Za-z0-9_]*)\b/g)
    for (const match of matches) {
      const api = match[1]
      if (permissionlessApis.has(api)) continue
      const required = requiredPermissions[api]
      if (!required) {
        errors.push(`chrome.${api} is used in ${relative(file)} but is not allowlisted by validation script`)
        continue
      }
      if (!permissions.has(required)) {
        errors.push(`chrome.${api} is used in ${relative(file)} but manifest permissions lacks "${required}"`)
      }
    }
  }
}

function collectFiles(root, extension) {
  if (!fs.existsSync(root)) return []
  const files = []
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name)
    if (entry.isDirectory()) {
      files.push(...collectFiles(fullPath, extension))
    } else if (entry.isFile() && fullPath.endsWith(extension)) {
      files.push(fullPath)
    }
  }
  return files
}

function relative(file) {
  return path.relative(repoRoot, file)
}
