import { createHash } from 'node:crypto'
import { lstat, readFile, readdir, writeFile } from 'node:fs/promises'
import { basename, join, resolve } from 'node:path'

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function compareUtf8Names(left, right) {
  return Buffer.compare(Buffer.from(left.name, 'utf8'), Buffer.from(right.name, 'utf8'))
}

async function collectEntries(directory, prefix = '') {
  const entries = (await readdir(directory, { withFileTypes: true })).sort(compareUtf8Names)
  const files = []
  for (const entry of entries) {
    const absolutePath = join(directory, entry.name)
    const relativePath = prefix === '' ? entry.name : `${prefix}/${entry.name}`
    if (entry.isSymbolicLink()) {
      throw new Error(`unsupported symbolic link in extension package: ${relativePath}`)
    }
    if (entry.isDirectory()) {
      files.push(...await collectEntries(absolutePath, relativePath))
      continue
    }
    if (!entry.isFile()) {
      throw new Error(`unsupported non-file entry in extension package: ${relativePath}`)
    }
    const bytes = await readFile(absolutePath)
    files.push({ path: relativePath, sha256: sha256(bytes) })
  }
  return files
}

export async function digestExtensionPackage(packageRoot) {
  const root = resolve(packageRoot)
  const rootStat = await lstat(root)
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error('extension package root must be a real directory')
  }
  const entries = await collectEntries(root)
  const tree = entries.map((entry) => `${entry.sha256}  ${entry.path}\n`).join('')
  return { digest: sha256(tree), fileCount: entries.length }
}

export async function writeExtensionPackageDigest(packageRoot, sidecarPath) {
  const result = await digestExtensionPackage(packageRoot)
  await writeFile(
    sidecarPath,
    `${result.digest}  ${basename(resolve(packageRoot))}\n`,
    { mode: 0o644 },
  )
  return result
}

export async function verifyExtensionPackageDigest(packageRoot, sidecarPath) {
  const sidecar = await readFile(sidecarPath, 'utf8')
  const match = /^([0-9a-f]{64})  ([^\r\n]+)\n$/.exec(sidecar)
  if (!match || match[2] !== basename(resolve(packageRoot))) {
    throw new Error('malformed extension package digest sidecar')
  }
  const result = await digestExtensionPackage(packageRoot)
  if (result.digest !== match[1]) {
    throw new Error('extension package content-tree digest mismatch')
  }
  return result
}
