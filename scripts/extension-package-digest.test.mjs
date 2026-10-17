import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, symlink, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import test from 'node:test'
import {
  digestExtensionPackage,
  verifyExtensionPackageDigest,
  writeExtensionPackageDigest,
} from './extension-package-digest.mjs'

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

test('content-tree digest binds every normalized path and byte without binding mtimes', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-extension-digest-'))
  const packageRoot = join(fixture, 'castalia-wallet-production')
  try {
    await mkdir(join(packageRoot, 'nested'), { recursive: true })
    await writeFile(join(packageRoot, 'manifest.json'), '{"manifest_version":3}\n')
    await writeFile(join(packageRoot, 'nested', 'worker.js'), 'export const ready = true\n')

    const manifestHash = sha256('{"manifest_version":3}\n')
    const workerHash = sha256('export const ready = true\n')
    const expectedTree = [
      `${manifestHash}  manifest.json\n`,
      `${workerHash}  nested/worker.js\n`,
    ].join('')
    const first = await digestExtensionPackage(packageRoot)
    assert.equal(first.fileCount, 2)
    assert.equal(first.digest, sha256(expectedTree))

    await utimes(join(packageRoot, 'manifest.json'), new Date(1_000), new Date(2_000))
    assert.equal((await digestExtensionPackage(packageRoot)).digest, first.digest)

    await writeFile(join(packageRoot, 'nested', 'worker.js'), 'export const ready = false\n')
    assert.notEqual((await digestExtensionPackage(packageRoot)).digest, first.digest)
  } finally {
    await rm(fixture, { recursive: true, force: true })
  }
})

test('sidecar verification fails closed on package mutation and malformed metadata', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-extension-sidecar-'))
  const packageRoot = join(fixture, 'castalia-wallet-production')
  const sidecar = `${packageRoot}.contents.sha256`
  try {
    await mkdir(packageRoot)
    await writeFile(join(packageRoot, 'manifest.json'), '{}\n')
    const written = await writeExtensionPackageDigest(packageRoot, sidecar)
    assert.equal(written.fileCount, 1)
    assert.equal(
      await readFile(sidecar, 'utf8'),
      `${written.digest}  ${basename(packageRoot)}\n`,
    )
    assert.deepEqual(await verifyExtensionPackageDigest(packageRoot, sidecar), written)

    await writeFile(join(packageRoot, 'manifest.json'), '{"changed":true}\n')
    await assert.rejects(
      () => verifyExtensionPackageDigest(packageRoot, sidecar),
      /content-tree digest mismatch/,
    )
    await writeFile(sidecar, 'not-a-digest\n')
    await assert.rejects(
      () => verifyExtensionPackageDigest(packageRoot, sidecar),
      /malformed extension package digest sidecar/,
    )
  } finally {
    await rm(fixture, { recursive: true, force: true })
  }
})

test('digest refuses symbolic links instead of following files outside the package', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-extension-symlink-'))
  const packageRoot = join(fixture, 'castalia-wallet-production')
  try {
    await mkdir(packageRoot)
    await writeFile(join(fixture, 'outside.txt'), 'private material\n')
    await symlink(join(fixture, 'outside.txt'), join(packageRoot, 'outside-link'))
    await assert.rejects(
      () => digestExtensionPackage(packageRoot),
      /unsupported symbolic link/,
    )
  } finally {
    await rm(fixture, { recursive: true, force: true })
  }
})
