import assert from 'node:assert/strict'
import {readFile,writeFile} from 'node:fs/promises'
import {verifyExtensionPackageDigest} from './extension-package-digest.mjs'
const root=process.env.CASTALIA_EXTENSION_DIRECTORY
const identity=await verifyExtensionPackageDigest(root,root+'.contents.sha256')
const provenance=JSON.parse(await readFile(root+'.provenance.json','utf8'))
assert.equal(provenance.sourceRevision,process.env.BUILDKITE_COMMIT)
assert.equal(provenance.sourcePackageDigest,identity.digest)
assert.equal(provenance.sourcePackageFileCount,identity.fileCount)
assert.equal(identity.digest,JSON.parse(await readFile('build/buildkite-verify/reproduction.json','utf8')).digest)
await writeFile('build/buildkite-verify/chrome-artifact.json',JSON.stringify({source:process.env.BUILDKITE_COMMIT,archiveSha256:process.argv[2],...identity,sourcePackage:'downloaded from this exact Buildkite job; no rebuild or mutation'},null,2)+'\n')
