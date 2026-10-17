import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const read = file => readFile(new URL(`../.buildkite/${file}`, import.meta.url), 'utf8')

function assertGenericManualGate(pipeline) {
  // Inspect the actual block prompt and field, so a comment cannot satisfy the gate.
  const block = pipeline.match(/^  - block:.*\n(?:(?:    |      |        ).*\n|\n)*/m)?.[0]
  assert.ok(block, 'manual block must exist')
  assert.match(block, /^    key: loaded-chrome-acceptance$/m)
  assert.match(block, /^    depends_on: portable-verify$/m)
  assert.match(block, /^    blocked_state: running$/m)
  const prompt = block.match(/^    prompt: >-\n((?:      [^\n]*\n)+)/m)?.[1].trim().replace(/\s+/g, ' ')
  assert.ok(prompt, 'manual block must contain an operator prompt')
  assert.match(prompt, /custody, registration, Files and provider-profile smokes against the SAME exact production artifact/)
  assert.match(prompt, /scripts\/smoke-extension-credential-presentation\.mts against that SAME exact artifact for generic v2 acceptance/)
  assert.match(prompt, /two independent applications, concurrent requests and worker restart/)
  assert.match(prompt, /All five smoke results are required/)
  assert.match(block, /^        key: chrome-generic-v2-evidence\n        required: true$/m)
  assert.doesNotMatch(block, /soft_fail:|skip:|if:|allow_dependency_failure:/)
}

test('Buildkite keeps hosted verification and loaded Chrome acceptance distinct', async () => {
  const pipeline = await read('pipeline.yml')
  assert.match(pipeline, /queue: linux-small/)
  assert.match(pipeline, /command: bash \.buildkite\/verify\.sh/)
  assert.match(pipeline, /depends_on: portable-verify/)
  assert.match(pipeline, /blocked_state: running/)
  assertGenericManualGate(pipeline)
  for (const path of ['build/castalia-wallet-browser-acceptance/**/*', 'build/castalia-wallet-browser-acceptance.contents.sha256', 'build/castalia-wallet-browser-acceptance.tar.gz', 'build/castalia-wallet-browser-acceptance.tar.gz.sha256']) assert.ok(pipeline.includes(path), path)
  for (const smoke of ['custody', 'registration', 'files', 'credential-presentation']) {
    const source = await readFile(new URL(`./smoke-extension-${smoke}.mts`, import.meta.url), 'utf8')
    assert.match(source, /process\.env\.CASTALIA_EXTENSION_DIRECTORY/)
  }
  assert.match(pipeline, /key: chrome-source-package\n\s+required: true/)
  assert.match(pipeline, /key: chrome-acceptance-evidence\n\s+required: true/)
  assert.doesNotMatch(pipeline, /soft_fail:|skip:|allow_dependency_failure:|plugins:/)
  const bootstrap = await read('bootstrap.sh')
  assert.match(bootstrap, /NODE_VERSION=20\.20\.0/)
  assert.match(bootstrap, /PYTHON_VERSION=3\.12\.15/)
  assert.match(bootstrap, /RUSTUP_TOOLCHAIN=1\.85\.1/)
  assert.match(bootstrap, /CARGO_BUILD_JOBS=2/)
  assert.match(bootstrap, /--component rustfmt --component clippy --target wasm32-unknown-unknown/)
  assert.match(bootstrap, /278a8d668085821f4d1a637bd864f1713f872b0ae3a118c77562a308c0abfe8d/)
  assert.ok(bootstrap.indexOf('278a8d668085821f4d1a637bd864f1713f872b0ae3a118c77562a308c0abfe8d') < bootstrap.indexOf('install -m 0755'))
  const runner = await read('checks.sh')
  for (const gate of [
    'npm ci --no-audit --no-fund', 'npm test', 'npm run typecheck', 'npm run build',
    'npm run validate:extension-package', 'scripts/verify-d0-contract.test.mjs',
    'cargo fmt --all -- --check', 'cargo test --locked --workspace --all-targets',
    'cargo clippy --locked --workspace --all-targets -- -D warnings',
    'python scripts/verify-custody-vector.py', 'git diff --exit-code',
  ]) assert.ok(runner.includes(gate), gate)
  assert.match(runner, /package:production-extension/)
  assert.match(runner, /inspect:production-extension/)
  assert.match(runner, /package:browser-acceptance-extension/)
  assert.match(runner, /acceptance-archive tar -C build -czf/)
  assert.ok(runner.indexOf('inspect:production-extension') < runner.indexOf('package:browser-acceptance-extension'))
  assert.doesNotMatch(runner, /export CASTALIA_PRESENTATION_TRUST|https:\/\/membership\.invalid/)
  assert.doesNotMatch(runner, /npm audit|smoke:extension-|git push|npm publish|run deploy/)
})

test('generic v2 manual acceptance cannot be replaced by a comment or optional field', async () => {
  const pipeline = await read('pipeline.yml')
  assert.throws(() => assertGenericManualGate(pipeline.replace(
    '      Also run scripts/smoke-extension-credential-presentation.mts against that SAME exact',
    '# Also run scripts/smoke-extension-credential-presentation.mts against that SAME exact',
  )), /must contain an operator prompt|scripts/)
  assert.throws(() => assertGenericManualGate(pipeline.replace(
    'key: chrome-generic-v2-evidence\n        required: true',
    'key: chrome-generic-v2-evidence\n        required: false',
  )))
  assert.throws(() => assertGenericManualGate(pipeline.replace(
    '    blocked_state: running', '    blocked_state: running\n    if: false',
  )))
})

test('checked-download helper rejects altered bytes before following commands execute', async () => {
  const source = await read('bootstrap.sh')
  const helper = source.match(/fetch_checked\(\) \{\n[\s\S]*?\n\}/)?.[0]
  assert.ok(helper)
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-buildkite-checksum-'))
  try {
    await mkdir(join(fixture, 'bin'))
    await writeFile(join(fixture, 'bin/curl'), `#!${process.execPath}
const fs = require('node:fs');
fs.writeFileSync(process.argv[process.argv.indexOf('--output') + 1], 'altered bytes');
`, { mode: 0o755 })
    // macOS ships a BSD sha256sum without --check; use its real SHA-256 checker.
    // Hosted Linux exercises the unmodified GNU command from the bootstrap.
    if (process.platform === 'darwin') {
      await writeFile(join(fixture, 'bin/sha256sum'), '#!/bin/sh\nexec /usr/bin/shasum -a 256 -c\n', { mode: 0o755 })
    }
    const digest = createHash('sha256').update('reviewed bytes').digest('hex')
    const result = spawnSync('bash', ['-c', `set -euo pipefail\n${helper}\nfetch_checked https://fixture.invalid artifact ${digest}\nprintf extracted > should-not-exist\n`], {
      cwd: fixture, encoding: 'utf8', env: { ...process.env, PATH: `${join(fixture, 'bin')}:${process.env.PATH}` },
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stdout + result.stderr, /FAILED|did NOT match/)
    await assert.rejects(readFile(join(fixture, 'should-not-exist')), { code: 'ENOENT' })
  } finally { await rm(fixture, { recursive: true, force: true }) }
})

test('portable runner fails at a failing gate and never packages later work', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-buildkite-runner-'))
  try {
    const bin = join(fixture, 'bin')
    await mkdir(bin)
    const script = join(fixture, 'checks.sh')
    await writeFile(script, await read('checks.sh'))
    const shim = `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const name = path.basename(process.argv[1]);
const args = process.argv.slice(2);
fs.appendFileSync(process.env.CASTALIA_TEST_COMMANDS, JSON.stringify([name, ...args]) + '\\n');
if (name === 'npm' && args[0] === 'test' && process.env.CASTALIA_TEST_FAIL === 'true') process.exit(19);
`
    for (const name of ['git', 'node', 'npm', 'rustc', 'cargo', 'wasm-pack', 'wasm-bindgen', 'wasm-opt', 'python', 'sha256sum', 'tar', 'bash']) {
      await writeFile(join(bin, name), shim, { mode: 0o755 })
    }
    const log = join(fixture, 'commands.jsonl')
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, CASTALIA_TEST_COMMANDS: log, CASTALIA_CANONICAL_BIN: bin }
    const failed = spawnSync('/bin/bash', [script], { cwd: fixture, encoding: 'utf8', env: { ...env, CASTALIA_TEST_FAIL: 'true' } })
    assert.equal(failed.status, 19, failed.stderr)
    let commands = (await readFile(log, 'utf8')).trim().split('\n').map(JSON.parse)
    assert.deepEqual(commands.at(-1), ['npm', 'test'])
    assert.ok(!commands.some(command => command.includes('package:production-extension')))
    await writeFile(log, '')
    const success = spawnSync('/bin/bash', [script], { cwd: fixture, encoding: 'utf8', env })
    assert.equal(success.status, 0, success.stderr)
    commands = (await readFile(log, 'utf8')).trim().split('\n').map(JSON.parse)
    assert.ok(commands.some(command => command.join(' ') === 'cargo test --locked --workspace --all-targets'))
    assert.ok(commands.some(command => command.join(' ') === 'cargo clippy --locked --workspace --all-targets -- -D warnings'))
    assert.ok(commands.findIndex(command => command.includes('package:production-extension')) < commands.findIndex(command => command.includes('inspect:production-extension')))
    assert.deepEqual(commands.at(-1), ['git', 'diff', '--exit-code'])
    assert.match(success.stdout, /Loaded Chrome custody acceptance remains a separate manual gate/)
  } finally { await rm(fixture, { recursive: true, force: true }) }
})
