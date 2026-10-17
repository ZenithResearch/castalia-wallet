import assert from 'node:assert/strict'
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { verifyWasmPackInstallDataflow } from './verify-wasm-pack-install.mjs'

const workflowUrl = new URL('../.github/workflows/verify.yml', import.meta.url)
const productionWorkflowUrl = new URL('../.github/workflows/package-production.yml', import.meta.url)

async function workflow() {
  return readFile(workflowUrl, 'utf8')
}

test('pull-request verification is fail-closed and immutable', async () => {
  const source = await workflow()
  assert.match(source, /pull_request:/)
  assert.match(source, /branches:\s*\[main\]/)
  assert.match(source, /permissions:\s*\n\s*contents:\s*read/)
  assert.doesNotMatch(source, /uses:\s*[^\s]+@(v\d+|main|master)\b/)
  for (const required of [
    'npm ci',
    'npm test',
    'npm run typecheck',
    'npm run build',
    'npm run validate:extension-package',
    'npm run package:production-extension',
    'npm run inspect:production-extension',
    'cargo fmt --all -- --check',
    'cargo test --locked --workspace --all-targets',
    'cargo clippy --locked --workspace --all-targets -- -D warnings',
    'scripts/verify-d0-contract.test.mjs',
    'scripts/verify-custody-vector.py',
  ]) assert.match(source, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
})

test('production packaging is manual, environment-bound, and uploads only an inspected v3 package', async () => {
  const source = await readFile(productionWorkflowUrl, 'utf8')
  assert.match(source, /workflow_dispatch:/)
  assert.match(source, /environment:\s*production/)
  assert.doesNotMatch(source, /uses:\s*[^\s]+@(v\d+|main|master)\b/)
  for (const required of [
    'npm run package:production-extension',
    'npm run inspect:production-extension',
    'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
    'build/castalia-wallet-production.contents.sha256',
    'if-no-files-found: error',
  ]) assert.match(source, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.ok(
    source.indexOf('npm run inspect:production-extension')
      < source.indexOf('actions/upload-artifact@'),
    'inspection must complete before the production package can be uploaded',
  )
})

test('toolchains are explicit and browser smoke remains a named external gate', async () => {
  const source = await workflow()
  assert.match(source, /node-version:\s*['"]20\.20\.0['"]/)
  assert.match(source, /python-version:\s*['"]3\.12['"]/)
  assert.match(source, /RUST_TOOLCHAIN:\s*['"]1\.85\.1['"]/)
  assert.match(source, /WASM_PACK_VERSION:\s*['"]0\.14\.0['"]/)
  assert.match(
    source,
    /WASM_PACK_SHA256:\s*['"]278a8d668085821f4d1a637bd864f1713f872b0ae3a118c77562a308c0abfe8d['"]/,
  )
  assert.match(
    source,
    /archive="wasm-pack-v\$\{WASM_PACK_VERSION\}-x86_64-unknown-linux-musl\.tar\.gz"/,
  )
  assert.match(
    source,
    /https:\/\/github\.com\/wasm-bindgen\/wasm-pack\/releases\/download\/v\$\{WASM_PACK_VERSION\}\/\$\{archive\}/,
  )
  assert.match(source, /sha256sum --check/)
  assert.doesNotThrow(() => verifyWasmPackInstallDataflow(source))
  for (const mutation of [
    source.replace('"$tmp/$archive" | sha256sum --check', '"$tmp/decoy.tar.gz" | sha256sum --check'),
    source.replace('tar --extract --gzip --file "$tmp/$archive"', 'tar --extract --gzip --file "$tmp/decoy.tar.gz"'),
    source.replace('install -m 0755 "$tmp/wasm-pack"', 'install -m 0755 "$tmp/unverified/wasm-pack"'),
    source.replace('          tar --extract', '          archive="decoy.tar.gz"\n          tar --extract'),
    source.replace('          tar --extract', '          printf unverified > "$tmp/$archive"\n          tar --extract'),
    source.replace('          install -m 0755', '          printf unverified > "$tmp/wasm-pack"\n          install -m 0755'),
    `${source}\n  duplicate-installer:\n    steps:\n      - name: Install checksum-pinned wasm-pack release\n        run: printf hostile > "$CARGO_HOME/bin/wasm-pack"\n`,
    `${source}\n  overwrite-verified-tool:\n    steps:\n      - name: Prepare later tools\n        run: printf hostile > "$CARGO_HOME/bin/wasm-pack"\n`,
    `${source}\n  overwrite-braced-tool:\n    steps:\n      - name: Prepare later tools\n        shell: bash\n        run: |\n          printf '#!/bin/sh\\nprintf hostile >&2\\nexit 0\\n' > "\${CARGO_HOME}/bin/wasm-pack"\n          chmod +x "\${CARGO_HOME}/bin/wasm-pack"\n`,
    source.replace(
      '      - name: Verify CI policy contract',
      `      - name: Replace installed tool via PATH resolution\n        shell: bash\n        run: |\n          tool="$(command -v wasm-pack)"\n          printf '#!/bin/sh\\nprintf hostile >&2\\nexit 0\\n' > "$tool"\n          chmod +x "$tool"\n          wasm-pack --version\n\n      - name: Verify CI policy contract`,
    ),
  ]) {
    assert.throws(() => verifyWasmPackInstallDataflow(mutation))
  }
  assert.doesNotMatch(source, /cargo install wasm-pack/)
  assert.ok(
    source.indexOf('sha256sum --check') < source.indexOf('run: npm test'),
    'the pinned wasm-pack archive must be verified before Node tests build extension WASM',
  )
  assert.match(source, /Loaded-browser custody smoke/)
  assert.match(source, /not executed on hosted CI/i)
  assert.doesNotMatch(source, /^\s*run:\s*npm run smoke:extension-custody\s*$/m)
})

test('WASM build failures behaviorally preserve the underlying spawn diagnostic', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-wasm-spawn-'))
  try {
    await mkdir(join(fixture, 'scripts'), { recursive: true })
    await mkdir(join(fixture, 'apps/chrome-extension/src'), { recursive: true })
    await cp(
      new URL('./build-castalia-wallet-wasm.mjs', import.meta.url),
      join(fixture, 'scripts/build-castalia-wallet-wasm.mjs'),
    )
    const bin = join(fixture, 'bin')
    await mkdir(bin)
    const cargoMissing = spawnSync(process.execPath, ['scripts/build-castalia-wallet-wasm.mjs'], {
      cwd: fixture, env: { ...process.env, BUILDKITE: '', PATH: bin }, encoding: 'utf8',
    })
    assert.notEqual(cargoMissing.status, 0)
    assert.match(cargoMissing.stderr, /failed to run cargo metadata:.*ENOENT/)
    await writeFile(join(bin, 'cargo'), `#!${process.execPath}\nprocess.exit(0)\n`, { mode: 0o755 })
    const result = spawnSync(process.execPath, ['scripts/build-castalia-wallet-wasm.mjs'], {
      cwd: fixture,
      env: { ...process.env, BUILDKITE: '', PATH: bin },
      encoding: 'utf8',
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /failed to run wasm-pack:.*ENOENT/)
  } finally {
    await rm(fixture, { recursive: true, force: true })
  }
})

test('the actual WASM builder rejects missing and stale Cargo locks without repairing them', async t => {
  for (const state of ['missing', 'stale']) {
    await t.test(state, async () => {
      const fixture = await mkdtemp(join(tmpdir(), 'castalia-wasm-lock-'))
      try {
        await mkdir(join(fixture, 'scripts'), { recursive: true })
        const crate = join(fixture, 'crates/castalia-wallet-core')
        await mkdir(join(crate, 'src'), { recursive: true })
        await cp(new URL('./build-castalia-wallet-wasm.mjs', import.meta.url),
          join(fixture, 'scripts/build-castalia-wallet-wasm.mjs'))
        await writeFile(join(fixture, 'Cargo.toml'), '[workspace]\nmembers = ["crates/castalia-wallet-core"]\nresolver = "2"\n')
        const manifest = '[package]\nname = "locked-wallet-fixture"\nversion = "0.1.0"\nedition = "2021"\n[lib]\ncrate-type = ["cdylib"]\n'
        await writeFile(join(crate, 'Cargo.toml'), manifest)
        await writeFile(join(crate, 'src/lib.rs'), 'pub fn fixture() {}\n')
        const env = { ...process.env, BUILDKITE: '', CARGO_NET_OFFLINE: 'true', CARGO_TARGET_DIR: join(fixture, 'target') }
        let previousLock
        if (state === 'stale') {
          const generated = spawnSync('cargo', ['generate-lockfile', '--offline'], { cwd: fixture, env, encoding: 'utf8' })
          assert.equal(generated.status, 0, generated.error?.message ?? generated.stderr)
          previousLock = await readFile(join(fixture, 'Cargo.lock'))
          await writeFile(join(crate, 'Cargo.toml'), manifest.replace('0.1.0', '0.2.0'))
        }
        const result = spawnSync(process.execPath, ['scripts/build-castalia-wallet-wasm.mjs'], {
          cwd: fixture, env, encoding: 'utf8',
        })
        assert.notEqual(result.status, 0)
        assert.match(result.stderr, /(?:lock file.*needs to be updated|cannot (?:create|update) the lock file)[\s\S]*--locked/)
        if (state === 'missing') await assert.rejects(readFile(join(fixture, 'Cargo.lock')), { code: 'ENOENT' })
        else assert.deepEqual(await readFile(join(fixture, 'Cargo.lock')), previousLock)
        await assert.rejects(readFile(join(fixture, 'apps/chrome-extension/src/generated/castalia-wallet-core/wasm-bytes.js')), { code: 'ENOENT' })
      } finally {
        await rm(fixture, { recursive: true, force: true })
      }
    })
  }
})

test('the WASM builder checks locked metadata before passing the lock requirement to compilation', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'castalia-wasm-commands-'))
  try {
    await mkdir(join(fixture, 'scripts'), { recursive: true })
    await cp(new URL('./build-castalia-wallet-wasm.mjs', import.meta.url), join(fixture, 'scripts/build-castalia-wallet-wasm.mjs'))
    const bin = join(fixture, 'bin')
    await mkdir(bin)
    const shim = `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const command = path.basename(process.argv[1]);
fs.appendFileSync(path.join(process.cwd(), 'commands.jsonl'), JSON.stringify({ command, args: process.argv.slice(2) }) + '\\n');
if (command === 'wasm-pack') {
  const out = process.argv[process.argv.indexOf('--out-dir') + 1];
  fs.writeFileSync(path.join(out, 'castalia_wallet_core_bg.wasm'), Buffer.from([0, 97, 115, 109]));
  fs.writeFileSync(path.join(out, 'castalia_wallet_core.js'), 'export class WasmWallet {}\\n');
}
`
    for (const command of ['cargo', 'wasm-pack']) await writeFile(join(bin, command), shim, { mode: 0o755 })
    const result = spawnSync(process.execPath, ['scripts/build-castalia-wallet-wasm.mjs'], {
      cwd: fixture, env: { ...process.env, BUILDKITE: '', PATH: bin }, encoding: 'utf8',
    })
    assert.equal(result.status, 0, result.stderr)
    const commands = (await readFile(join(fixture, 'commands.jsonl'), 'utf8')).trim().split('\n').map(line => JSON.parse(line))
    assert.deepEqual(commands.map(({ command }) => command), ['cargo', 'wasm-pack'])
    assert.deepEqual(commands[0].args, ['metadata', '--locked', '--format-version', '1'])
    assert.deepEqual(commands[1].args.slice(-2), ['--', '--locked'])
    assert.match(await readFile(join(fixture, 'apps/chrome-extension/src/generated/castalia-wallet-core/wasm-bytes.js'), 'utf8'), /CASTALIA_WALLET_CORE_WASM/)
  } finally {
    await rm(fixture, { recursive: true, force: true })
  }
})
