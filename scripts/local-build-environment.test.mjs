import assert from 'node:assert/strict'
import test from 'node:test'
import { localBuildEnvironment } from './local-build-environment.mjs'

test('local WASM builds remap home, custom tool homes and source paths including spaces', () => {
 const env = localBuildEnvironment('/fixture home/wallet source', { RUSTFLAGS: '-C opt-level=z', CARGO_HOME: '/tools/cargo', RUSTUP_HOME: '/tools/rust' }, '/fixture home')
 assert.equal(env.RUSTFLAGS, undefined)
 assert.deepEqual(env.CARGO_ENCODED_RUSTFLAGS.split('\x1f'), ['-C', 'opt-level=z', '--remap-path-prefix=/fixture home=/castalia/home', '--remap-path-prefix=/tools/cargo=/castalia/cargo', '--remap-path-prefix=/tools/rust=/castalia/rustup', '--remap-path-prefix=/fixture home/wallet source=/castalia/wallet'])
})
test('encoded flags retain precedence and the caller environment is unchanged', () => {
 const original = { RUSTFLAGS: 'ignored', CARGO_ENCODED_RUSTFLAGS: '-C\x1fdebuginfo=0' }
 assert.ok(localBuildEnvironment('/fixture/source', original, '/fixture/home').CARGO_ENCODED_RUSTFLAGS.startsWith('-C\x1fdebuginfo=0\x1f'))
 assert.equal(original.RUSTFLAGS, 'ignored')
})
