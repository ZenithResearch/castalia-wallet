import { homedir } from 'node:os'
import { join } from 'node:path'

/** Rust panic/source metadata must not disclose the builder's filesystem. */
export function localBuildEnvironment(root, env = process.env, home = homedir()) {
  const inherited = env.CARGO_ENCODED_RUSTFLAGS === undefined
    ? (env.RUSTFLAGS ?? '').split(/\s+/).filter(Boolean)
    : env.CARGO_ENCODED_RUSTFLAGS.split('\x1f').filter(Boolean)
  // rustc uses the last matching prefix; the source root is most specific.
  const mappings = [[home, '/castalia/home'], [env.CARGO_HOME ?? join(home, '.cargo'), '/castalia/cargo'],
    [env.RUSTUP_HOME ?? join(home, '.rustup'), '/castalia/rustup'], [root, '/castalia/wallet']]
  const flags = [...inherited, ...mappings.map(([from, to]) => `--remap-path-prefix=${from}=${to}`)]
  const result = { ...env, CARGO_ENCODED_RUSTFLAGS: flags.join('\x1f') }
  delete result.RUSTFLAGS
  return result
}
