import { createHash } from 'node:crypto'

const EXPECTED_WORKFLOW_SHA256 = '36c397156bef41100cb3f75be43c02eb0a217de9bf666e16c943a8183c329f00'

function requireMatch(source, pattern, message) {
  const match = source.match(pattern)
  if (!match) throw new Error(message)
  return match
}

export function verifyWasmPackInstallDataflow(workflow) {
  const digest = createHash('sha256').update(workflow).digest('hex')
  if (digest !== EXPECTED_WORKFLOW_SHA256) {
    throw new Error(`unreviewed workflow bytes: ${digest}`)
  }
  const installerSteps = [
    ...workflow.matchAll(/^\s*- name: Install checksum-pinned wasm-pack release\s*$/gm),
  ]
  if (installerSteps.length !== 1) {
    throw new Error(`expected exactly one wasm-pack installer step, found ${installerSteps.length}`)
  }
  const cargoHomeReferences = workflow.match(/CARGO_HOME/g) ?? []
  const installedPathReferences = workflow.match(/bin\/wasm-pack/g) ?? []
  if (cargoHomeReferences.length !== 1 || installedPathReferences.length !== 1) {
    throw new Error(
      `expected one installed wasm-pack destination reference, found CARGO_HOME=${cargoHomeReferences.length} path=${installedPathReferences.length}`,
    )
  }
  const step = requireMatch(
    workflow,
    /- name: Install checksum-pinned wasm-pack release\n(?<body>[\s\S]*?)(?=\n\s*- name:)/,
    'missing checksum-pinned wasm-pack installer step',
  ).groups.body

  const run = requireMatch(
    step,
    /\n\s*run: \|\n(?<script>(?:\s{10}[^\n]+\n?)+)/,
    'missing wasm-pack installer script',
  ).groups.script
  const commands = run
    .split('\n')
    .filter(Boolean)
    .map((line) => line.trim())

  assertCommands(commands, [
    'archive="wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz"',
    'url="https://github.com/wasm-bindgen/wasm-pack/releases/download/v${WASM_PACK_VERSION}/${archive}"',
    'tmp="$(mktemp -d)"',
    'curl --fail --location --silent --show-error "$url" --output "$tmp/$archive"',
    'printf \'%s  %s\\n\' "$WASM_PACK_SHA256" "$tmp/$archive" | sha256sum --check',
    'tar --extract --gzip --file "$tmp/$archive" --directory "$tmp" --strip-components=1',
    'install -m 0755 "$tmp/wasm-pack" "$CARGO_HOME/bin/wasm-pack"',
    'wasm-pack --version',
  ])

  return true
}

function assertCommands(actual, expected) {
  if (actual.length !== expected.length) {
    throw new Error(`unexpected wasm-pack installer command count: ${actual.length}`)
  }
  for (const [index, command] of expected.entries()) {
    if (actual[index] !== command) {
      throw new Error(`invalid wasm-pack provenance command ${index + 1}`)
    }
  }
}
