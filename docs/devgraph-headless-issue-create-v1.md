> Historical reference. The Wallet implementations described below were retired after `58d32a40559ffff0a9d99411f967b0889524c994`. See [the retirement boundary](wallet-application-adapter-retirement.md). These commands are not available in current Wallet packages. Historical bytes and evidence below are unchanged.

# Existing Dregg identity: headless Issue signing

The native `castalia-wallet-devgraph-issue-create-v1` binary is a separate,
owner-invoked Wallet custody adapter for exactly `devgraph.issue.create.v1`.
It loads an **existing Dregg raw 32-byte seed file**, verifies its Ed25519
public key against an explicit pin, and produces the unchanged
`secs-devgraph-issue-create-producer-input.v1` envelope. secS DG-E1 then
verifies the presentation and applies its installed exact-resource policy.

The Issue-signing path itself never generates an identity. The Ed25519 seed is the same identity material
Dregg uses; the v1 presentation verifies only its Ed25519 half. It does not
claim hybrid/PQ authorization or confer membership, permissions, or a login
session. Codex and Hermes using the same identity are the same authenticated
principal; their process names alone cannot provide cryptographic attribution.

## Configuration and use

For an explicitly new headless identity, `devgraph auth key create` invokes the
named Work Wallet helper's `--create-identity --key-file FILE` mode. Only Wallet
generates the OS-random 32-byte Dregg seed and atomically publishes it create-only
in a private mode-0600 file. This is file-based custody without encryption or
Keychain storage; it does not extract, replace, or reinterpret browser custody.
The returned public descriptor is
`{"schema":"devgraph.wallet-identity.v1","public_key":"<64 lowercase hex>","created":true}`.
The CLI verifies and persists only the reference/public pin. An existing key or
profile is never replaced by creation. No Work grant or membership is created.

`--inspect-identity --key-file FILE` returns the same public descriptor with
`created:false`, allowing recovery of the public pin after an interrupted setup.
Neither mode signs a request. The closed argument forms reject mixed flags,
unsafe paths, and broad permissions. If output/profile reporting fails after
key publication, preserve and inspect the key rather than generating another.

Devgraph now provides `devgraph auth setup --key-file PATH --public-key HEX` to
validate and save an existing identity reference for both named Work and this
legacy Issue command. Setup invokes the named Work Wallet binary's exclusive
`--check-identity` mode: Wallet verifies the existing raw seed and expected pin
without signing, generating a key, or writing an envelope. Success returns only
`{"ok":true,"identity_verified":true}`. The Devgraph profile stores the path and
public pin, never the seed. This adds no authority or wire-contract fields.

An agent's trusted environment loader can export these two settings from a
gitignored `.env`. An explicit complete pair overrides the saved Devgraph
profile; a partial pair is rejected. Neither CLI automatically sources `.env`.

```dotenv
DEVGRAPH_SIGNING_KEY_FILE=/absolute/path/to/the/existing/dregg-identity.key
DEVGRAPH_SIGNING_PUBLIC_KEY=<existing Ed25519 public key: 64 lowercase hex characters>
```

The first value is a file reference, not a private key. The second is public
and catches selection of the wrong identity. The key file must already exist;
missing files never trigger key generation. Only the raw 32-byte Dregg format
is accepted. Hex text, PEM, 64-byte keypair encodings, encrypted browser
records, `.castalia-recovery`, and `.castaway` are not silently reinterpreted.
Do not extract a browser-held seed to use this adapter. An identity held only
in encrypted Wallet custody requires a compatible custody adapter.

All paths passed to the native binary must be absolute, with no symlink path
components. Inputs must be regular, single-link, effective-user-owned files
without group/other permissions, special mode bits, or extended ACLs. The
output must be absent in a private directory. Ancestors must be owner/root
controlled; root sticky temporary directories are allowed. On macOS, mounts
with ownership disabled are rejected. Linux also rejects POSIX ACLs. macOS
execution is verified locally; Linux execution has not been verified locally.

```sh
cargo build --release --locked -p castalia-wallet-devgraph-cli

castalia-wallet-devgraph-issue-create-v1 \
  --request-file /absolute/private/request.json \
  --idempotency-key-file /absolute/private/idempotency-key.txt \
  --producer-input-output /absolute/private/producer-input.json
```

The Issue request follows the existing [v1 contract](devgraph-issue-create-v1.md).
The idempotency file is 16–128 allowed ASCII characters followed by exactly
one LF. Inputs are bounded and decoded before private key loading; duplicate
fields, unknown fields, null defaults, non-integer priorities, unsafe integers,
and invalid Unicode fail closed. Audience, operation, signature domain, and
60-second lifetime are fixed. Each invocation creates fresh random session and
nonce values. No generic byte-signing or clock/nonce/policy override exists.

Private seed buffers are zeroized on exit from custody. Only public signed
material is written through a held directory descriptor to an atomic,
create-new, mode-0600 output. Stdout/stderr contain fixed bounded JSON status
codes, never private bytes, caller paths, or request bodies.

## Devgraph integration

On the current macOS host, the operator installs the native executable as an
owner-controlled, non-group/world-writable, single-link regular executable at:

```text
~/Library/Application Support/Zenith/CastaliaWallet/bin/castalia-wallet-devgraph-issue-create-v1
```

The separate `secs-devgraph-issue-create-v1` binary must be installed at:

```text
~/Library/Application Support/Zenith/secS/bin/secs-devgraph-issue-create-v1
```

With both installed, Devgraph's `agent-issue-create-v1` command snapshots the
request/idempotency files, invokes Wallet with only the two signer settings,
invokes secS without those settings, and hands the signed projection and same
snapshot to its exact receiver. Devgraph never reads the private seed. No
browser profile, extension unlock, origin approval, or interactive popup is
used by this explicit headless command. Existing browser behavior is unchanged.

Installed secS policy, public trust registries, and receiver policy binding
must all authorize the selected actor and exact Issue resource at execution
time. A key path does not grant permission, and an expired grant still denies.
The adapter creates no generic Work API credential and enables no other Work
mutation. Reuse the same idempotency key when retrying an uncertain outcome;
a successful command reports the canonical receiver's Issue/receipt evidence.

## Compatibility and validation

There is no wire or persisted-data migration: existing browser presentations,
secS envelopes, signed projections, receiver policies, and encrypted Wallet
records retain their v1 contracts. The Rust signer reproduces the authoritative
three-repository vector byte for byte. The CLI integration tests independently
verify emitted signatures, identity reuse, fresh nonce/session values, strict
input rejection, file protections, and create-new outputs.

```sh
cargo test --workspace --all-targets --locked
cargo clippy -p castalia-wallet-devgraph-cli --all-targets -- -D warnings
npm test
npm run typecheck
```

These checks establish implementation evidence, not live permission activation
or a broader production custody review. Live acceptance additionally requires
the operator-selected existing identity and a current secS grant.
