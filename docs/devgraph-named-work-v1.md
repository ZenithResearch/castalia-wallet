> Historical reference. The Wallet implementations described below were retired after `58d32a40559ffff0a9d99411f967b0889524c994`. See [the retirement boundary](wallet-application-adapter-retirement.md). These commands are not available in current Wallet packages. Historical bytes and evidence below are unchanged.

# Headless named Work signing

The `castalia-wallet-devgraph-work-v1` binary signs the separate closed
`devgraph.work-request.v1` contract for Devgraph. It supports create, patch,
status, archive, accept, convert, parent.set, dependency.add/remove, and
blocker.add/remove. This source addition does not activate a production grant.
The original `castalia-wallet-devgraph-issue-create-v1` remains unchanged.

The explicit raw-file custody profile also provides owner-invoked recovery:

```text
castalia-wallet-devgraph-work-v1 --export-identity --output-file /absolute/private/new-recovery.key
castalia-wallet-devgraph-work-v1 --inspect-identity --key-file /absolute/private/new-recovery.key
```

Export validates the configured key/public pin, copies the same seed entirely
inside native Wallet, and publishes an owner-private 0600 file atomically without
overwriting anything. The parent directory must be private and every ancestor
must be safe. A root:wheel mounted-volume ancestor may be group-writable only
when the calling user is outside wheel, mount ownership is enforced, and the
held descriptor is proven to identify that mount root. The exception never
applies to private leaf directories or signing files.

The export descriptor contains only schema, public key, `exported=true`, and
`application_encrypted=false`. This is a raw recovery copy of the headless file
profile, not an encrypted `.castalia-recovery` or `.castaway` container. It does
not alter extension custody, membership or grants. Seed buffers zeroize on
drop; no seed is returned on stdout/stderr. Deleting one copy does not revoke
the others. The recovery orchestrator separately preserves secS authority and
replay state and keeps restored permissions inactive pending operator review.

The operator supplies the existing Dregg Ed25519 seed through
`DEVGRAPH_SIGNING_KEY_FILE` and pins its public key with
`DEVGRAPH_SIGNING_PUBLIC_KEY`. The seed file must contain exactly 32 raw bytes;
the pin is 64 lowercase hexadecimal characters. This creates no identity and
does not reinterpret membership, encrypted recovery containers, or hybrid/PQ
keys. Only the native Wallet process opens the seed. A trusted launcher can
export these variables; the binary never sources `.env`.

```text
castalia-wallet-devgraph-work-v1 \
  --request-file /absolute/private/request.json \
  --idempotency-key-file /absolute/private/idempotency.txt \
  --producer-input-output /absolute/private/new-producer-input.json
```

All files and directories are descriptor-validated. Requests and idempotency
files are bounded owner-private regular files; output is create-only. The key
file uses the same private custody helper as the existing Issue signer. Neither
raw input nor key material is echoed in errors.

The request has mandatory `schema`, `operation`, `kind`, `id`,
`expected_version`, and `payload` fields. Create uses null expected_version;
other operations require the exact positive current version. Parent and edge
references also carry versions. The parser independently derives all affected
resources, including both parents during reparenting and the acceptance
Decision during Proposal conversion. No caller-supplied resource list is trusted.
The shared `tests/fixtures/named-work-v1/requests.json` vectors cover all eleven
commands and all five Work kinds with the same canonical bytes as Devgraph/secS.

The signer produces `devgraph.work.wallet-presentation.v1` using Ed25519 over
`devgraph.work.wallet-presentation.v1/signature\0` plus canonical unsigned JSON.
Request hashing uses `devgraph.work-request.v1\0` plus canonical request bytes.
The presentation binds the derived operation/resources, audience
`devgraph://receiver-local`, idempotency digest, fresh session/nonce, and a
60-second window. The outer output schema is
`secs-devgraph-work-producer-input.v1`. It is input to secS, not a Devgraph write
authorization by itself. secS owns grant checking and its independent projection;
Devgraph owns mutation execution and receipts.

Sharing this existing key between Codex and Hermes shares their authenticated
principal. Agent labels do not split grants. There is no arbitrary-message
signing, caller-selected audience, network call, or browser approval bypass in
this explicit owner-invoked headless command.

Validation includes native CLI signatures for all shared vectors, malformed
request/number/duplicate-field denials, existing custody regressions, and an
explicit native Wallet→secS test workflow. Live use still requires the actual
key reference, public pin, installed binaries, and current operator-held grants.


## Arena compatibility

The shared pinned Devgraph request parser also accepts the existing
`devgraph.arena-request.v1` create, patch, archive and member.set requests. Arena
request digests have their own domain; Wallet presentation domains and the native
producer-input envelope do not change. Member changes bind the Work subject and
all non-null previous/new Arena references. A Task parent change can additionally
bind its previous Arena. Old Work requests preserve their exact canonical bytes.
This parser support never creates grants or changes the installed receiver policy.
