# Owner-configured native service command

## Current finite pilot composition and owner setup — 17 October 2026

Wallet and its create-only owner-setup companion now select the complete342-file Native export `a7100a7`; historical `eb8d839` and older exports remain unchanged and verified. Both registry locks retain all186 original registry rows and one shared private-files package identity. Setup explicitly pins `journal_capacity=local_review_pilot_512` into the command authority, Wallet configuration and final master hash chain. Native defaults remain32holder/256global; the opt-in profile changes no byte, Pending, replay, expiry, history or permission boundary.

Physical-Mac qualification passes111holder tests per default/hostile profile,18setup tests per profile,23private-files tests,37source controls and16package controls, actual locked/offline metadata, unchanged public goldens, both all-target builds, strict Clippy and formatting. Counts overlap. Actual setup RED retained17passes/one missing-capacity failure; source/package RED retained5/one expected failures before consistent selection. Source was identical before/after the complete final run and every owned process group was empty. Generic npm remains39passes/5existing failures and type checking is unavailable because `tsc` is absent; those are not native qualification passes.

The companion creates separate native holder/command-issuer/result-party custody only through reviewed Native/Wallet APIs, uses a maximum one-hour fixed review scope, writes intent first and COMPLETE/master last, and retains partial state on failure. It does not start services, create a run or enable a provider. Actual new nine-handler/recovery integration, trusted installation/finite owner activation, selected real input and first useful workflow remain pending. No VM prerequisite or Gate/status completion.

Evidence: `/Volumes/home/bananawalnut/repos/process-execution-evidence/2026-10-14/wallet-capacity-setup-qualified-20261017/manifest.json`.

## Historical query and configuration-pin checkpoint — 17 October 2026

The normal Wallet command now supports explicit fresh Runtime query acquisition and an optional same-read SHA-256 command-configuration pin. Frank must choose the pinned form. Issue/resume retain request uniqueness and the original authorization window; queries use fresh Native challenge/session/nonce identity, including repeated identical read bytes. The eight permitted reader profiles add no permission grant. Unsupported reads, commands and Service requests deny through Query. There is no unpinned, reissue or signer fallback.

The selected complete immutable Native export is eb8d839. All 333 source files match its qualified commit; historical 20d/afeb/B/A exports remain unchanged and checked. All 186 registry rows, root generic files, frozen public goldens and the single shared private-files package identity remain unchanged.

Physical-Mac final qualification passes 111 tests per default/hostile profile: 87 unit, one holder-only and 23 actual Native/Wallet/command controls, zero failures or ignores. The 23 selected private-files tests, all-target build, strict Clippy and formatting also pass. Source integrity has 32 passing controls and package identity has 15, plus actual locked/offline metadata in both profiles and unchanged public goldens. Focused query/pin counts overlap. All six groups are reaped/empty and runtime/test source is byte-identical before/after. An earlier full run passed default tests/build but strict Clippy rejected a lazy fallback in the new test fixture; only that fixture expression changed, then all required Rust checks were rerun. The missing-pin API, unsupported-query and unprotected-export test-first failures are retained. The initial package-control invocation's isolated-import error is a runner error, retained and corrected without changing tested source.

Exact source, both ordinary command binaries, executed test artifacts, logs, proposals/reviews and earlier attempts are retained at `/Volumes/home/bananawalnut/repos/process-execution-evidence/2026-10-14/wallet-query-pin-qualified-20261017/manifest.json`. Generic npm/typecheck remain separate checks with their actual results recorded there. These are actual disposable OS-generated custody/clock tests, not installed receiver/provider qualification. Frank's adapter, actual helper/receiver fresh admission, replay/cursor reconciliation, finite live issuer/public pins, trusted installation and accountable result/provider execution remain open. No live role, identity, service/profile or Gate/workflow status changes. No VM gate is required.

This opt-in normal binary in the excluded service-holder package has passed the source-bound physical-Mac checks recorded in README. It is not yet an installed command or an installed production authority qualification.

The two existing compatibility command forms remain exact:

```text
castalia-wallet-service issue --config /absolute/owner-private/command.json
castalia-wallet-service resume --config /absolute/owner-private/command.json
```

Either form also accepts exactly one optional suffix, after the config path:

```text
castalia-wallet-service issue --config /absolute/owner-private/command.json --config-sha256 <64 lowercase hex>
castalia-wallet-service resume --config /absolute/owner-private/command.json --config-sha256 <64 lowercase hex>
```

The owner-selected SHA-256 pins the exact bounded command-configuration bytes read internally. The digest comparison occurs before the closed parse or any configuration-selected source opening; there is no precheck followed by a different read. Missing, malformed, uppercase, repeated or extra suffix arguments deny. A correct digest does not approve authority or relax the private-file checks. The unpinned compatibility forms remain available; a launcher that requires a pin must always select the pinned form and must not retry without it. Frank's forthcoming native adapter requires this pinned form. The Rust library preserves `exchange(configuration, mode, exact_request)` and adds `exchange_pinned(configuration, mode, expected_sha256, exact_request)` over the same internal read and exchange logic. Native's separate same-read pin remains mandatory in both paths.

The owner chooses the config path at process startup. Untrusted requests must not select that path or supply command arguments. The only request input is exact stdin bytes. The binary reads at most 2,097,153 bytes to detect the 2,097,152-byte transport ceiling. The selected public application reader separately enforces Runtime's 2,097,152-byte or Service's 65,536-byte request limit and closed command/query contract before Native issuance. Bytes are never trimmed, normalized or re-encoded. A completed read requires EOF; launcher deadlines remain the caller's process-supervision responsibility.

There is no default mode, autodetection, fallback from resume to issue, renewed TTL, caller clock, key, raw signer, policy, arbitrary journal or output-path option. Unknown or extra arguments deny. The command uses the existing real OS clock, Wallet custody and Native journal. Opening the Wallet store observes the OS clock and invalidates in-process handles as required; it does not persist Wallet CLOCK. Holder signing also does not write Wallet CLOCK. Native journal operations retain their own durable clock observations. The exchange command can create or complete Native journal state and is not read-only.

## Closed trusted configuration

The config is UTF-8 JSON with exactly these fields and nested fields. This illustrative shape contains placeholders and is not an operator configuration:

```json
{
  "schema": "castalia.wallet-service-command.v1",
  "native_configuration": "/absolute/owner-private/native.json",
  "native_configuration_sha256": "<64 lowercase hexadecimal characters>",
  "wallet_root": "/absolute/owner-private/wallet",
  "application": "runtime",
  "store_binding": {
    "store_id": "<32 lowercase hexadecimal characters>",
    "subject_id": "<exact existing public subject>",
    "application": "runtime",
    "purpose": "secs-service-holder-proof.v1",
    "minimum_revision": 1
  },
  "expected_state": {
    "state_revision": 1,
    "state_sha256": "<64 lowercase hexadecimal characters>"
  }
}
```

Use `service` in both application fields for Service Management. StoreBinding and ExpectedState come from the selected actual Wallet's public identity, not from a request or a success assertion. Revisions are positive safe integers; the SHA and store ID encodings are exact lowercase hex. Subject and purpose use the existing Wallet limits. Paths are absolute, bounded by the existing 1024-byte metadata string limit and checked by the existing descriptor-relative private-file reader. Both configuration reads are bounded at 65,536 bytes. The inherited strict JSON parser denies recursive duplicate keys, floats, out-of-range integers and the reserved arbitrary-precision metadata token; all command-level and nested field sets are closed.

The ordinary `castalia_wallet_private_files::read` safety checks apply: owner-private regular files, one link, bounded exact reads and retained no-follow ancestor traversal. No new file-reading implementation or storage policy is introduced. The process separately checks the selected Native config's pinned bytes and wallet_root, then calls Native's `open_pinned_owner_configuration(path, expected_sha256)`. That API must hash its own one actual bounded read before its closed parse/source opening. Merely checking the path before and after an unpinned Native opener would be insufficient. Native owns its full configuration schema and journal/issuer selection; the command does not reproduce it.

The actual Wallet store must match the public binding, application and exact expected state. Pending challenges must also match the configured application, exact request bytes and actual holder subject/key before Wallet presentation. No generic Member Key, browser or membership path changes.

## Execution and recovery

`issue` invokes Native issue, validates the returned challenge identity/request, asks the actual current Wallet holder operation for the frozen proof, then invokes Native complete. `resume` invokes only the explicit Native resume API. Missing, expired, pruned or otherwise denied entries fail; they never create a challenge. Pending entries go through the same current holder and completion path. Completed entries use the exact Native completion returned after Native's current authority/window validation; the command does not retrieve or inject a cached proof itself.

Only after success does stdout contain the existing three-field envelope: `schema` (`runtime.secs-envelope.v1` or `service.secs-envelope.v1`), `packet_hex` and `signed_context_hex`. Both byte fields are exact Native bytes encoded as lowercase hex. Packet admission remains application request bound + 16,384-byte proof bound + 69-byte overhead; signed context remains bounded to 65,536 bytes. No new envelope field or receiver contract is introduced. The command never writes an output artifact or second journal. A stdout write can partially fail after durable completion. For issue/resume, the caller must discard incomplete output and explicitly resume the same request. Resume preserves the original window; it cannot guarantee delivery after expiry. For the fresh query mode described below, a lost response does not advance the caller cursor and a later new Query invocation is explicit; raw bytes alone do not identify the lost read once more than one read exists.

All ordinary denials exit 2 with fixed stderr `castalia wallet service command denied` followed by a newline. Pre-output denials leave stdout empty and do not print request, configuration, path, policy, key or internal error content. OS termination, panic and partial stdout transport failure are not claimed to satisfy a complete-envelope guarantee. Authority is checked at the existing local operation boundaries; this is not atomic revocation through later transport/receiver use.

## Test-first and qualification boundaries

The separate test patch extends the actual OS-generated fixture and adds ten normal-binary controls. Both application profiles cover issue, exact restarted resume, missing/wrong exact request, discarded process output, original expiry, revocation and changed owner. The three issue/presentation/completion loss-boundary controls deliberately drop the producer at public API boundaries; they are not private fault injection or claims that a process was killed at those points. Independent decoding verifies issuer/holder/context signatures, exact request/identity/context/Packet bindings and retained windows/bytes. Config/parser/storage/CLI failures use fixed denial assertions, and resume verifies no denied issue silently created the original Pending entry. All stores, OS-generated keys and finite permissions are disposable fixtures.

The missing explicit binary produced the expected test-first RED result. The implementation then passed ten focused controls and the complete source checks: 102 tests per default/hostile-JSON profile, 23 selected private-files tests, all-target build, strict Clippy and formatting, plus 27 source-tamper and 14 package-ID controls. Counts overlap across profiles and focused reruns. The historical immutable `20d064d` Native export contains the required resume/pinned-open APIs and matches its separately qualified committed source. The retained qualification manifest binds exact source and executable bytes; vendored bytes must not be edited. Tokio is promoted with its existing exact version/features from dev to direct dependencies; registry rows, lockfiles, root Cargo exclusions and generic Wallet sources remain unchanged by this proposal. Installed qualification, receiver admission, finite live owner approval and useful provider execution remain separate work. Gate 1 remains open.

Issue/resume preserve one original session/opcode/nonce. Explicit Query below creates a new observation; Service intake alone does not complete the useful Mac workflow.

## Command-configuration pin

The four actual library/binary pin controls now pass in both final feature profiles, including substitution by another valid owner-private configuration. Their initial missing-API RED and predecessor checks are retained. The old issue/resume syntax remains supported, while Frank always supplies the exact same-read pin.

## Explicit fresh Runtime query mode

```text
castalia-wallet-service query --config /absolute/owner-private/command.json
castalia-wallet-service query --config /absolute/owner-private/command.json --config-sha256 <64 lowercase hex>
```

`Mode::Query` is closed to the eight frozen Runtime reader operations actually
used by Frank: work.list/events.list/attempt.get/output.get/run.get/artifact.get/
version.get/receipt.get. process.get/effect.get, every Runtime command and every
Service request deny. Reader eligibility is no permission: the selected actual
Wallet binding, Native receiver descriptor/principal/evidence/current policy and
original-window guards still decide every acquisition.

Query calls only Native acquire_query, actual Wallet current-challenge holder
presentation and Native complete_query. Native owns fresh challenge/session/nonce;
the exact request bytes and existing envelope are unchanged. The command does not
select an acquisition ID or retrieve a proof, create a second journal, renew an
old exchange, invoke issue/resume as fallback or retry an uncertain domain command.
Each explicit Query is a new read. A caller that loses output keeps its last
successfully applied cursor/results and may later invoke Query again. Abandoned
rows remain bounded/charged until original expiry. Saved challenge/proof can be
completed exactly through Native; this CLI makes no raw-only exact recovery claim
for a lost read or historical delivery acknowledgment. Reusing an old completed
context at Runtime is replay, not a fresh poll.

The same-read command pin applies unchanged; Frank must always choose the pinned form and never retry unpinned. The fixture paths select the exact eb8d839 export. Old fixture calls retain their original request/opcode; new controls use exact public Runtime query bytes and the actual OS-key/clock/custody constructor. Five actual binary controls cover all eight reads, distinct replay identity, discarded output, excluded valid reads/commands/Service, pin mismatch, revocation and exclusive expiry. Their initial four positive failures and passing denial control are retained. These source checks do not establish actual Runtime receiver admission, durable cursor advancement, live authority or useful workflow completion.
