# Owner-selected service-authority startup checkpoint

Status: Native startup/bootstrap and additive explicit no-create resume/pinned startup source qualified locally on macOS. The wider integration remains partial; this is not installed command authority or a Gate exit.

`ServiceAuthority::open_owner_configuration` reads one bounded owner-private closed configuration, rejects duplicate/unknown fields and caller clock/key bytes, and fixes actual Wallet, Native policy, selected issuer-key source and replay journal for its lifetime. Independent public pins remain configuration data. `issue` accepts exact request bytes and returns the retained challenge; `complete` accepts exact request plus a compact Wallet holder proof and returns exact retained Packet v0/context bytes without renewing the original window. Output is transport data, not receiver admission.

The journal retains its selected private directory and identity, checks fresh traversal and the original held lock against the current entry before connection, persistence and final export. Final actual-owner and clock checks remain last. Denial never selects replacement storage; cleanup uncertainty preserves the original denial. This does not protect against the owning UID replacing/restoring arbitrary state between observations or storage rollback across process restarts.

## Create-only source APIs

`ServiceAuthority::create_issuer_key` uses OS entropy inside Native and returns only the public key. An empty owner-private root is required. Existing/partial roots are preserved and retries deny; there is no overwrite, implicit cleanup, rotation or raw-seed port. Creation retains the original exclusive lock and readable key descriptor through durable sync, strict storage/inode checks and seed read-back. The same path-size/depth bounds apply before creation and later startup. The exact64 lowercase-hex file is Native issuer custody, distinct from the separately approved Wallet holder seed.

`OwnerPublicationSource::create_initial` requires a canonical generation1 complete policy, the actual retained Wallet observation, an empty owner-selected Native root and a finite current window. It creates the lock/current files without replacement, repeats actual Wallet/root/lock/time checks and returns a public startup pin. Partial or uncertain publication is retained for explicit diagnosis. A public pin alone grants no authority. A lost key-creation response requires explicit public inspection/recovery, never silent regeneration.

## Prior startup/bootstrap validation and review

Prior bootstrap checkpoint: **1,050 workspace tests passed, zero failed, one existing opt-in workflow ignore**. Workspace build, strict workspace/all-target Clippy and formatting passed. Eight startup/bootstrap tests and two deterministic creation inode/path tests passed; the eight startup tests also passed under hostile JSON features. These focused counts overlap the workspace result. All seven completed checks across unchanged-source runs were reaped, and source-before/after bindings matched.

The earlier startup-only checkpoint separately passed1,046 workspace tests and six hostile startup cases. Its initial 23 fixture-open failures came from TMPDIR under the group-writable external mount. An owner-private internal scratch directory fixed the test environment without changing protections or mount permissions. The bootstrap's first compile failure was a missing test-only standard-library trait import, then corrected. A later lint attempt has no completed result because its process-group probe raised an OS permission error while internal space was below the unchanged guard. The four completed checks were retained; only lint, formatting and hostile startup were resumed against byte-identical source after inactive package caches were reclaimed. Failed/interrupted attempts and their exact source/logs remain retained.

Independent read-only review closed two proposal findings before application: creation could reacquire a replacement lock/key, and creation omitted normal startup path bounds. The final implementation retains original FDs and shares bounds. Ordinary finalization regressions deny replacement locks and identical-seed replacement key inodes while preserving displaced/replacement files; unchanged finalization succeeds. Over-depth creation leaves the target empty. Review of the applied source found no new actionable issues.

Evidence: `/Volumes/home/bananawalnut/repos/process-execution-evidence/2026-10-14/native-service-startup-bootstrap-20261017/manifest.json`. The prior blocked proposal/attempts remain at `native-service-startup-blocked-20261016` in the same evidence day. The separately retained startup-only validation and Mac user-operated lifecycle evidence live under `/Users/bananawalnut/.codex/visualizations/2026/10/11/01a1285e-6c89-7a52-9bae-8a734c9e0f7f/`.

## Remaining integration

1. Wallet b6624390007d8f42bac2d71c17bb712d64593b8a contains the exact20d resume/pinned-startup export with one shared filesystem identity. Historical exports remain immutable.
2. That Wallet commit qualifies the normal issue/resume command (102 tests per default/hostile profile). Native fresh query acquisition now passes its source checks. The new Wallet export/query mode, same-read command-config pin and Frank adapter remain active integration work; installed workflow admission is unfinished.
3. Run ordinary-library actual-clock disposable custody through the actual verification helper and receivers on macOS.
4. Prepare the finite live Native issuer role/public pins for owner approval, then wire trusted installed startup.
5. Complete accountable normalized-result production, real provider/Matrix request intake, the useful Mac workflow/recovery pilot, and Jess's installation/admission.

No live identity, role, permission, installed authority, installer, dependency, workflow or Gate completion is changed by this source checkpoint. The installed base services remain live/default-deny and Frank has no enabled actors. The operator's Mac is the target; no VM is required.

## Additive exact-request explicit resume contract

`open_pinned_owner_configuration(path, expected_sha256)` adds an owner-selected
consistency fence over the same bounded private bytes Native actually consumes,
before closed parsing or opening any selected source/journal. The existing
`open_owner_configuration` retains its behavior through the same private parse
and open helper. Neither accepts raw configuration/key bytes or caller time as a
new public authority port. The command must independently validate those pinned
owner bytes against its fixed Wallet root/profile; a digest alone is no approval.

`ServiceAuthority::resume(exact_request)` is a no-create owner-local recovery
operation. `ServiceResume::PendingChallenge` contains the original guarded
challenge; `Completed` contains the exact stored Packet/context after the existing
complete/cache path revalidates every current owner, signature, binding and
original window. No standalone unvalidated proof is returned; the completed Packet retains its
existing validated proof field. No new challenge,
entropy, context signature or TTL is selected by resume. Missing, expired/pruned,
tombstoned, ambiguous and changed requests deny. `issue` retains its existing
Pending-only retry semantics, including its explicitly separate new-invitation
behavior after normal expiry pruning.

The opt-in command should distinguish an explicit first issue from resume.
Resume denial must never fall back to issue. Pending resumes call actual Wallet
current-custody presentation for that same challenge, then complete; Completed
resumes return guarded cached output without signing again. If a process stops
after Wallet presentation but before Native persistence, Pending retains the
challenge, not a proof; unchanged current Wallet custody can reproduce the fixed
deterministic proof within the original window. No second Wallet journal or
caller-selected arbitrary-path exchange store is introduced. This is authority
transport recovery, not receiver dispatch deduplication or indefinite exactly-once
execution. Generic caller/human APIs, Packet v0, schema4 and journal schema stay
unchanged.

This additive Native slice passes the source qualification recorded above: 1,060 workspace tests, ten focused recovery/pin regressions, 18 hostile startup cases, workspace build, strict lint and formatting. Exact evidence is in the native-explicit-resume-qualified-20261017 packet. A new immutable Wallet composition, normal-binary command controls, actual helper/receivers and installed qualification remain required. No live role or installation is enabled by the source result.

## Explicit fresh Runtime read acquisition (locally qualified source)

`acquire_query` intentionally begins a new read, not a retry. It is closed by the
frozen Runtime reader to work.list/events.list/attempt.get/output.get/run.get/
artifact.get/version.get/receipt.get, the finite current Frank consumer set.
process.get, effect.get, all Runtime commands and all Service requests deny.
Actual current receiver descriptors, principal permissions, evidence obligations,
custody and whole-window/key policy still decide each acquisition; reader support
adds no grant. Native generates fresh challenge/session/nonce and durably retains
the original challenge before output. `complete_query` selects only the proof's
signed challenge primary identity and binds exact request/claims/proof/current
owners. Its final guarded completion/cache operations allow other read identities
with identical query bytes, but deny target replacement/rejection or byte changes.
Original issue/complete/resume retain request-unique behavior; no method falls
back to new acquisition. Journal schema, Packet v0, context4 and proof bytes stay
compatible; no user query field, caller ID, token mapping or Wallet journal is added.

If read output is lost, the caller retains its last successfully applied cursor
and may later explicitly begin another read. It cannot claim recovery/ack of the
old read or resend a cached context as fresh Runtime evidence. Existing exact
complete_query retries with retained proof remain original-window cache delivery,
not a new poll. Unknown lost acquisition identity may be abandoned; its row stays
charged until original expiry. This query-only policy does not permit retrying an
uncertain domain command. All existing row/byte/pending/physical quotas remain;
frequent polling may receive Capacity and must back off. Poll interval and existing
owner-selected maximum_ttl must fit those quotas; no silent quota increase,
unexpired eviction or timing-guarantee change is proposed.

Native source qualification now passes 1,070 workspace tests, ten focused query controls and all28 hostile startup controls, with build, strict Clippy and formatting. Independent source review found no actionable production issue. The source-bound manifest is native-query-acquisition-qualified-20261017. A new immutable Wallet export, actual-clock Wallet command controls and two actual Runtime query admissions plus replay/cursor checks remain required before an installed read path can be claimed.
