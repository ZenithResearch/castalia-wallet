# Empty workspace owner setup

This standalone opt-in companion provisions a stable dedicated Frank Runtime holder and a separate Native command issuer using the existing native raw-file custody APIs. It is independent of process payloads. It creates no example process, run, actor, provider, result issuer, assignment, source manifest or capture. Runtime owns initialization of its empty database; setup requires an empty private `data` directory and never opens a business database.

The only CLI form is:

```
castalia-wallet-workspace-setup create --plan /absolute/private/plan.json --plan-sha256 <lowercase-SHA256>
```

The closed plan has exactly `schema` (`castalia.wallet-workspace-setup.v1`), `workspace_root`, `not_before`, `not_after`, `identity_not_after`, `wallet_command_sha256` and `verifier_sha256`. Times are canonical decimal Unix-second strings. `not_before < not_after` selects a current permission window of at most3600seconds; `not_after <= identity_not_after <= not_before +31536000` selects a separate holder lifetime of at most365days. The dedicated subject/key therefore survives permission expiry. The issuer, Native owner-policy, receiver rules and Runtime permissions still end at `not_after`; the broader owner-input envelope is custody metadata and grants no extension. It requires existing owner0700 `workspace_root/{config,data,native}`, empty data, absent `workspace_root/authority`, and exact owner0500 binaries `native/castalia-wallet-service` and `native/process-runtime-secs-check`. The plan's exact bounded private read is SHA-pinned before parsing or custody. No browser-selected signer, application, caller identity, permission list, arbitrary file import or automatic time renewal exists.

Setup writes a durable intent first, then generates one holder (`service:frank-workspace`) and one command issuer (`node:workspace-command-issuer`, `issuer:workspace-command-v1`). It retains all partial state and denies reentry rather than silently rekeying. It emits unchanged public contracts under `authority/config`: `command-authority.json`, `wallet-command.json`, `runtime-policy.json` and `runtime-receiver.json`. The separate Native and Wallet same-read pins, actual current Wallet reference, native generation and descriptor fingerprints are preserved. Exactly five operations are granted: draft.put/publish/process.get on the `processes/` prefix, version.get on `versions/`, and events.list on exact `events`. Prefixes are explicitly store scoped; events observation is the isolated store's catalog, without a nonexistent process/run filter. All execution, actor, run, artifact, Service and result operations remain denied.

The emitted command authority explicitly selects the already supported `local_review_pilot_512` journal capacity. That historical enum name changes no authorization semantics: the existing finite512-row holder/global, byte and physical bounds remain enforced. Native challenge TTL is30seconds and never exceeds the original policy/custody window. There is no generic signer or public raw-key export. Policy expiry/revocation denies. The live identity can be explicitly configured after its old grants expire without changing its key; configuring the same expired grants does not renew them. A real grant renewal must use the existing coupled Wallet/Native owner-administration APIs, update exact policy/configuration pins and select a new finite window while the identity is still live. Setup never renews automatically and must not be rerun to rotate the dedicated identity.

`authority/COMPLETE.json` is last, with schema `castalia.wallet-workspace-setup-complete.v1`, exact input plan hash, root, actual public holder, Native generation/hash, command issuer public metadata, four exact configuration hashes, policy `not_before`/`not_after`, separate `identity_not_after`, and finite capacity. Its flags say `activation:false`, `service_started:false`, `runtime_store_initialized:false`, `process_created:false` and `run_created:false`. An actual current Wallet lease and post-I/O floor/exclusive-expiry check guard completion. Root composition can derive a separate pinned Frank workspace profile from these outputs; no Frank master or workflow is generated here.

Process creation/publish uses the unchanged Runtime command schema. Draft.put persists a schema-valid editable draft; publish performs semantic DAG/type compilation. There is no fabricated validate RPC, run or example needed to make the workspace available. Local-review setup is unchanged and optional.

The source depends only on the selected immutable Native export already used by the holder; all186 registry versions/checksums and the single shared filesystem package remain fixed. `process.get` fresh-query support must be selected in that export before the new actual-custody query controls can pass. Source checks and future build/test commands are ordinary `cargo test/build/clippy --locked --offline --manifest-path crates/castalia-wallet-workspace-setup/Cargo.toml`, with default and `hostile-json-features`, plus `cargo fmt`. Coordinate use of the shared Cargo target. The disposable tests pin public nonexecutable layout bytes but never run them; their actual public custody/Native calls do not qualify installed binaries or a live identity. Validation and installed composition are pending until separately recorded.


## Explicit stopped-workspace permission renewal

The dedicated holder lifetime is independent of its grants. Owner-selected renewal uses the same Wallet store, subject, key generation, holder key, Native issuer directory/key, command journal and all existing replay history. It admits exactly the same five authoring/catalog operations and fixed resources. It never creates a process, run, actor, result authority, capture or provider. The controller must verify the workspace is stopped and retain its migration hold; native leases protect current publication, without attesting that every OS process has stopped.

The additive CLI forms are `renew --plan ABS --plan-sha256 SHA` and `resume-renewal --plan ABS --plan-sha256 SHA`. The closed seven-field plan is schema `castalia.wallet-workspace-renewal.v1`, `workspace_root`, `previous_complete` (closed `path`/`sha256`), canonical decimal-string `not_before`/`not_after`, `wallet_command_sha256`, and `verifier_sha256`. The consumed bounded private plan read is SHA-pinned. The new current window is at most3600seconds and cannot exceed the still-live holder lifetime. No permissions, identities, application modes or caller clocks are selectable. Old permission expiry is permitted; expired/revoked custody and stale anchors deny.

Old COMPLETE/configurations remain immutable. A create-only `authority/renewals/<oldNativeGeneration+1>/` contains bounded public `INTENT.json`, `ORIGINAL.json`, `config/{command-authority,wallet-command,runtime-policy,runtime-receiver}.json`, and COMPLETE last. At most64 renewal directories are admitted; there is no pruning, automatic rotation or history reset. The new receipt has schema `castalia.wallet-workspace-renewal-complete.v1`, all setup receipt keys and values updated to actual current state, plus exact `previous_complete:{path,sha256}`. The holder revision advances once, `previous_state_sha256` links the original holder, Native generation advances once, and key/store identity and identity lifetime stay unchanged. Success stdout is `castalia.wallet-workspace-renewal-output.v1` with `status:configured_not_activated` and `complete:{path,sha256}`. Activation/config selection and explicit Frank journal binding migration are controller-owned later steps.

The actual Wallet exclusive administration session is acquired before Native administration. Exact old CAS/reference/source-root anchors and exact target policy are retained before Native prepares its marker. The real Native transition guard authorizes the exact Configure on that same Wallet lease; only supported Wallet mutation and Native outcome/publication/finalization APIs change owner state. No code reads, copies or exports raw keys. New configurations keep the same journal root and the already supported `local_review_pilot_512` finite row profile; every byte/physical quota and replay guard remains in force.

A pure preflight rejection exits2. Once an intent exists, partial publication or uncertain completion exits4 (`recovery_required`) and retains all files. `resume-renewal` uses the exact original plan, anchors, request and window, without signing, acquiring a challenge or selecting fresh times. It can finish an already committed and publicly observable Configure, Native publication, completed cleanup or lost-output readback through the existing original-input Native APIs. Poisoned or unobservable Wallet state remains held: the frozen Wallet session cannot supply its physical-root observation while poisoned, so this companion never reconciles based only on a path or inferred fence. A future checked Wallet recovery continuation is required. A durable own INTENT interrupted before Native prepare is deliberately held too: current exact resume only observes unchanged original source and cannot invent a completed transition. Safe pre-prepare continuation is future work; it is distinct from the frozen Native prepared gap. A durable prepared transition interrupted BEFORE Wallet Configure is deliberately held: the frozen Native recovery guard permits reconciliation, not replay of Configure; an abort cannot silently substitute old delegation under the renewed policy. Automatic continuation of that case requires a future reviewed Native owner contract. Neither the CLI nor controller may delete the marker, rekey, reapply the mutation or claim success to escape it.

Tests use actual disposable public Wallet/Native APIs and real signatures. The SQLite read-only test connection checks retained journal row bytes; it does not replace the real journal implementation. Public binary-layout fixture bytes are never executed. Source tests and proposals do not qualify an installed software tuple or a live renewal.


After successful Native finalization and publication of COMPLETE, renewal releases every Wallet/Native administration lease and calls the supported Wallet `cleanup_unreferenced` API with the exact completed holder CAS. This retires duplicate custody revision copies so the next Configure meets Wallet's single-current-revision invariant. It never reads/exports key bytes, rekeys, prunes command/replay history, or deletes public ORIGINAL/INTENT/COMPLETE/configuration evidence. Partial or failed Native/Wallet transitions never enter this cleanup path. Completion is the last public file; success additionally requires this supported custody cleanup and an unchanged holder/time check.

A cleanup not yet performed can be retried by exact-plan resume without a new Wallet revision, Native generation or time window. Any cleanup error retains COMPLETE and returns4. If the actual Wallet API reports uncertainty and poisons custody, the existing poisoned/unobservable hold still applies; automatic checked reconciliation remains separate unresolved work. No claim is made that every uncertain cleanup failure can resume automatically.

## Finite live-provider authority

The same stopped-workspace transition also accepts the closed plan schema
`castalia.wallet-workspace-live-provider-authority.v1`. It has the seven renewal
fields plus `actor_id` and `run_id`; both must be valid Runtime identifiers. The
plan carries no operation list, resource list, key, provider configuration or
caller-selected policy.

This profile retains the five authoring/catalog rules and adds seventeen fixed
rules. `actor.register` and `work.list` name the exact selected Actor.
`run.create` and `run.get` name the exact selected Run. Claim, heartbeat,
complete, fail, release, effect intent/dispatch/observe, attempt read and output
read are restricted to the `runs/<run_id>/steps/` prefix. Artifact put/get and
receipt get cover the isolated store's content-addressed `artifacts/` and
`receipts/` namespaces so real inputs, outputs and their existing canonical
receipts can be committed and read. It grants no other Actor, Run, handoff,
effect-resolution or service authority. The resulting receipt records the exact Actor and Run and reports twenty-two
permissions. A later ordinary authoring renewal cannot silently remove this
profile and the same Actor must be selected again. The new plan may replace the
one exact Run identifier, so a terminal or uncertain execution is never reused;
the predecessor Run permissions are omitted from the successor policy.

The transition changes no custody identity or command issuer, exports no key,
and preserves the existing command/replay journal. As with every renewal, the
controller must stop the workspace, pin the previous receipt and installed
binaries, review the finite time window, and explicitly select the resulting
configuration before Runtime or Frank can use it.
