# Explicit local-review pilot journal row profile

The legacy Native service authority configuration still omits journal_capacity.
It keeps32 retained rows per stable holder and256 globally. All Pending, Completed
cached responses and replay tombstones count. Limits with the legacy profile still
may only tighten these ceilings; setting rows33/257 alone remains invalid.

A new OPTIONAL owner startup member selects one closed finite quota profile:
journal_capacity = "local_review_pilot_512".
It changes only row ceilings to512 per stable holder AND512 globally. This field is
in the exact bounded same-read hashed Native configuration, not the Runtime request,
Wallet proof, permission policy, readiness flag or caller input. Unknown/null/duplicate
values deny. "legacy" explicitly selects the unchanged default. No new role or grant
is implied; all actual issue/query/complete/current-owner/replay checks remain.

Unchanged hard ceilings: Pending8perholder/64global,8MiB perholder accounted bytes,
32MiB global accounted bytes,16MiB global request bytes,64MiB physical directory.
Maximum request2MiB, completion reservation, full row/proof/context/SQLite/WAL/SHM/
lock/temp/allocated-extent bounds remain. Therefore512 large requests need not fit:
the original byte/Pending/physical caps can bind first. This is not a guarantee
of call success, a disk reservation or a way to suppress quota errors.

The journal aggregate pre-read bound and complete row audit use the selected
profile's hard row ceilings, then apply any tighter selected Limits. This repairs
both the old fixed256 aggregate count and the audit's old unconditional default
holder32 check. No schema/table, record serialization, signature, TTL, nonce,
session, request identity, compaction or expiry rule changes. Unexpired rows are
never evicted, rotated, pruned or spread across identities to avoid a ceiling.
Existing exclusive expiry pruning remains the only ordinary removal.

Capacity is startup policy, not persisted authority. A journal holding33sameholder
or512total valid unexpired rows cannot be reopened by tighter legacy policy:
it fails closed without deleting the rows. Reopen with the original opted-in
profile preserves exact cached responses/tombstones. Operators must keep the
same explicitly pinned profile across command restarts. Removing the opt-in
does not erase retained replay state or silently regain capacity.

Implementation/source tests (not run by author):
1. Public Native startup under legacy config admits32actual completed fresh reads,
   rejects33, keeps32rows and still returns an exact retained completion.
2. Opted-in startup admits33actual completed reads, reopens and returns original
   proof/context unchanged, still denies ambiguous old request-unique APIs.
   Legacy reopen of that journal denies and leaves33rows.
3. Invalid capacity config denies before journal creation.
4. Limits profile preserves all other hard ceilings; lower limits still tighten.
5. Efficient real SQLite test stores512codec-valid untrusted replay tombstones in
   one actual transaction while checking CURRENT real rows for each admission;
   513denies, restart/tightened reopen retains all512, replay identity remains
   rejected/ambiguous, and expiry/clock rollback behavior stays unchanged.
   These tombstones are storage fixtures, NOT authenticated issuer evidence.

The public-startup three tests form01test-first and compile against the old public
API. The opted-in positive should fail on the old closed config parser; no invented
test result is supplied. Store-profile enum tests accompany02implementation because
they use its new private quota type. Parent owns actual RED/GREEN/full validation.

Source throughput concern: Session.session audits every retained row before and
after expiry pruning; stats/capacity/unique lookup can repeat the same full audit,
and each command process opens Journal and its stats admission. Audit performs
bounded SELECT/fetch_all, row-byte SHA, codec/relational validation and holder
accounting. Per-operation work is O(n) in unexpired rows; a growing burst is O(n^2)
cumulative.512doubles the worst row-count factor versus oldglobal256, with total
record bytes still32MiB. No timings or bottleneck cause was measured by this author;
do not claim a speed fix. Existing process deadlines remain and actual nine-step
chain must establish useful throughput. Do not skip/cross-call-cache audits here.

Propagation after Native source qualification:
- Commit/export the exact new Native source; parent performs the normal immutable
  Wallet vendor/export selection and same186registry/singleFS verification.
  Historical helper11e7128 and old exports remain unchanged.
- Rebuild Wallet command against that export: its outer command configuration DTO
  stays unchanged and still pins Native config SHA; old eb8Native parser cannot
  accept the new member, so no silent fallback or old artifact promotion.
- In fixed create-only pilot setup, emit journal_capacity="local_review_pilot_512"
  in command-authority.json only. Its readback-derived SHA flows automatically into
  wallet-command.json then Frank master. Existing configs lacking it remain legacy.
  The setup crate needs the new export only for its actual config roundtrip tests;
  its key creation APIs/oneFS ownership are unchanged.
- New bundle/profile pins actual rebuilt Wallet/setup binaries and their configs.
  Native result journal is separate and is not enlarged by this change.


[Physical-Mac capacity source qualification — 17 October 2026] The optional owner-pinned journal_capacity=local_review_pilot_512 profile now passes five focused default and five hostile JSON controls, the complete1,092-test workspace (one existing opt-in ignore), workspace build, strict Clippy and formatting. Counts overlap. Legacy32/256, all byte/Pending/physical caps, replay and exclusive-expiry behavior remain. Tests retain512 actual tombstone rows, deny513 and fail closed on tighter reopen; public startup retains33 actual completed reads and exact cached retry. Actual first result admission previously hit the old32-row limit; new immutable Wallet export/rebuild, nine-handler chain/recovery, trusted installed activation and useful input remain pending. No gate or authority role is completed/provisioned by this receipt. Evidence: native-pilot-journal-capacity-qualified-20261017.
