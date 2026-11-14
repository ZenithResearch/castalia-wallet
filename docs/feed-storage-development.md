# Guarded feed storage development

The extension can read an already stored, Rust-validated v3 snapshot without
losing feeds during account edits or older/empty imports. Every complete
feed-bearing candidate is validated and preflighted through the actual WASM
core before sealing or confirmation. Source/collection conflicts and combined
limits refuse the whole candidate. Unknown sections cannot be stripped.

Import review distinguishes incoming, previously saved and resulting
configuration. All labels, URLs, collections and preferences are inert text;
there are no fetch, activation or sign-in actions. Restored enabled preferences
are not permission. Default incoming-v3 admission and v3 export remain refused
until the supported consumer cohort qualifies. Keep original import files.

The existing custody FIFO serializes supported production mutations. Exact
stored ciphertext and revision are fenced before a single-record Chrome write.
A final synchronous epoch/cancellation check follows the last awaited read,
immediately before installing a preview or initiating storage. Confirmation also
rechecks expiry. A review cannot be revived after revocation during that read.
Chrome storage does not supply independent cross-context CAS; external writers
would require a new transaction design. An already initiated atomic write may
finish; this is not a promise to undo a committed record on cancellation.

## Evidence — 2026-11-14

Full npm tests:450 passed,4 opt-in skips, zero failures; full typecheck passes.
Six regressions were red before fixing the final-read revocation/cancellation
race and now pass. Independent re-review found no remaining concrete blocker.
[Source hashes and scope](feed-storage-evidence.json) accompany this increment.

Actual Chrome development acceptance passes12 checks: guarded refusal, inert
review/cancel, real QUOTA_BYTES write failure, commit, exact encrypted reload,
full browser restart/unlock, older/empty preservation, conflicts, account edits,
two-page stale actions and v3 export refusal. Three paused final-read cases send
the real REVOKE_ORIGIN message from another Wallet page before releasing the
storage read; no pending review or write escapes invalidation.

Positive v3 paths used a separate private development package with a one-line
in-memory guard override. Repository source never changed during browser tests;
only disposable synthetic profiles were used and removed. No HTTP feed request,
personal browser data, custody authority or installed extension was changed.
Timer expiry and injected preflight failures are deterministic adapter checks;
browser quota/restart/revocation checks are actual browser operations. Power-loss
or corruption during Chrome storage is not qualified by this result. Production
writer and cross-client/runtime release gates remain open.
