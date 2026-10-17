# Review SDK integration boundary

Checkpoint A requires the current Zenith Review/Auth SDK path to request and verify a Castalia Wallet possession proof. The existing Review SDK repo has pre-existing dirty review-audio-fallback work and must not be edited in place for wallet work.

## Source repo

- Dirty worktree: `/example/operator/repos/zenith-review-sdk`
- Branch: `hermes/20260518-160607-review-audio-fallback`
- Baseline HEAD observed for wallet isolation: `ab30a6c`
- Pre-existing dirty files remain in the original worktree and are excluded from wallet work.

## Isolated wallet worktree

- Worktree: `/example/operator/repos/zenith-review-sdk-castalia-wallet`
- Branch: `hermes/20260528-154409-castalia-wallet`
- Initial status after creation: clean
- S1 result: committed `5657dc5 feat: add Castalia wallet auth seam`
- Verification: `npm test`, `npm run typecheck`, and `npm run build` pass in the isolated worktree

## Implementation rule

Any S1 wallet-auth seam must be implemented only in the isolated worktree or another clean worktree. Checkpoint A is not green until the Review/Auth SDK path can request and verify a Castalia Wallet `signChallenge` presentation, or the remaining SDK work is listed as an explicit blocker.
