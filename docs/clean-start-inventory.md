# Clean-start inventory

Generated from the 2026-05-28 planning pass. Update this file after each setup task.

## Castalia Wallet

- Path: `/example/operator/repos/castalia-wallet`
- State before W0: absent
- W0 result: repo initialized on `main` with docs/scaffold only

## Dregg fork

- Target path: `/example/operator/repos/dregg`
- State before D0: absent
- D0 result: cloned successfully
- Origin: `git@github.com:bananawalnut/dregg.git`
- Upstream: `git@github.com:emberian/dregg.git`
- Local `main`: `6425a0b0ff0f817f3470761192448d0e301d06f8`
- Upstream `main`: `6425a0b0ff0f817f3470761192448d0e301d06f8`
- Divergence: fork `main` matches upstream `main` at D0
- Working tree after D0: clean

## Zenith Review SDK

- Path: `/example/operator/repos/zenith-review-sdk`
- Observed branch: `hermes/20260518-160607-review-audio-fallback`
- Pre-existing dirty state: `CHANGELOG.md`, `README.md`, `dist/index.d.ts`, `dist/index.js`, `package-lock.json`, `package.json`, `src/index.ts`, untracked `.hermes/`, untracked `tests/`
- Boundary: do not edit in place for wallet work; create an isolated worktree before S1.

## Downloaded Cipherclerk artifact

- Path: `/example/operator/Downloads/dregg-cipherclerk`
- Role: evidence/source material only; do not install as a personal wallet.
