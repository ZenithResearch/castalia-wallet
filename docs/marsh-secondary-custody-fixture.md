# Disposable Marsh secondary custody check

Two fresh Castalia Wallet roots, C and R, occupy separate sessions and storage slots. A test-only guard restores R's encrypted backup into an empty third slot only after the exact staged root and Cardano funding descriptor match the independently recorded R identity. C's original encrypted snapshot stays byte-identical at revision one and unlocks again. The test uses a synthetic testnet with magic 2 and a 32-byte genesis hash of repeated `12`. [Integration test](../crates/castalia-wallet-core/tests/marsh_recovery_custody.rs)

## What was checked

| Case | Observation |
| --- | --- |
| Independent restore | C and R have distinct public root keys and Cardano payment-key hashes. R's recovered descriptor equals the recorded descriptor field for field. A fresh session opens the persisted recovery snapshot with the destination password and reports inactive membership. |
| Controller re-export | Two randomized encrypted exports of C differ. Ordinary recovery accepts C's own backup in its own fresh slot. The secondary-role guard refuses both exports because they recover C. |
| Substitutions | A valid backup for a third fresh Wallet passes stock staging and fails the secondary-descriptor check. Wrong network magic and wrong genesis each keep the Cardano address and payment credential unchanged while failing full descriptor equality. A wrong password, modified ciphertext and actual data-only Castaway export fail stock recovery. The destination remains absent and no failed candidate can commit. |
| Conflicting writes | A controller-slot alias, stale initial revision, incorrect pending token and incorrect commit revision all refuse. Cancelling a staged import leaves the slot empty. Two independently valid previews for the same empty destination yield different encrypted snapshots. One installs; the other receives an occupied-slot error and cannot reconcile against that winner. |
| Lost confirmation | After installation the first session still reports unconfigured. It reads back the exact winner and confirms with its original pending token and bytes. This performs no second write. A repeated confirmation fails. The controller record and its funding descriptor remain intact. |

The stock APIs split these checks. `PrepareRestore` authenticates the encrypted portable file, requires an empty session at the expected revision and creates a pending candidate. The generic chain-account preview does not supply the admitted funding network. The harness obtains the exact encrypted snapshot from `CommitCandidate` and uses the stock Wallet import and Cardano funding-account methods on its custody field with the destination password. It compares the imported root to the preview and the independently recorded secondary identity, checks independence from C, and compares the complete typed funding descriptor. Only a matching candidate reaches storage. [Stock recovery protocol](native-recovery-session.md) · [Funding descriptor](../crates/castalia-wallet-core/src/cardano_account.rs)

The Unix fixture owns a fresh mode-0700 directory and fixed child paths. It writes a complete mode-0600 temporary snapshot, syncs the file and installs it with an atomic, no-overwrite hard link. `ConfirmCommit` follows exact slot readback. The two writers exercise an empty-slot compare-and-set at revision zero. The lost acknowledgement is injected inside the test process. Power-loss recovery, directory durability, arbitrary path aliases, installed-app storage, and general multi-revision updates remain outside this evidence. Temporary encrypted material is removed on normal exit. Public run observations contain only synthetic funding descriptors.

## Captured public comparison

The author run on Wallet source `0c5f7bae8d21496234e5702872c8dfbf3639887b` passed both tests in 65.91 seconds. Each account has schema `castalia.cardano-funding-account.v1`, descriptor-only authority, Ed25519 account index 0, and the same synthetic funding network. The secondary rows below refer to separate original and recovered stores.

| Wallet state | Public payment-key hash | Public enterprise address |
| --- | --- | --- |
| Original controller | `dc568b160305bdb3f7fd59c85f9409913d42b253da5bbbafee945ca0` | `addr_test1vrw9dzckqvzmmvlhl4vushu5pxgn6s4j20d9hwa0a629egqzw3w57` |
| Recorded secondary | `e85e546c0a5805d40329a5cdd74b676a5e795159ac6cdf9eaa0aecca` | `addr_test1vr59u4rvpfvqt4qr9xjum46tva49u723txkxehu74g9wejscrfgke` |
| Recovered secondary | `e85e546c0a5805d40329a5cdd74b676a5e795159ac6cdf9eaa0aecca` | `addr_test1vr59u4rvpfvqt4qr9xjum46tva49u723txkxehu74g9wejscrfgke` |

## Reproduction

Run from the Wallet checkout. Each run generates new roots and randomized ciphertext. The qualified invariants are the equality, refusal and isolation outcomes. Use `--nocapture` to display the compared public descriptors.

```sh
cargo test --locked --offline -p castalia-wallet-core --features funding-fixtures --test marsh_recovery_custody -- --test-threads=1 --nocapture
```

The first macOS debug run exhausted the stock test-worker stack before writing any encrypted record. The integration tests now run the stock dispatcher on a 16 MiB worker stack. The existing feed-storage tests also size their worker stack explicitly. This is a test configuration on the measured host. [Worker precedent](../crates/castalia-wallet-core/tests/feed_storage.rs)

This evidence covers the credential and storage comparisons in AD-CUSTODY-01 through AD-CUSTODY-04. It uses production library methods on disposable fixtures. It does not qualify a recovered-key spending signature, an on-ledger Marsh installation, controller replacement, real Wallet custody, or saved-account consent. Current Marsh state, authority transitions and original-body approval remain separate A6/O2/W6 work.
