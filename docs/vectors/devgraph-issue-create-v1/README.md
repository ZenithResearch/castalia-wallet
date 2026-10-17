# `devgraph.issue.create.v1` DG-W vectors

These three files are byte-identical copies of Devgraph's authoritative DG-V
fixtures at merge `2ba578fe05855e983e04bc10d766d2fff8b12319`, under
`tests/fixtures/secs_devgraph_issue_create_v1/`:

| File | SHA-256 |
| --- | --- |
| `request.json` | `81ab8aff8d053b90303b57d9ba868168426829dd1fcaa510183c6bc4f03fc608` |
| `idempotency-key.txt` | `a87f1c2a1db5f4941e41e77cdb6d04989da7dcd52bab41acded33fe3815d371a` |
| `wallet-presentation.json` | `35333326f0aa8af0b227beda4298c2a537fb2f29176016f3b2bed5b262e0ab9c` |

The key and presentation are test fixtures only. No production seed or
credential is present. Contract changes require a new version and synchronized
secS, Devgraph, and Wallet vectors; v1 must not be silently reinterpreted.
