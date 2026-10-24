# Matrix companion contract candidate

Shared typed Matrix companion contract and fixture host. Applications receive the read client; trusted Wallet UI alone receives the approval controller. The fixture transport uses synthetic state and is not a live Matrix implementation or encrypted production store. Importing this package does not authorize a connection or a send.

Source was reconciled from the existing Anima vendored candidate, retaining its strict TypeScript assertions. The earlier provisional 58dc0fd source reference did not contain this package; use a commit containing this package as the authoritative source. No runtime behavior is changed by the source relocation.
