# Operator consent budget

`castalia.access-request-challenge.v1` keeps its existing wire shape and signing
transcript. Operator inbox/review/decision envelopes now permit 128 KiB of JSON
so exact hierarchy scopes can repeat across permissions. Member request/status
envelopes remain limited to 16 KiB; depth, canonical JSON, issuer/caller, holder,
installation, operation and 120-second expiry checks are unchanged.

This is an additive capacity change. Older signers reject larger envelopes;
matched native and Chrome builds are required for them. Stored Wallet snapshots,
credential formats, grant scope and onward delegation do not change.
