# Shared read authority

Status: source candidate for the native Zenith read preview. No installed issuer
trust, membership, grant or custody is changed by this source update.

`castalia-wallet-presentation::read_authority` defines an application-neutral
issuer policy, signed read credential and holder presentation. The same source
is compiled into Wallet Rust/native/WASM and pinned into secS's standalone read
authority tool. Applications own permission names and constraint semantics.
There is no new generic arbitrary signing API exposed to pages.

Internal custody commands are `approve_read_credential`,
`store_read_credential`, `read_credential` and `sign_read_call`. Approval requires
an unlocked, backup-eligible wallet with active membership and an independently
configured issuer pin. Storage verifies the issuer signature, holder, device,
exact approved permissions and expiry before returning an existing transactional
custody candidate. Signing remains in Rust and creates a random per-read nonce.
Lock, cancellation and changed membership trust invalidate pending authority.
Changing trust clears saved read access. Exported recovery and Castaway files
contain no access credential or connection approval.

The new schemas/domains are `castalia.read-policy.v1`,
`castalia.read-credential.v1` and `castalia.read-presentation.v1`. Existing
request-credential v1 and credential-presentation v2 mutation contracts are not
modified or repurposed. Existing encrypted local snapshots without
`read_credentials` remain readable; this preview's new stored read field is not
understood by old cores, so disconnect before downgrading. The web portable
contract snapshots remain immutable; the web client does not consume this new
native read connection yet.

Policy lifetime is at most one hour. Per-call proofs are valid for less than 60
seconds. The secS host must check current trusted registry status and atomically
consume verified nonces before dispatch; signature verification alone is not
complete authorization. Renewal cannot create wider operator permission. No
Dregg self-attenuation or child delegation is claimed.
