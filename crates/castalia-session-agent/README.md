# Ephemeral session custody helper

Developer qualification primitive, not a membership Wallet, account backup or
production isolation boundary. `SessionKey` generates a fresh finite Ed25519 key
inside this Rust child. There is no seed import/export, arbitrary-sign command or
owner signing interface. Existing Wallet stores and signed formats are unchanged.

Build with `cargo build -p castalia-session-agent --locked`, then launch only from
a configured private broker using `--profile-file <absolute-owner-private-file>`.
The profile schema is `castalia.session-agent-profile.v1`: trusted secS provider
pin, receiver pin and `maximum_session_seconds` (60–86400). No secret is required
in the profile. Provider issuer/key/public-key pins must match the receiver pins.

Sequential inherited NDJSON commands use `castalia.session-agent-command.v1`,
32-lowercase-hex `request_id` and a closed `body`. Operations: `create_session`,
`approve_member_request`, `approve_enrollment`, `install_grant`, `present_call`,
`close_session`. Frames are capped at 131072 bytes. Up to eight active identities
and 256 retained successful command outcomes are supported; exact retries recover
original results, conflicting IDs and exhausted capacity fail closed.

Member consent supports existing access request/status only. Enrollment proves
possession of the session key, not authority. Installing a native-verified secS v2
root requires the exact reviewed expiry/permissions, same holder/installation
and configured provider. Equal root reinstall is idempotent; a different root
cannot replace it. Presentations derive same-holder, equal-scope credentials of
at most 60 seconds, bounded by the approved root. Onward delegation is disabled.
The provider must verify current policy/revocation/replay and actual resource
selectors, including paired effects transactionally; the helper is not a graph.

The private response can include roots and proofs. Never expose this wire
directly as MCP. A model-facing broker returns opaque handles and business data.
Keys disappear on close/process exit; there is no restart/recreation recovery.
Closing does not revoke a server-side root. A same-UID inherited-pipe process is
not the authenticated XPC signer boundary and must not be described as one.
