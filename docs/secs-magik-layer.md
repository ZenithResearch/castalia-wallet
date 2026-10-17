# secS-magik layer

secS-magik is the later private-capability / zk-RPC layer. It is strategically connected to Castalia Wallet, but it is not implemented in Checkpoint A.

## Checkpoint A boundary

The first docs should prioritize Zenith as the initial Hub/auth surface. Moons can initially be treated as a Zenith member, but that creates a later credential migration problem. The smoother ideal is Gallery federation without launching the full Gallery Hub, if the credential model supports it.

Do not hard-code a Moons/Gallery federation example as if Gallery Hub already exists. Treat it as a future federation path and migration-risk note.

## Later private-call surfaces

Future work should distinguish:

- private paid remote LLM calls;
- private Ethereum RPC reads;
- private HubFS/state reads;
- delegated Hub actions;
- Hub-to-Hub private capability calls.
