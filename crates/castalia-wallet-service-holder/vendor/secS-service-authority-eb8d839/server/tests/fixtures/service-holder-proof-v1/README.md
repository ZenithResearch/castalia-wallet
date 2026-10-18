# Public disposable service holder vectors

Fixture-only, not installed trust or qualification. Root binaries are Runtime; service/ binaries use the explicitly allocated synthetic Service opcode0x79. Both sets contain exact challenge, compact proof, signed transcripts, Packetv0 and public verifier/holder keys. No private key bytes are exported. Deterministic disposable signing seeds exist only in cfg(test) source; no library signing oracle is shipped.

bundle-vectors.json has independent Python hashlib/struct canonical public-bundle preimages and SHA256 values. Its static reader source hash pins the reviewed reader in addition to exact schema hashes. manifest.json records binary/vector bytes and digests, including that independent vector file.

Ordinary tests only read and compare these files. Deliberate test-only refresh: UPDATE_SERVICE_HOLDER_VECTORS=1 cargo +1.96.0 test --locked --offline -p server service_holder_public_deterministic_vectors_match --lib. Schema/static-reader changes also require independent public-bundle preimage refresh, review and release expectation changes. Never admit these synthetic registries/descriptors/evidence as live authority.
