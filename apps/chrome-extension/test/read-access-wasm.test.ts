import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  createPrivateKey,
  createPublicKey,
  createHash,
  sign,
  verify,
} from "node:crypto";
import test from "node:test";
import {
  initSync,
  WasmWallet,
} from "../src/generated/castalia-wallet-core/bindings.js";
import { CASTALIA_WALLET_CORE_WASM } from "../src/generated/castalia-wallet-core/wasm-bytes.js";
initSync({ module: CASTALIA_WALLET_CORE_WASM });
const custody = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/contracts/castalia-wallet-custody-v1.vector.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const encoder = new TextEncoder();
const issuer = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, 9),
  ]),
  format: "der",
  type: "pkcs8",
});
const issuerPublic = createPublicKey(issuer)
  .export({ format: "der", type: "spki" })
  .subarray(-32)
  .toString("hex");
function canonical(v: any): string {
  return v === null || typeof v !== "object"
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? `[${v.map(canonical).join(",")}]`
      : `{${Object.keys(v)
          .sort()
          .map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`)
          .join(",")}}`;
}
function opened() {
  const wallet = new WasmWallet();
  wallet.unlock(
    encoder.encode(JSON.stringify(custody.container)),
    custody.inputs.passphraseUnicode,
  );
  return wallet;
}
function fixture(wallet: WasmWallet) {
  const caller = { kind: "browser", id: "https://app.example.test" },
    policy = {
      schema: "castalia.read-policy.v1",
      issuer: "fixture",
      key_id: "test",
      public_key: issuerPublic,
      receiver: "https://server.example.test",
      audience: "example",
      max_lifetime_seconds: 600,
      permissions: [
        {
          operation: "example.list",
          resource: "https://server.example.test/work",
          constraints: { ids: ["one"] },
        },
      ],
    };
  const challenge = {
    schema: "castalia.read-access-challenge.v1",
    request_id: "33".repeat(16),
    nonce: "A".repeat(43),
    subject_public_key: wallet.publicKey(),
    installation_id: "22".repeat(16),
    issuer: "fixture",
    receiver: policy.receiver,
    issued_at: 100,
    expires_at: 220,
    credential_expires_at: 700,
    details: { authority_policy: policy },
  };
  const pins = [
    {
      issuer: policy.issuer,
      key_id: policy.key_id,
      public_key: policy.public_key,
      audience: policy.audience,
      callers: [caller],
    },
  ];
  const prepare = () =>
    wallet.prepareReadAccess(
      JSON.stringify(challenge),
      challenge.installation_id,
      JSON.stringify(pins),
      JSON.stringify(caller),
      "101",
    );
  const claims = {
    schema: "castalia.read-credential.v1",
    credential_id: "44".repeat(16),
    holder_public_key: wallet.publicKey(),
    installation_id: challenge.installation_id,
    issuer: policy.issuer,
    key_id: policy.key_id,
    receiver: policy.receiver,
    audience: policy.audience,
    policy_digest: createHash("sha256").update(canonical(policy)).digest("hex"),
    permissions: policy.permissions,
    issued_at: 103,
    expires_at: 700,
  };
  const credential = {
    claims,
    signature: sign(
      null,
      Buffer.concat([
        Buffer.from("castalia.read-credential.v1/signature\0"),
        Buffer.from(canonical(claims)),
      ]),
      issuer,
    ).toString("hex"),
  };
  return { prepare, credential, caller };
}
test("actual read WASM validates issuer, signs exact calls, rejects writes and clears on lock", () => {
  const wallet = opened(),
    f = fixture(wallet),
    handle = f.prepare();
  try {
    assert.equal(
      JSON.parse(handle.summary()).permissions[0].operation,
      "example.list",
    );
    wallet.approveReadAccess(handle, "102");
    const tampered = structuredClone(f.credential);
    tampered.claims.permissions[0].operation = "example.write";
    const bad = f.prepare();
    wallet.approveReadAccess(bad, "102");
    assert.throws(() =>
      wallet.acceptReadCredential(bad, JSON.stringify(tampered), "104"),
    );
    bad.free();
    wallet.acceptReadCredential(handle, JSON.stringify(f.credential), "104");
    const call = {
      operation: "example.list",
      resource: "https://server.example.test/work",
      parameters: { limit: 1 },
    };
    const result = JSON.parse(
      wallet.presentReadCall(handle, JSON.stringify(call), f.caller.id, "105"),
    );
    const key = createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(wallet.publicKey(), "hex"),
      ]),
      format: "der",
      type: "spki",
    });
    const proof = { ...result.proof };
    delete proof.signature;
    assert.equal(
      verify(
        null,
        Buffer.concat([
          Buffer.from("castalia.read-presentation.v1/signature\0"),
          Buffer.from(canonical(proof)),
        ]),
        key,
        Buffer.from(result.proof.signature, "hex"),
      ),
      true,
    );
    assert.throws(() =>
      wallet.presentReadCall(
        handle,
        JSON.stringify({ ...call, operation: "example.write" }),
        f.caller.id,
        "105",
      ),
    );
    assert.throws(() =>
      wallet.presentReadCall(
        handle,
        JSON.stringify(call),
        "https://other.example.test",
        "105",
      ),
    );
    wallet.lock();
    wallet.unlock(
      encoder.encode(JSON.stringify(custody.container)),
      custody.inputs.passphraseUnicode,
    );
    assert.throws(() =>
      wallet.presentReadCall(handle, JSON.stringify(call), f.caller.id, "106"),
    );
  } finally {
    handle.free();
    wallet.lock();
    wallet.free();
  }
});
