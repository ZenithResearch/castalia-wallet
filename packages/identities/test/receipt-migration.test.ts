import test from "node:test";
import assert from "node:assert/strict";
import {
  emptyIdentityDatabase,
  parseIdentityDatabase,
  migrateIdentityReceiptReferences,
  IdentityDatabase,
  type EncryptedSnapshot,
} from "../src/index.js";
const owner = "01".repeat(32);
function legacy() {
  const d = emptyIdentityDatabase(owner);
  d.accounts.push({
    id: "a",
    identityId: owner,
    provider: "github",
    subjectId: "7",
    displayName: "creator",
    linkedAt: 1,
  });
  d.receipts.push({
    id: "r",
    accountId: "a",
    offerId: owner,
    network: "solana:devnet",
    authorizationDigest: owner,
    dreggReceiptHash: owner,
    transaction: "historical-transaction",
    status: "finalized",
    observedAt: 2,
  });
  return d;
}
test("identity v2 migration preserves historical evidence and distinguishes service commitments", () => {
  const v1 = legacy(),
    v2 = migrateIdentityReceiptReferences(v1, owner);
  assert.equal(v1.version, 1);
  assert.equal(v2.version, 2);
  assert.deepEqual(v2.receipts[0]?.receiptReference, {
    schema: "wallet.reward-receipt-reference.v1",
    kind: "dregg-native",
    digest: owner,
  });
  v2.receipts.push({
    ...v2.receipts[0]!,
    id: "s",
    receiptReference: {
      schema: "wallet.reward-receipt-reference.v1",
      kind: "service-v1",
      digest: "02".repeat(32),
    },
  });
  assert.deepEqual(parseIdentityDatabase(v2, owner), v2);
  for (const change of [
    (d: any) => (d.receipts[1].dreggReceiptHash = owner),
    (d: any) => (d.receipts[1].receiptReference.signature = "secret"),
    (d: any) => (d.receipts[1].receiptReference.kind = "native"),
    (d: any) => (d.version = 3),
  ]) {
    const b = structuredClone(v2);
    change(b);
    assert.throws(() => parseIdentityDatabase(b, owner));
  }
});
test("v1 import merges into v2 without losing historical records across lock/reload", async () => {
  let saved: EncryptedSnapshot | null = null;
  const store = {
    async read() {
      return saved;
    },
    async compareAndSwap(revision: number, next: EncryptedSnapshot) {
      assert.equal(saved?.revision ?? 0, revision);
      saved = next;
    },
  };
  // Cipher transport is exercised with real Wasm by the separate custody suite.
  const cipher = {
    async sealIdentitySection(s: string) {
      return JSON.stringify({ encoded: s });
    },
    async openIdentitySection(s: string) {
      return JSON.parse(s).encoded;
    },
  };
  const db = new IdentityDatabase(owner, store, cipher);
  await db.unlock();
  await db.import(legacy());
  await db.import(migrateIdentityReceiptReferences(legacy(), owner));
  assert.equal(db.snapshot().version, 2);
  db.lock();
  await db.unlock();
  await db.import(legacy());
  assert.equal(db.snapshot().receipts.length, 1);
  const before = saved;
  await assert.rejects(db.import({ ...db.snapshot(), version: 99 }));
  assert.deepEqual(saved, before);
});
