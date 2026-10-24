import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { IDBFactory } from "fake-indexeddb";
import {
  IdentityDatabase,
  indexedDbIdentityStore,
  emptyIdentityDatabase,
  parseIdentityDatabase,
  type EncryptedSnapshot,
  type SnapshotStore,
  type IdentityCipher,
} from "../src/index.js";

const owner = "01".repeat(32);
class Store implements SnapshotStore {
  snapshot: EncryptedSnapshot | null = null;
  async read() {
    return structuredClone(this.snapshot);
  }
  async compareAndSwap(expected: number, next: EncryptedSnapshot) {
    if ((this.snapshot?.revision ?? 0) !== expected)
      throw new Error("revision_conflict");
    this.snapshot = structuredClone(next);
  }
}
async function cipher(): Promise<IdentityCipher> {
  const key = await webcrypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return {
    async sealIdentitySection(value) {
      const iv = webcrypto.getRandomValues(new Uint8Array(12));
      const encrypted = await webcrypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        Buffer.from(value),
      );
      return Buffer.concat([iv, Buffer.from(encrypted)]).toString("base64");
    },
    async openIdentitySection(value) {
      const bytes = Buffer.from(value, "base64");
      return Buffer.from(
        await webcrypto.subtle.decrypt(
          { name: "AES-GCM", iv: bytes.subarray(0, 12) },
          key,
          bytes.subarray(12),
        ),
      ).toString();
    },
  };
}
test("encrypted persistence, lock and unlock preserve distinct stable identities", async () => {
  const store = new Store(),
    crypto = await cipher(),
    db = new IdentityDatabase(owner, store, crypto);
  await db.unlock();
  await db.update((data) => {
    data.accounts.push({
      id: "a1",
      identityId: owner,
      provider: "x",
      subjectId: "123",
      displayName: "same",
      linkedAt: 1,
    });
    data.accounts.push({
      id: "a2",
      identityId: owner,
      provider: "x",
      subjectId: "124",
      displayName: "same",
      linkedAt: 1,
    });
  });
  assert.equal(JSON.stringify(store.snapshot).includes("same"), false);
  assert.equal(db.snapshot().accounts.length, 2);
  db.lock();
  assert.throws(() => db.snapshot(), /locked/);
  await db.unlock();
  assert.equal(db.snapshot().accounts[0]?.subjectId, "123");
});
test("concurrent snapshots refuse lost updates", async () => {
  const store = new Store(),
    crypto = await cipher();
  const a = new IdentityDatabase(owner, store, crypto),
    b = new IdentityDatabase(owner, store, crypto);
  await a.unlock();
  await b.unlock();
  await a.update(() => {});
  await assert.rejects(
    b.update(() => {}),
    /revision_conflict/,
  );
});
test("malformed imports, wrong owners, secrets and unsupported versions do not overwrite data", async () => {
  const store = new Store(),
    db = new IdentityDatabase(owner, store, await cipher());
  await db.unlock();
  await db.update(() => {});
  const before = structuredClone(store.snapshot);
  for (const patch of [
    { version: 2 },
    { ownerPublicKey: "ff".repeat(32) },
    { accessToken: "secret" },
  ]) {
    await assert.rejects(
      db.import({ ...emptyIdentityDatabase(owner), ...patch }),
    );
    assert.deepEqual(store.snapshot, before);
  }
});
test("foreign keys, duplicate provider subjects and admin relationships are rejected", () => {
  const data = emptyIdentityDatabase(owner);
  data.accounts.push({
    id: "a",
    identityId: owner,
    provider: "github",
    subjectId: "7",
    displayName: "one",
    linkedAt: 1,
  });
  data.accounts.push({ ...data.accounts[0]!, id: "b" });
  assert.throws(() => parseIdentityDatabase(data, owner), /duplicate/);
  data.accounts.pop();
  data.relationships.push({
    id: "r",
    accountId: "a",
    resourceId: "missing",
    relationship: "personal_owner",
    observedAt: 1,
  });
  assert.throws(() => parseIdentityDatabase(data, owner), /foreign_key/);
});
test("lock during encryption aborts persistence", async () => {
  const store = new Store(),
    underlying = await cipher();
  let db: IdentityDatabase;
  const crypto: IdentityCipher = {
    ...underlying,
    async sealIdentitySection(value) {
      db.lock();
      return underlying.sealIdentitySection(value);
    },
  };
  db = new IdentityDatabase(owner, store, crypto);
  await db.unlock();
  await assert.rejects(
    db.update(() => {}),
    /locked/,
  );
  assert.equal(store.snapshot, null);
});
test("IndexedDB commits encrypted snapshots, survives reopening and rejects cross-tab lost updates", async () => {
  const factory = new IDBFactory(),
    crypto = await cipher();
  const store = indexedDbIdentityStore(owner, factory);
  const first = new IdentityDatabase(owner, store, crypto);
  await first.unlock();
  await first.update((data) =>
    data.accounts.push({
      id: "a",
      identityId: owner,
      provider: "x",
      subjectId: "123",
      displayName: "creator",
      linkedAt: 1,
    }),
  );
  first.lock();
  const persisted = await store.read();
  assert.equal(JSON.stringify(persisted).includes("creator"), false);
  const second = new IdentityDatabase(
    owner,
    indexedDbIdentityStore(owner, factory),
    crypto,
  );
  await second.unlock();
  await first.unlock();
  assert.equal(second.snapshot().accounts[0]?.subjectId, "123");
  const writes = await Promise.allSettled([
    first.update(() => {}),
    second.update(() => {}),
  ]);
  assert.equal(
    writes.filter((result) => result.status === "fulfilled").length,
    1,
  );
  assert.equal((await store.read())?.revision, 2);
});
test("disconnect and import preserve payout history without trusting imported finality", async () => {
  const db = new IdentityDatabase(owner, new Store(), await cipher());
  await db.unlock();
  await db.update((data) => {
    data.accounts.push({
      id: "a",
      identityId: owner,
      provider: "x",
      subjectId: "123",
      displayName: "creator",
      linkedAt: 1,
    });
    data.receipts.push({
      id: "receipt",
      accountId: "a",
      offerId: owner,
      network: "solana:devnet",
      authorizationDigest: owner,
      dreggReceiptHash: owner,
      transaction: "public-reference",
      status: "finalized",
      observedAt: 2,
    });
  });
  await db.disconnect("a", 3);
  await db.import(emptyIdentityDatabase(owner));
  assert.equal(db.snapshot().receipts.length, 1);
  assert.equal(db.snapshot().accounts[0]?.disconnectedAt, 3);
});
test("imports compare record values, not JSON property order", async () => {
  const db = new IdentityDatabase(owner, new Store(), await cipher());
  await db.unlock();
  const data = emptyIdentityDatabase(owner);
  data.identities = [{ publicKey: owner, id: owner }];
  await db.import(data);
  assert.equal(db.snapshot().identities.length, 1);
});
