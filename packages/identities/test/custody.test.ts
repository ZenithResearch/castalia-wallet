import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { IDBFactory } from "fake-indexeddb";
import {
  IdentityDatabase,
  emptyIdentityDatabase,
  indexedDbIdentityStore,
  migrateIdentityReceiptReferences,
  type IdentityRecords,
  type IdentityCipher,
} from "../src/index.js";

// Exercise the shared core built from this exact producer revision.
const generated = fileURLToPath(new URL("../../../apps/chrome-extension/src/generated/castalia-wallet-core", import.meta.url));
async function runtime() {
  const mod = await import(
    pathToFileURL(resolve(generated, "castalia_wallet_core.js")).href
  );
  mod.initSync({
    module: readFileSync(resolve(generated, "castalia_wallet_core_bg.wasm")),
  });
  const wallet = new mod.WebWalletCustody();
  wallet.create("ephemeral custody regression", 1n);
  const cipher: IdentityCipher = {
    async sealIdentitySection(s) {
      return wallet.sealIdentitySection(s);
    },
    async openIdentitySection(s) {
      return wallet.openIdentitySection(new TextEncoder().encode(s));
    },
  };
  return { wallet, cipher, owner: wallet.publicKey() as string };
}
function records(
  owner: string,
  budget: number,
  character = "a",
): IdentityRecords {
  const data = emptyIdentityDatabase(owner);
  const display = () => {
    const size = Math.min(255, budget);
    budget -= size;
    return "n" + character.repeat(size);
  };
  for (let n = 1; n <= 1000; n++) {
    data.accounts.push({
      id: "account-" + n,
      identityId: owner,
      provider: "x",
      subjectId: String(n),
      displayName: display(),
      linkedAt: 1,
    });
    data.resources.push({
      id: "resource-" + n,
      provider: "github",
      kind: "repository",
      providerResourceId: String(n),
      displayName: display(),
    });
  }
  for (let n = 1; n <= 100; n++)
    data.attestations.push({
      id: "attestation-" + n,
      accountId: "account-" + n,
      relationshipId: null,
      issuer: "01".repeat(32),
      evidenceDigest: "02".repeat(32),
      issuedAt: 1,
      expiresAt: 2,
    });
  return data;
}
const byteLength = (s: string) => new TextEncoder().encode(s).length;
test("actual custody: v2 service receipt snapshots survive recovery with unchanged keys", async () => {
  for (const character of ["a", "界"]) {
    const { wallet, cipher, owner } = await runtime();
    try {
      const recovery = wallet.recoveryKey();
      const accounts = wallet.chainAccounts();
      const data = migrateIdentityReceiptReferences(
        records(owner, 80000, character),
        owner,
      );
      data.receipts.push({
        id: "service",
        accountId: "account-1",
        offerId: owner,
        network: "solana:devnet",
        authorizationDigest: owner,
        receiptReference: {
          schema: "wallet.reward-receipt-reference.v1",
          kind: "service-v1",
          digest: owner,
        },
        transaction: "synthetic-public-reference",
        status: "submitted",
        observedAt: 2,
      });
      const store = indexedDbIdentityStore(owner, new IDBFactory());
      const db = new IdentityDatabase(owner, store, cipher);
      await db.unlock();
      await db.import(data);
      db.lock();
      wallet.lock();
      wallet.restoreFromRecoveryKey(
        recovery,
        "ephemeral restored regression",
        2n,
      );
      assert.equal(wallet.publicKey(), owner);
      assert.equal(wallet.chainAccounts(), accounts);
      const reopened = new IdentityDatabase(owner, store, cipher);
      await reopened.unlock();
      assert.deepEqual(reopened.snapshot(), data);
    } finally {
      wallet.free();
    }
  }
});
test("actual custody: ASCII envelope boundary is checked before commit; lock/reload keeps the previous snapshot", async () => {
  const { wallet, cipher, owner } = await runtime();
  try {
    const store = indexedDbIdentityStore(owner, new IDBFactory()),
      db = new IdentityDatabase(owner, store, cipher);
    await db.unlock();
    await db.update(() => {});
    let lo = 0,
      hi = 510000;
    const envelope = async (budget: number) =>
      cipher.sealIdentitySection(
        JSON.stringify({
          schema: "castalia.identity-snapshot.v1",
          revision: 2,
          records: records(owner, budget),
        }),
      );
    const fits = async (budget: number) => {
      try {
        return byteLength(await envelope(budget)) <= 1048576;
      } catch (error) {
        if (!String(error).includes("invalid_wallet_file")) throw error;
        return false;
      }
    };
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      if (await fits(mid)) lo = mid;
      else hi = mid - 1;
    }
    const good = records(owner, lo),
      bad = records(owner, lo + 1);
    assert.ok(byteLength(await envelope(lo)) <= 1048576);
    assert.equal(await fits(lo + 1), false);
    await db.import(good);
    const before = await store.read();
    db.lock();
    const reloaded = new IdentityDatabase(owner, store, cipher);
    await reloaded.unlock();
    assert.equal(reloaded.snapshot().accounts.length, 1000);
    await assert.rejects(
      reloaded.update((draft) => Object.assign(draft, bad)),
      (error) =>
        /identity_envelope_too_large|invalid_wallet_file/.test(String(error)),
    );
    assert.deepEqual(await store.read(), before);
    reloaded.lock();
    await reloaded.unlock();
    assert.deepEqual(reloaded.snapshot(), good);
  } finally {
    wallet.free();
  }
});
test("actual custody: UTF-8 Unicode limits and unreadable cipher output preserve the last snapshot", async () => {
  const { wallet, cipher, owner } = await runtime();
  try {
    const store = indexedDbIdentityStore(owner, new IDBFactory()),
      db = new IdentityDatabase(owner, store, cipher);
    await db.unlock();
    const good = records(owner, 100000, "界");
    await db.import(good);
    const before = await store.read();
    db.lock();
    await db.unlock();
    assert.deepEqual(db.snapshot(), good);
    const oversized = records(owner, 300000, "界");
    assert.ok(JSON.stringify(oversized).length < 1048576);
    assert.ok(byteLength(JSON.stringify(oversized)) > 1048576);
    await assert.rejects(
      db.update((draft) => Object.assign(draft, oversized)),
      /identity_plaintext_too_large/,
    );
    assert.deepEqual(await store.read(), before);
    const unreadable = new IdentityDatabase(owner, store, {
      ...cipher,
      async sealIdentitySection() {
        return "unreadable envelope";
      },
    });
    await unreadable.unlock();
    await assert.rejects(unreadable.update(() => {}));
    assert.deepEqual(await store.read(), before);
    const wrong = new IdentityDatabase(owner, store, {
      ...cipher,
      async sealIdentitySection(s) {
        const value = JSON.parse(s);
        value.records.accounts[0].displayName = "substituted";
        return cipher.sealIdentitySection(JSON.stringify(value));
      },
    });
    await wrong.unlock();
    await assert.rejects(
      wrong.update(() => {}),
      /identity_roundtrip_mismatch/,
    );
    assert.deepEqual(await store.read(), before);
  } finally {
    wallet.free();
  }
});
