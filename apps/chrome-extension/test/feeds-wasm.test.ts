import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import {
  initSync,
  WasmWallet,
} from "../src/generated/castalia-wallet-core/bindings.js";
import { CASTALIA_WALLET_CORE_WASM } from "../src/generated/castalia-wallet-core/wasm-bytes.js";

import {
  initSync as initWebSync,
  WebWalletCustody,
} from "../src/generated/castalia-wallet-core/castalia_wallet_core.js";

initSync({ module: CASTALIA_WALLET_CORE_WASM });
initWebSync({ module: CASTALIA_WALLET_CORE_WASM });
const encoder = new TextEncoder();
const custody = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/contracts/castalia-wallet-custody-v1.vector.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const corpus = JSON.parse(
  readFileSync(
    new URL("../../../contracts/feeds/v1/conformance.json", import.meta.url),
    "utf8",
  ),
) as { cases: { id: string; valid: boolean; raw: string }[] };
function identity(owner: string) {
  return {
    schema: "zenith.identity-section.v1",
    version: 1,
    subject: {
      type: "Person",
      memberKey: owner,
      fields: Object.fromEntries(
        [
          "displayName",
          "givenName",
          "familyName",
          "headline",
          "biography",
          "website",
          "orcid",
        ].map((name) => [name, { value: "", disclosure: "private" }]),
      ),
      roles: [],
      affiliations: [],
      journals: [],
    },
    updatedAt: 0,
  };
}
function opened() {
  const core = new WasmWallet();
  core.unlock(
    encoder.encode(JSON.stringify(custody.container)),
    custody.inputs.passphraseUnicode,
  );
  return core;
}
test("actual rebuilt WASM agrees on every raw feed vector without enabling a writer", () => {
  const core = opened(),
    profile = identity(core.publicKey());
  try {
    assert.equal(corpus.cases.length, 102);
    for (const vector of corpus.cases) {
      const raw =
        '{"schema":"castalia.castaway-contents.v3","version":3,"sections":{"identity":' +
        JSON.stringify(profile) +
        ',"feeds":' +
        vector.raw +
        "}}";
      if (vector.valid) {
        const validated = JSON.parse(core.validateCastawayDescriptors(raw));
        assert.equal(validated.version, 3, vector.id);
        assert.deepEqual(
          validated.sections.feeds,
          JSON.parse(vector.raw),
          vector.id,
        );
      } else
        assert.throws(
          () => core.validateCastawayDescriptors(raw),
          undefined,
          vector.id,
        );
    }
    const feeds = JSON.parse(
      corpus.cases.find((vector) => vector.id === "one-public-source")!.raw,
    );
    const contents = {
      schema: "castalia.castaway-contents.v3",
      version: 3,
      sections: { identity: profile, feeds },
    };
    assert.throws(
      () =>
        core.exportCastaway(JSON.stringify(contents), "backup password", 1n),
      /feed_writer_not_qualified/,
    );
    assert.equal(core.publicKey(), profile.subject.memberKey);
  } finally {
    core.lock();
    core.free();
  }
});
test("actual rebuilt WASM retains legacy v1 and v2 encrypted round trips", () => {
  const core = opened(),
    owner = core.publicKey();
  try {
    for (const version of [1, 2]) {
      const contents = {
        schema: "castalia.castaway-contents.v" + version,
        version,
        sections: {
          identity: identity(owner),
          ...(version === 2
            ? {
                walletIdentities: {
                  schema: "castalia.wallet-identities.v1",
                  version: 1,
                  ownerMemberKey: owner,
                  authority: "descriptor-only",
                  accounts: [],
                },
              }
            : {}),
        },
      };
      const validated = JSON.parse(
        core.validateCastawayDescriptors(JSON.stringify(contents)),
      );
      assert.deepEqual(validated, contents);
      const file = core.exportCastaway(
        JSON.stringify(contents),
        "backup password",
        1n,
      );
      assert.equal(JSON.parse(file).schema, "castalia.castaway.v" + version);
      assert.deepEqual(
        JSON.parse(
          core.importCastaway(encoder.encode(file), "backup password"),
        ),
        contents,
      );
    }
  } finally {
    core.lock();
    core.free();
  }
});

test("actual WASM preflights both host adapters without enabling v3 export", () => {
  for (const Core of [WasmWallet, WebWalletCustody]) {
    const core = new Core();
    core.unlock(
      encoder.encode(JSON.stringify(custody.container)),
      custody.inputs.passphraseUnicode,
    );
    const owner = core.publicKey();
    const preflight = (raw: string): number =>
      (
        core as unknown as { preflightCastawayDescriptors(raw: string): number }
      ).preflightCastawayDescriptors(raw);
    try {
      for (const vector of corpus.cases) {
        const raw =
          '{"schema":"castalia.castaway-contents.v3","version":3,"sections":{"identity":' +
          JSON.stringify(identity(owner)) +
          ',"feeds":' +
          vector.raw +
          "}}";
        if (vector.valid) {
          const size = preflight(raw);
          assert.ok(
            Number.isSafeInteger(size) &&
              size > encoder.encode(JSON.stringify(JSON.parse(raw))).length &&
              size <= 1_048_576,
            vector.id,
          );
          assert.throws(
            () => core.exportCastaway(raw, "backup password", 1n),
            /feed_writer_not_qualified/,
          );
        } else assert.throws(() => preflight(raw), undefined, vector.id);
      }
      const legacy = {
        schema: "castalia.castaway-contents.v1",
        version: 1,
        sections: { identity: identity(owner) },
      };
      const raw = JSON.stringify(legacy);
      const file = core.exportCastaway(
        raw,
        "backup password",
        9_007_199_254_740_991n,
      );
      assert.equal(preflight(raw), encoder.encode(file).length);
      const wrong = structuredClone(legacy);
      wrong.sections.identity.subject.memberKey = "ff".repeat(32);
      assert.throws(() => preflight(JSON.stringify(wrong)));
      const duplicate = raw.replace('"version":1', '"version":1,"version":1');
      assert.throws(() => preflight(duplicate));
      core.lock();
      assert.throws(() => preflight(raw));
    } finally {
      core.lock();
      core.free();
    }
  }
});

test("both actual WASM adapters decrypt independent synthetic v3 envelopes", () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL("../../../contracts/feeds/v1/encrypted-v3.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(fixture.cases.length, 8);
  assert.equal(
    fixture.cases.filter((v: { valid: boolean }) => v.valid).length,
    3,
  );
  for (const Core of [WasmWallet, WebWalletCustody]) {
    const core = new Core();
    core.unlock(
      encoder.encode(fixture.inputs.custodyFile),
      fixture.inputs.custodyPassword,
    );
    const owner = core.publicKey();
    try {
      for (const vector of fixture.cases) {
        if (vector.valid) {
          const opened = core.importCastaway(
            encoder.encode(vector.envelope),
            fixture.inputs.dataPassword,
          );
          assert.deepEqual(
            JSON.parse(opened),
            JSON.parse(vector.contentsRaw),
            vector.id,
          );
          assert.throws(
            () => core.exportCastaway(opened, fixture.inputs.dataPassword, 1n),
            /feed_writer_not_qualified/,
          );
        } else
          assert.throws(
            () =>
              core.importCastaway(
                encoder.encode(vector.envelope),
                fixture.inputs.dataPassword,
              ),
            undefined,
            vector.id,
          );
      }
      assert.throws(() =>
        core.importCastaway(
          encoder.encode(fixture.cases[0].envelope),
          "wrong fixture password",
        ),
      );
      assert.equal(core.publicKey(), owner);
    } finally {
      core.lock();
      core.free();
    }
  }
});
