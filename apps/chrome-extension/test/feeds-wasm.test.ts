import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import {
  initSync,
  WasmWallet,
} from "../src/generated/castalia-wallet-core/bindings.js";
import { CASTALIA_WALLET_CORE_WASM } from "../src/generated/castalia-wallet-core/wasm-bytes.js";

initSync({ module: CASTALIA_WALLET_CORE_WASM });
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
