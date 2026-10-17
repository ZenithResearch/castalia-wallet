import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const claimsUrl = new URL("../docs/production-claims.md", import.meta.url);
const readmeUrl = new URL("../README.md", import.meta.url);

test("production claims keep implemented evidence separate from release authority", async () => {
  const claims = await readFile(claimsUrl, "utf8");

  for (const required of [
    "tested pre-production",
    "Always say **preview**",
    "no anonymity or unlinkability promise",
    "does not encode, decode, import, export, or claim conformance to `.castaway`",
    "Claims that are not permitted yet",
    "Evidence required to change the label",
    "successful protected production-package run",
    "clean-profile Chrome installation",
    "independent application-security and cryptographic review",
    "Approved short-form copy",
  ])
    assert.match(
      claims,
      new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"),
    );
});

test("README exposes the canonical production-claim boundary", async () => {
  const readme = await readFile(readmeUrl, "utf8");

  assert.match(readme, /tested pre-production identity and membership wallet/i);
  assert.match(readme, /\[Production claims\]\(docs\/production-claims\.md\)/);
  assert.match(readme, /not a production-ready financial wallet/i);
});
