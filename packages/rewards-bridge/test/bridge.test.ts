import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseRequest,
  parseResponse,
  parseLaunch,
  createRequestGate,
  canonicalOrigin,
} from "../src/index.js";

const id = "a1".repeat(16);
const request = {
  schema: "wallet.rewards.request.v1",
  id,
  operation: "connect",
  issuedAt: 1000,
  expiresAt: 1100,
};
test("strict request version, operation, expiry and byte limits", () => {
  assert.deepEqual(parseRequest(request, 1020), request);
  for (const value of [
    { ...request, schema: "wallet.rewards.request.v2" },
    { ...request, operation: "sign" },
    { ...request, secret: "anything" },
    { ...request, issuedAt: 1050 },
    { ...request, expiresAt: 1400 },
    { ...request, id: "🦉".repeat(8192) },
    { ...request, id: "bad" },
  ])
    assert.throws(() => parseRequest(value, 1020));
  assert.throws(() => parseRequest(request, 1100));
});
test("exact allowlisted origin and fragment; never accept a return URL", () => {
  const fragment = `#request=${id}&origin=${encodeURIComponent("https://rewards.example")}`;
  assert.deepEqual(parseLaunch(fragment, ["https://rewards.example"]), {
    id,
    origin: "https://rewards.example",
  });
  for (const bad of [
    fragment + "&return=https://evil.example",
    fragment + `&request=${id}`,
    "#request=x&origin=null",
  ])
    assert.throws(() => parseLaunch(bad, ["https://rewards.example"]));
  assert.throws(() => parseLaunch(fragment, ["https://rewards.example.evil"]));
  for (const bad of [
    "null",
    "https://rewards.example/",
    "https://user@rewards.example",
    "http://rewards.example",
    "https://rewards.example/path",
  ])
    assert.throws(() => canonicalOrigin(bad));
  assert.equal(
    canonicalOrigin("http://127.0.0.1:4173"),
    "http://127.0.0.1:4173",
  );
});
test("request gate pins the opener, exact origin and id, consumes once, rejects replacement", () => {
  const opener = {};
  const gate = createRequestGate(
    { id, origin: "https://rewards.example" },
    opener,
  );
  assert.equal(
    gate.take(
      { source: {}, origin: "https://rewards.example", data: request },
      1020,
    ),
    null,
  );
  assert.equal(
    gate.take(
      { source: opener, origin: "https://evil.example", data: request },
      1020,
    ),
    null,
  );
  assert.equal(
    gate.take(
      {
        source: opener,
        origin: "https://rewards.example",
        data: { ...request, id: "b2".repeat(16) },
      },
      1020,
    ),
    null,
  );
  assert.deepEqual(
    gate.take(
      { source: opener, origin: "https://rewards.example", data: request },
      1020,
    ),
    request,
  );
  assert.equal(
    gate.take(
      { source: opener, origin: "https://rewards.example", data: request },
      1021,
    ),
    null,
  );
});
test("responses are public descriptors only, not eligibility or signing authority", () => {
  const response = {
    schema: "wallet.rewards.response.v1",
    id,
    operation: "connect",
    result: {
      walletPublicKey: "12".repeat(32),
      solanaAddress: "11111111111111111111111111111111",
      solanaPublicKey: "00".repeat(32),
    },
  };
  assert.deepEqual(parseResponse(response, id), response);
  assert.throws(() =>
    parseResponse(
      { ...response, result: { ...response.result, privateKey: "secret" } },
      id,
    ),
  );
  assert.throws(() =>
    parseResponse(
      { ...response, result: { ...response.result, verified: true } },
      id,
    ),
  );
  assert.throws(() => parseResponse(response, "b2".repeat(16)));
  assert.throws(() =>
    parseResponse({ ...response, result: undefined, error: "unknown" }, id),
  );
});
