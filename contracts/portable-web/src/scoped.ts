import {
  base64urlFromBytes,
  bytesFromBase64url64,
  bytesFromHex32,
  hexFromBytes,
  validateZenithTrustPolicy,
  type ZenithMembershipTrustPolicyV1,
  type ZenithMembershipTrustRootV1,
} from "./index.js";

export const SCOPED_MEMBERSHIP_VERSION = 4 as const;
export const SCOPED_MEMBERSHIP_REQUEST_SCHEMA =
  "castalia.scoped-membership-issuance-request.v4" as const;
export const SCOPED_MEMBERSHIP_CREDENTIAL_SCHEMA =
  "castalia.scoped-membership-credential.v4" as const;
export const MEMBERSHIP_DESCRIPTOR_SCHEMA =
  "castalia.membership-descriptor.v4" as const;
export const SCOPED_MEMBERSHIP_ENDPOINT_PATH = "/v4/memberships" as const;
export const ZENITH_MEMBERSHIP_DESCRIPTOR_PATH =
  "/v4/membership-descriptors/zenith" as const;
export const SCOPED_MEMBERSHIP_JOIN_DOMAIN =
  "castalia/scoped-membership-join/v4\0" as const;
export const SCOPED_MEMBERSHIP_ID_DOMAIN =
  "castalia/scoped-membership-id/v4\0" as const;
export const SCOPED_MEMBERSHIP_CREDENTIAL_DOMAIN =
  "castalia/scoped-membership-credential/v4\0" as const;
export const MEMBERSHIP_DESCRIPTOR_DOMAIN =
  "castalia/membership-descriptor/v4\0" as const;
export const COMMUNITY_ID_DOMAIN = "castalia/community-id/v1\0" as const;

export type CommunityGenesisV1 = {
  schema: "castalia.community-genesis.v1";
  version: 1;
  scopeType: "community";
  alias: string;
  nonce: string;
};

// A public registration nonce, generated once. It is not a signing key or a secret.
export const ZENITH_COMMUNITY_GENESIS: Readonly<CommunityGenesisV1> =
  Object.freeze({
    schema: "castalia.community-genesis.v1",
    version: 1,
    scopeType: "community",
    alias: "zenith",
    nonce: "74517325a71df9aa0f0d30858d50db7e7b6250b76da5d7649bc04279e2be47ab",
  });
export const ZENITH_COMMUNITY_SCOPE_ID =
  "a0065f491f2827d40732c837ac3af6f20b2ff8f3f16d5abe86d96ef8ba0fcc85" as const;

export type ScopedMembershipIssuanceRequestV4 = {
  schema: typeof SCOPED_MEMBERSHIP_REQUEST_SCHEMA;
  version: 4;
  scopeType: "community";
  scopeId: string;
  ownerPublicKey: string;
  signatureSuite: "Ed25519";
  signature: string;
};
export type ScopedMembershipCredentialV4 = {
  schema: typeof SCOPED_MEMBERSHIP_CREDENTIAL_SCHEMA;
  version: 4;
  scopeType: "community";
  scopeId: string;
  membershipId: string;
  ownerPublicKey: string;
  status: "active";
  issuerId: string;
  issuerKeyId: string;
  signatureSuite: "Ed25519";
  issuerSignature: string;
};
export type MembershipDescriptorV4 = {
  schema: typeof MEMBERSHIP_DESCRIPTOR_SCHEMA;
  version: 4;
  scopeType: "community";
  scopeId: string;
  genesis: CommunityGenesisV1;
  alias: string;
  name: string;
  issuerId: string;
  issuerKeyId: string;
  membershipEndpoint: string;
  signatureSuite: "Ed25519";
  issuerSignature: string;
};
export type ScopedMembershipTrustPolicyV1 = {
  schema: "castalia.scoped-membership-trust-policy.v1";
  version: 1;
  roots: readonly ZenithMembershipTrustRootV1[];
  scopes: readonly {
    scopeId: string;
    genesis: CommunityGenesisV1;
    issuerIds: readonly string[];
  }[];
};
export type MembershipDescriptorVerificationOptions = {
  expectedScopeId?: string;
  allowLoopback?: boolean;
};

const encoder = new TextEncoder();
const ID = /^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u;
const signaturePlaceholder = base64urlFromBytes(new Uint8Array(64));
function exact(
  input: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    typeof input !== "object" ||
    input === null ||
    Array.isArray(input) ||
    Object.keys(input).sort().join(",") !== [...keys].sort().join(",")
  )
    throw new Error(`${label} fields are not canonical`);
  return input as Record<string, unknown>;
}
function signature64(input: unknown, label: string): Uint8Array {
  const bytes = bytesFromBase64url64(input, label);
  if (base64urlFromBytes(bytes) !== input)
    throw new Error(`${label} is not canonical base64url`);
  return bytes;
}
function id(input: unknown, label: string): asserts input is string {
  if (typeof input !== "string" || !ID.test(input))
    throw new Error(`${label} is not canonical`);
}
function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const bytes = new Uint8Array(
    parts.reduce((total, part) => total + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
}
function buffer(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}
function jsonTranscript(domain: string, payload: unknown): Uint8Array {
  return encoder.encode(domain + JSON.stringify(payload));
}
async function digest(bytes: Uint8Array): Promise<string> {
  return hexFromBytes(
    new Uint8Array(
      await globalThis.crypto.subtle.digest("SHA-256", buffer(bytes)),
    ),
  );
}
export function parseCommunityGenesis(input: unknown): CommunityGenesisV1 {
  const value = exact(
    input,
    ["schema", "version", "scopeType", "alias", "nonce"],
    "community genesis",
  );
  if (
    value.schema !== "castalia.community-genesis.v1" ||
    value.version !== 1 ||
    value.scopeType !== "community"
  )
    throw new Error("community genesis protocol is not canonical v1");
  id(value.alias, "community alias");
  bytesFromHex32(value.nonce, "community registration nonce");
  return {
    schema: "castalia.community-genesis.v1",
    version: 1,
    scopeType: "community",
    alias: value.alias,
    nonce: value.nonce as string,
  };
}
export function deriveCommunityScopeId(
  genesis: CommunityGenesisV1,
): Promise<string> {
  return digest(
    jsonTranscript(COMMUNITY_ID_DOMAIN, parseCommunityGenesis(genesis)),
  );
}
export function scopedMembershipJoinTranscript(
  ownerPublicKey: string,
  scopeId: string,
): Uint8Array {
  return concat(
    encoder.encode(SCOPED_MEMBERSHIP_JOIN_DOMAIN),
    bytesFromHex32(ownerPublicKey, "Member Key"),
    bytesFromHex32(scopeId, "community scope ID"),
  );
}
export function deriveScopedMembershipId(
  ownerPublicKey: string,
  scopeId: string,
): Promise<string> {
  return digest(
    concat(
      encoder.encode(SCOPED_MEMBERSHIP_ID_DOMAIN),
      bytesFromHex32(ownerPublicKey, "Member Key"),
      bytesFromHex32(scopeId, "community scope ID"),
    ),
  );
}
export function parseScopedMembershipRequest(
  input: unknown,
): ScopedMembershipIssuanceRequestV4 {
  const value = exact(
    input,
    [
      "schema",
      "version",
      "scopeType",
      "scopeId",
      "ownerPublicKey",
      "signatureSuite",
      "signature",
    ],
    "scoped membership request",
  );
  if (
    value.schema !== SCOPED_MEMBERSHIP_REQUEST_SCHEMA ||
    value.version !== 4 ||
    value.scopeType !== "community" ||
    value.signatureSuite !== "Ed25519"
  )
    throw new Error("scoped membership request protocol is not canonical v4");
  bytesFromHex32(value.scopeId, "community scope ID");
  bytesFromHex32(value.ownerPublicKey, "Member Key");
  signature64(value.signature, "membership request signature");
  return structuredClone(value) as ScopedMembershipIssuanceRequestV4;
}
export function parseScopedMembershipCredential(
  input: unknown,
): ScopedMembershipCredentialV4 {
  const value = exact(
    input,
    [
      "schema",
      "version",
      "scopeType",
      "scopeId",
      "membershipId",
      "ownerPublicKey",
      "status",
      "issuerId",
      "issuerKeyId",
      "signatureSuite",
      "issuerSignature",
    ],
    "scoped membership credential",
  );
  if (
    value.schema !== SCOPED_MEMBERSHIP_CREDENTIAL_SCHEMA ||
    value.version !== 4 ||
    value.scopeType !== "community" ||
    value.status !== "active" ||
    value.signatureSuite !== "Ed25519"
  )
    throw new Error(
      "scoped membership credential protocol is not canonical v4",
    );
  bytesFromHex32(value.scopeId, "community scope ID");
  bytesFromHex32(value.membershipId, "membership ID");
  bytesFromHex32(value.ownerPublicKey, "Member Key");
  id(value.issuerId, "issuer ID");
  id(value.issuerKeyId, "issuer key ID");
  signature64(value.issuerSignature, "issuer signature");
  return structuredClone(value) as ScopedMembershipCredentialV4;
}
function credentialPayload(
  value: ScopedMembershipCredentialV4,
): Omit<ScopedMembershipCredentialV4, "issuerSignature"> {
  return {
    schema: value.schema,
    version: value.version,
    scopeType: value.scopeType,
    scopeId: value.scopeId,
    membershipId: value.membershipId,
    ownerPublicKey: value.ownerPublicKey,
    status: value.status,
    issuerId: value.issuerId,
    issuerKeyId: value.issuerKeyId,
    signatureSuite: value.signatureSuite,
  };
}
export function scopedMembershipCredentialTranscript(
  input: Omit<ScopedMembershipCredentialV4, "issuerSignature">,
): Uint8Array {
  const value = parseScopedMembershipCredential({
    ...input,
    issuerSignature: signaturePlaceholder,
  });
  return jsonTranscript(
    SCOPED_MEMBERSHIP_CREDENTIAL_DOMAIN,
    credentialPayload(value),
  );
}
export function validateMembershipEndpoint(
  input: string,
  allowLoopback = false,
): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error("membership endpoint must be a canonical HTTPS URL");
  }
  const development =
    allowLoopback &&
    url.protocol === "http:" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    url.href !== input ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.protocol !== "https:" && !development)
  )
    throw new Error("membership endpoint must be a canonical HTTPS URL");
  return url;
}
export function parseMembershipDescriptor(
  input: unknown,
): MembershipDescriptorV4 {
  const value = exact(
    input,
    [
      "schema",
      "version",
      "scopeType",
      "scopeId",
      "genesis",
      "alias",
      "name",
      "issuerId",
      "issuerKeyId",
      "membershipEndpoint",
      "signatureSuite",
      "issuerSignature",
    ],
    "membership descriptor",
  );
  if (
    value.schema !== MEMBERSHIP_DESCRIPTOR_SCHEMA ||
    value.version !== 4 ||
    value.scopeType !== "community" ||
    value.signatureSuite !== "Ed25519"
  )
    throw new Error("membership descriptor protocol is not canonical v4");
  bytesFromHex32(value.scopeId, "community scope ID");
  const genesis = parseCommunityGenesis(value.genesis);
  id(value.alias, "community alias");
  id(value.issuerId, "issuer ID");
  id(value.issuerKeyId, "issuer key ID");
  if (value.alias !== genesis.alias)
    throw new Error("descriptor alias does not match genesis");
  if (
    typeof value.name !== "string" ||
    value.name.length < 1 ||
    value.name.length > 80 ||
    value.name !== value.name.trim() ||
    Array.from(value.name).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    throw new Error("community name is not canonical");
  if (
    typeof value.membershipEndpoint !== "string" ||
    value.membershipEndpoint.length > 2048
  )
    throw new Error("membership endpoint is not canonical");
  signature64(value.issuerSignature, "descriptor signature");
  return { ...(structuredClone(value) as MembershipDescriptorV4), genesis };
}
function descriptorPayload(
  value: MembershipDescriptorV4,
): Omit<MembershipDescriptorV4, "issuerSignature"> {
  return {
    schema: value.schema,
    version: value.version,
    scopeType: value.scopeType,
    scopeId: value.scopeId,
    genesis: parseCommunityGenesis(value.genesis),
    alias: value.alias,
    name: value.name,
    issuerId: value.issuerId,
    issuerKeyId: value.issuerKeyId,
    membershipEndpoint: value.membershipEndpoint,
    signatureSuite: value.signatureSuite,
  };
}
export function membershipDescriptorTranscript(
  input: Omit<MembershipDescriptorV4, "issuerSignature">,
): Uint8Array {
  return jsonTranscript(
    MEMBERSHIP_DESCRIPTOR_DOMAIN,
    descriptorPayload(
      parseMembershipDescriptor({
        ...input,
        issuerSignature: signaturePlaceholder,
      }),
    ),
  );
}
export function zenithScopedMembershipTrustPolicy(
  policy: ZenithMembershipTrustPolicyV1,
): ScopedMembershipTrustPolicyV1 {
  validateZenithTrustPolicy(policy);
  return {
    schema: "castalia.scoped-membership-trust-policy.v1",
    version: 1,
    roots: structuredClone(policy.roots),
    scopes: [
      {
        scopeId: ZENITH_COMMUNITY_SCOPE_ID,
        genesis: { ...ZENITH_COMMUNITY_GENESIS },
        issuerIds: ["zenith-research"],
      },
    ],
  };
}
export function validateScopedMembershipTrustPolicy(
  input: unknown,
): asserts input is ScopedMembershipTrustPolicyV1 {
  const value = exact(
    input,
    ["schema", "version", "roots", "scopes"],
    "scoped membership trust policy",
  );
  if (
    value.schema !== "castalia.scoped-membership-trust-policy.v1" ||
    value.version !== 1 ||
    !Array.isArray(value.scopes) ||
    !value.scopes.length
  )
    throw new Error("scoped membership trust policy is not canonical v1");
  validateZenithTrustPolicy({
    schema: "castalia.zenith-membership-trust-policy.v1",
    version: 1,
    roots: value.roots,
  });
  const scopes = new Set<string>();
  for (const inputScope of value.scopes as unknown[]) {
    const scope = exact(
      inputScope,
      ["scopeId", "genesis", "issuerIds"],
      "trusted community scope",
    );
    bytesFromHex32(scope.scopeId, "trusted scope ID");
    parseCommunityGenesis(scope.genesis);
    if (scopes.has(scope.scopeId as string))
      throw new Error("duplicate trusted community scope");
    scopes.add(scope.scopeId as string);
    if (!Array.isArray(scope.issuerIds) || !scope.issuerIds.length)
      throw new Error("scope needs authorized issuers");
    const issuers = new Set<string>();
    for (const issuer of scope.issuerIds as unknown[]) {
      id(issuer, "authorized issuer ID");
      if (issuers.has(issuer))
        throw new Error("duplicate authorized issuer ID");
      issuers.add(issuer);
    }
  }
}
async function trustedRoot(
  scopeId: string,
  issuerId: string,
  issuerKeyId: string,
  policy: ScopedMembershipTrustPolicyV1,
): Promise<ZenithMembershipTrustRootV1> {
  validateScopedMembershipTrustPolicy(policy);
  const scope = policy.scopes.find(
    (candidate) => candidate.scopeId === scopeId,
  );
  if (!scope || (await deriveCommunityScopeId(scope.genesis)) !== scope.scopeId)
    throw new Error("membership scope is not trusted");
  if (!scope.issuerIds.includes(issuerId))
    throw new Error("membership issuer is not authorized for this scope");
  const root = policy.roots.find(
    (candidate) =>
      candidate.issuerId === issuerId && candidate.keyId === issuerKeyId,
  );
  if (!root) throw new Error("membership issuer key is not trusted");
  return root;
}
async function verifySignature(
  root: ZenithMembershipTrustRootV1,
  signature: string,
  transcript: Uint8Array,
): Promise<void> {
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    buffer(bytesFromHex32(root.publicKey, "issuer public key")),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  if (
    !(await globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      buffer(bytesFromBase64url64(signature, "issuer signature")),
      buffer(transcript),
    ))
  )
    throw new Error("membership signature is invalid");
}
export async function verifyScopedMembershipCredential(
  input: unknown,
  policy: ScopedMembershipTrustPolicyV1,
  expectedOwnerPublicKey?: string,
  expectedScopeId?: string,
): Promise<ScopedMembershipCredentialV4> {
  const value = parseScopedMembershipCredential(input);
  if (
    expectedOwnerPublicKey !== undefined &&
    value.ownerPublicKey !== expectedOwnerPublicKey
  )
    throw new Error("membership owner does not match this Member Key");
  if (expectedScopeId !== undefined && value.scopeId !== expectedScopeId)
    throw new Error("membership scope does not match the selected community");
  const root = await trustedRoot(
    value.scopeId,
    value.issuerId,
    value.issuerKeyId,
    policy,
  );
  if (
    value.membershipId !==
    (await deriveScopedMembershipId(value.ownerPublicKey, value.scopeId))
  )
    throw new Error(
      "membership ID is not deterministic for its owner and scope",
    );
  await verifySignature(
    root,
    value.issuerSignature,
    scopedMembershipCredentialTranscript(credentialPayload(value)),
  );
  return value;
}
export async function verifyMembershipDescriptor(
  input: unknown,
  policy: ScopedMembershipTrustPolicyV1,
  options: MembershipDescriptorVerificationOptions = {},
): Promise<MembershipDescriptorV4> {
  const value = parseMembershipDescriptor(input);
  if (
    options.expectedScopeId !== undefined &&
    value.scopeId !== options.expectedScopeId
  )
    throw new Error("descriptor scope does not match the selected community");
  if ((await deriveCommunityScopeId(value.genesis)) !== value.scopeId)
    throw new Error("descriptor genesis does not match scope ID");
  const root = await trustedRoot(
    value.scopeId,
    value.issuerId,
    value.issuerKeyId,
    policy,
  );
  const endpoint = validateMembershipEndpoint(
    value.membershipEndpoint,
    options.allowLoopback,
  );
  if (endpoint.pathname !== SCOPED_MEMBERSHIP_ENDPOINT_PATH)
    throw new Error("membership endpoint path is not canonical v4");
  await verifySignature(
    root,
    value.issuerSignature,
    membershipDescriptorTranscript(descriptorPayload(value)),
  );
  return value;
}
async function responseJson(response: Response): Promise<unknown> {
  if (!response.ok)
    throw new Error(
      `membership issuer rejected the request (${String(response.status)})`,
    );
  if (!response.body)
    throw new Error("membership issuer returned an empty response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > 16_384) {
      await reader.cancel();
      throw new Error("membership response is too large");
    }
    chunks.push(value);
  }
  const body = new TextDecoder("utf-8", { fatal: true }).decode(
    concat(...chunks),
  );
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new Error("membership issuer returned malformed JSON");
  }
}
export async function fetchZenithMembershipDescriptor(input: {
  issuerOrigin: string;
  trustPolicy: ScopedMembershipTrustPolicyV1;
  allowLoopback?: boolean;
  fetchImpl?: typeof fetch;
}): Promise<MembershipDescriptorV4> {
  const endpoint = validateMembershipEndpoint(
    `${input.issuerOrigin}${ZENITH_MEMBERSHIP_DESCRIPTOR_PATH}`,
    input.allowLoopback,
  );
  if (endpoint.origin !== input.issuerOrigin)
    throw new Error("membership issuer must be a canonical origin");
  const response = await (input.fetchImpl ?? fetch)(endpoint, {
    signal: AbortSignal.timeout(15_000),
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
  });
  return verifyMembershipDescriptor(
    await responseJson(response),
    input.trustPolicy,
    {
      expectedScopeId: ZENITH_COMMUNITY_SCOPE_ID,
      allowLoopback: input.allowLoopback ?? false,
    },
  );
}
export async function issueScopedMembershipCredential(input: {
  descriptor: MembershipDescriptorV4;
  ownerPublicKey: string;
  signature: string;
  trustPolicy: ScopedMembershipTrustPolicyV1;
  allowLoopback?: boolean;
  fetchImpl?: typeof fetch;
}): Promise<ScopedMembershipCredentialV4> {
  const descriptor = await verifyMembershipDescriptor(
    input.descriptor,
    input.trustPolicy,
    { allowLoopback: input.allowLoopback ?? false },
  );
  const request = parseScopedMembershipRequest({
    schema: SCOPED_MEMBERSHIP_REQUEST_SCHEMA,
    version: 4,
    scopeType: "community",
    scopeId: descriptor.scopeId,
    ownerPublicKey: input.ownerPublicKey,
    signatureSuite: "Ed25519",
    signature: input.signature,
  });
  const response = await (input.fetchImpl ?? fetch)(
    descriptor.membershipEndpoint,
    {
      signal: AbortSignal.timeout(15_000),
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
    },
  );
  const credential = await verifyScopedMembershipCredential(
    await responseJson(response),
    input.trustPolicy,
    input.ownerPublicKey,
    descriptor.scopeId,
  );
  if (
    credential.issuerId !== descriptor.issuerId ||
    credential.issuerKeyId !== descriptor.issuerKeyId
  )
    throw new Error("membership issuer does not match the approved descriptor");
  return credential;
}
