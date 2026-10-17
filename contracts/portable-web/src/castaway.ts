import {
  parseZenithMembershipCredential,
  parseScopedMembershipCredential,
  type ScopedMembershipCredentialV4,
  type ZenithMembershipCredentialV3,
} from "@castalia/membership-contract";

export const CASTAWAY_CONTENTS_SCHEMA =
  "castalia.castaway-contents.v1" as const;
export const CASTAWAY_ENVELOPE_SCHEMA = "castalia.castaway.v1" as const;
export const ZENITH_IDENTITY_SCHEMA = "zenith.identity-section.v1" as const;
export const ZENITH_IDENTITY_DISCLOSURE_SCHEMA =
  "zenith.identity-disclosure.v1" as const;
export const ZENITH_CHAIN_ACCOUNTS_SCHEMA =
  "zenith.chain-accounts-section.v1" as const;
export const CASTALIA_CHAIN_ACCOUNT_DERIVATION_SCHEMA =
  "castalia.chain-account-derivation.v1" as const;

export const ZENITH_PERSON_ROLE_SUGGESTIONS = [
  "Author",
  "Researcher",
  "Student",
] as const;
export const ZENITH_PERSON_ROLES = ZENITH_PERSON_ROLE_SUGGESTIONS;
export type ZenithPersonRole = string;
export type ClaimDisclosure = "private" | "selected";

export type ZenithTextClaim = {
  value: string;
  disclosure: ClaimDisclosure;
};

export type ZenithIdentityFields = {
  displayName: ZenithTextClaim;
  givenName: ZenithTextClaim;
  familyName: ZenithTextClaim;
  headline: ZenithTextClaim;
  biography: ZenithTextClaim;
  website: ZenithTextClaim;
  orcid: ZenithTextClaim;
};

export type ZenithRoleClaim = {
  role: ZenithPersonRole;
  disclosure: ClaimDisclosure;
};

export type ZenithAcademicInstitutionAffiliation = {
  type: "AcademicInstitution";
  name: string;
  department: string;
  position: string;
  identifier: string;
  website: string;
  disclosure: ClaimDisclosure;
};

export type ZenithJournalRelationship = {
  type: "Journal";
  name: string;
  relationship: "Author" | "Editor" | "Reviewer" | "Contributor";
  identifier: string;
  website: string;
  disclosure: ClaimDisclosure;
};

export type ZenithIdentitySectionV1 = {
  schema: typeof ZENITH_IDENTITY_SCHEMA;
  version: 1;
  subject: {
    type: "Person";
    memberKey: string;
    fields: ZenithIdentityFields;
    roles: ZenithRoleClaim[];
    affiliations: ZenithAcademicInstitutionAffiliation[];
    journals: ZenithJournalRelationship[];
  };
  updatedAt: number;
};

export type ChainAccountFamily = "cardano" | "evm" | "solana";
export type ChainAccountNetworkId =
  | "cardano:mainnet"
  | "eip155:1"
  | "eip155:4663"
  | "solana:mainnet-beta";
export type ChainAccountKeySuite = "Ed25519" | "secp256k1";
export type ChainAccountDerivation =
  | "castalia.cardano-payment-from-member-root.v1"
  | "castalia.evm-from-member-root.v1"
  | "castalia.solana-from-member-root.v1";

export type ZenithChainAccountV1 = {
  accountId: string;
  keyId: string;
  family: ChainAccountFamily;
  networkId: ChainAccountNetworkId;
  address: string;
  publicKey: string;
  keySuite: ChainAccountKeySuite;
  derivationSchema: typeof CASTALIA_CHAIN_ACCOUNT_DERIVATION_SCHEMA;
  derivation: ChainAccountDerivation;
  accountIndex: 0;
  status: "preview";
};

export type ZenithChainAccountsSectionV1 = {
  schema: typeof ZENITH_CHAIN_ACCOUNTS_SCHEMA;
  version: 1;
  ownerMemberKey: string;
  authority: "descriptor-only";
  recovery: "castalia.wallet-custody.v1";
  accounts: ZenithChainAccountV1[];
};

export type CastawayContentsV1 = {
  schema: typeof CASTAWAY_CONTENTS_SCHEMA;
  version: 1;
  sections: {
    identity: ZenithIdentitySectionV1;
    memberships?: ZenithMembershipCredentialV3[];
    scopedMemberships?: ScopedMembershipCredentialV4[];
    chainAccounts?: ZenithChainAccountsSectionV1;
  };
};

export type CastawayEnvelopeV1 = {
  schema: typeof CASTAWAY_ENVELOPE_SCHEMA;
  contentsSchema: typeof CASTAWAY_CONTENTS_SCHEMA;
  ownerPublicKey: string;
  exportedAt: number;
  kdf: {
    name: "Argon2id";
    version: 19;
    salt: string;
    memoryKiB: 65_536;
    iterations: 3;
    parallelism: 1;
    derivedKeyBytes: 32;
  };
  aead: {
    name: "AES-256-GCM";
    nonce: string;
    tagBits: 128;
  };
  ciphertext: string;
};

export type ZenithIdentityDisclosureV1 = {
  schema: typeof ZENITH_IDENTITY_DISCLOSURE_SCHEMA;
  version: 1;
  assurance: "self-asserted";
  subject: {
    type: "Person";
    memberKey: string;
  };
  claims: {
    fields: Partial<Record<keyof ZenithIdentityFields, string>>;
    roles: ZenithPersonRole[];
    affiliations: Omit<ZenithAcademicInstitutionAffiliation, "disclosure">[];
    journals: Omit<ZenithJournalRelationship, "disclosure">[];
  };
  createdAt: number;
};

const HEX_32 = /^[0-9a-f]{64}$/u;
const ORCID = /^(?:\d{4}-){3}\d{3}[\dX]$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const CARDANO_MAINNET_ADDRESS = /^addr1[023456789ac-hj-np-z]{45,120}$/u;
const EVM_ADDRESS = /^0x[0-9a-f]{40}$/u;
const SOLANA_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/u;
const COMPRESSED_SECP256K1_PUBLIC_KEY = /^(?:02|03)[0-9a-f]{64}$/u;
const FIELD_NAMES = [
  "displayName",
  "givenName",
  "familyName",
  "headline",
  "biography",
  "website",
  "orcid",
] as const satisfies readonly (keyof ZenithIdentityFields)[];
const JOURNAL_RELATIONSHIPS = [
  "Author",
  "Editor",
  "Reviewer",
  "Contributor",
] as const;

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("identity value must be an object");
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]) {
  if (Object.keys(value).sort().join(",") !== [...keys].sort().join(","))
    throw new Error("identity value contains missing or unknown fields");
}

function text(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || value.length > maximum)
    throw new Error(`${name} is malformed`);
  return value;
}

function disclosure(value: unknown): ClaimDisclosure {
  if (value !== "private" && value !== "selected")
    throw new Error("claim disclosure is malformed");
  return value;
}

function timestamp(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0)
    throw new Error("identity timestamp is malformed");
  return value as number;
}

function textClaim(value: unknown, name: string): ZenithTextClaim {
  const candidate = record(value);
  exactKeys(candidate, ["value", "disclosure"]);
  const maximum = name === "biography" ? 4_000 : 320;
  return {
    value: text(candidate.value, name, maximum),
    disclosure: disclosure(candidate.disclosure),
  };
}

function personRole(value: unknown): ZenithPersonRole {
  const role = text(value, "identity role", 80);
  const containsControlCharacter = Array.from(role).some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
  if (
    !role ||
    role !== role.trim() ||
    role !== role.normalize("NFC") ||
    containsControlCharacter
  )
    throw new Error("identity role is malformed");
  return role;
}

function safeUrl(value: string, name: string): string {
  if (!value) return value;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS URL`);
  }
  if (parsed.protocol !== "https:")
    throw new Error(`${name} must be an absolute HTTPS URL`);
  return value;
}

function parseIdentity(value: unknown): ZenithIdentitySectionV1 {
  const identity = record(value);
  exactKeys(identity, ["schema", "version", "subject", "updatedAt"]);
  if (identity.schema !== ZENITH_IDENTITY_SCHEMA || identity.version !== 1)
    throw new Error("identity schema is unsupported");
  const subject = record(identity.subject);
  exactKeys(subject, [
    "type",
    "memberKey",
    "fields",
    "roles",
    "affiliations",
    "journals",
  ]);
  if (subject.type !== "Person")
    throw new Error("identity subject is not a Person");
  const memberKey = text(subject.memberKey, "member key", 64);
  if (!HEX_32.test(memberKey))
    throw new Error("identity member key is malformed");

  const fieldsValue = record(subject.fields);
  exactKeys(fieldsValue, FIELD_NAMES);
  const fields = Object.fromEntries(
    FIELD_NAMES.map((name) => [name, textClaim(fieldsValue[name], name)]),
  ) as ZenithIdentityFields;
  safeUrl(fields.website.value, "website");
  if (fields.orcid.value && !ORCID.test(fields.orcid.value))
    throw new Error("ORCID is malformed");

  if (!Array.isArray(subject.roles) || subject.roles.length > 12)
    throw new Error("identity roles are malformed");
  const roles = subject.roles.map((value): ZenithRoleClaim => {
    const role = record(value);
    exactKeys(role, ["role", "disclosure"]);
    return {
      role: personRole(role.role),
      disclosure: disclosure(role.disclosure),
    };
  });
  if (
    new Set(roles.map(({ role }) => role.toLocaleLowerCase("en-US"))).size !==
    roles.length
  )
    throw new Error("identity roles contain duplicates");

  if (!Array.isArray(subject.affiliations) || subject.affiliations.length > 12)
    throw new Error("identity affiliations are malformed");
  const affiliations = subject.affiliations.map(
    (value): ZenithAcademicInstitutionAffiliation => {
      const affiliation = record(value);
      exactKeys(affiliation, [
        "type",
        "name",
        "department",
        "position",
        "identifier",
        "website",
        "disclosure",
      ]);
      if (affiliation.type !== "AcademicInstitution")
        throw new Error("affiliation type is unsupported");
      const website = text(affiliation.website, "institution website", 320);
      safeUrl(website, "institution website");
      return {
        type: "AcademicInstitution",
        name: text(affiliation.name, "institution name", 240),
        department: text(affiliation.department, "department", 240),
        position: text(affiliation.position, "institution position", 240),
        identifier: text(affiliation.identifier, "institution identifier", 240),
        website,
        disclosure: disclosure(affiliation.disclosure),
      };
    },
  );

  if (!Array.isArray(subject.journals) || subject.journals.length > 24)
    throw new Error("identity journals are malformed");
  const journals = subject.journals.map((value): ZenithJournalRelationship => {
    const journal = record(value);
    exactKeys(journal, [
      "type",
      "name",
      "relationship",
      "identifier",
      "website",
      "disclosure",
    ]);
    if (journal.type !== "Journal")
      throw new Error("journal type is unsupported");
    if (
      !JOURNAL_RELATIONSHIPS.includes(
        journal.relationship as (typeof JOURNAL_RELATIONSHIPS)[number],
      )
    )
      throw new Error("journal relationship is unsupported");
    const website = text(journal.website, "journal website", 320);
    safeUrl(website, "journal website");
    return {
      type: "Journal",
      name: text(journal.name, "journal name", 240),
      relationship:
        journal.relationship as ZenithJournalRelationship["relationship"],
      identifier: text(journal.identifier, "journal identifier", 240),
      website,
      disclosure: disclosure(journal.disclosure),
    };
  });

  return {
    schema: ZENITH_IDENTITY_SCHEMA,
    version: 1,
    subject: {
      type: "Person",
      memberKey,
      fields,
      roles,
      affiliations,
      journals,
    },
    updatedAt: timestamp(identity.updatedAt),
  };
}

export function parseZenithIdentitySection(
  value: unknown,
): ZenithIdentitySectionV1 {
  return parseIdentity(value);
}

const CHAIN_NETWORKS = {
  "cardano:mainnet": {
    family: "cardano",
    keySuite: "Ed25519",
    derivation: "castalia.cardano-payment-from-member-root.v1",
    address: CARDANO_MAINNET_ADDRESS,
  },
  "eip155:1": {
    family: "evm",
    keySuite: "secp256k1",
    derivation: "castalia.evm-from-member-root.v1",
    address: EVM_ADDRESS,
  },
  "eip155:4663": {
    family: "evm",
    keySuite: "secp256k1",
    derivation: "castalia.evm-from-member-root.v1",
    address: EVM_ADDRESS,
  },
  "solana:mainnet-beta": {
    family: "solana",
    keySuite: "Ed25519",
    derivation: "castalia.solana-from-member-root.v1",
    address: SOLANA_ADDRESS,
  },
} as const satisfies Record<
  ChainAccountNetworkId,
  {
    family: ChainAccountFamily;
    keySuite: ChainAccountKeySuite;
    derivation: ChainAccountDerivation;
    address: RegExp;
  }
>;

export function parseCastawayChainAccounts(
  value: unknown,
  ownerPublicKey: string,
): ZenithChainAccountsSectionV1 {
  const section = record(value);
  exactKeys(section, [
    "schema",
    "version",
    "ownerMemberKey",
    "authority",
    "recovery",
    "accounts",
  ]);
  if (
    section.schema !== ZENITH_CHAIN_ACCOUNTS_SCHEMA ||
    section.version !== 1 ||
    section.authority !== "descriptor-only" ||
    section.recovery !== "castalia.wallet-custody.v1"
  )
    throw new Error("Castaway chain-account section is unsupported");
  const ownerMemberKey = text(
    section.ownerMemberKey,
    "chain-account owner",
    64,
  );
  if (!HEX_32.test(ownerMemberKey) || ownerMemberKey !== ownerPublicKey)
    throw new Error("Castaway chain accounts belong to a different Member Key");
  if (!Array.isArray(section.accounts) || section.accounts.length > 8)
    throw new Error("Castaway must contain at most 8 chain accounts");
  const accountIds = new Set<string>();
  const networkIds = new Set<string>();
  const accounts = section.accounts.map((value): ZenithChainAccountV1 => {
    const account = record(value);
    exactKeys(account, [
      "accountId",
      "keyId",
      "family",
      "networkId",
      "address",
      "publicKey",
      "keySuite",
      "derivationSchema",
      "derivation",
      "accountIndex",
      "status",
    ]);
    const accountId = text(account.accountId, "chain account ID", 64);
    const keyId = text(account.keyId, "chain key ID", 64);
    if (!HEX_32.test(accountId) || !HEX_32.test(keyId))
      throw new Error("Castaway chain-account identifier is malformed");
    const networkIdValue = text(account.networkId, "chain network ID", 32);
    if (!Object.hasOwn(CHAIN_NETWORKS, networkIdValue))
      throw new Error("Castaway chain network is unsupported");
    const networkId = networkIdValue as ChainAccountNetworkId;
    const network = CHAIN_NETWORKS[networkId];
    if (
      account.family !== network.family ||
      account.keySuite !== network.keySuite ||
      account.derivationSchema !== CASTALIA_CHAIN_ACCOUNT_DERIVATION_SCHEMA ||
      account.derivation !== network.derivation ||
      account.accountIndex !== 0 ||
      account.status !== "preview"
    )
      throw new Error("Castaway chain-account derivation is unsupported");
    const address = text(account.address, "chain account address", 128);
    const publicKey = text(account.publicKey, "chain account public key", 66);
    if (
      !network.address.test(address) ||
      (network.keySuite === "Ed25519"
        ? !HEX_32.test(publicKey)
        : !COMPRESSED_SECP256K1_PUBLIC_KEY.test(publicKey))
    )
      throw new Error("Castaway chain-account public projection is malformed");
    if (accountIds.has(accountId) || networkIds.has(networkId))
      throw new Error("Castaway chain accounts contain duplicates");
    accountIds.add(accountId);
    networkIds.add(networkId);
    return {
      accountId,
      keyId,
      family: network.family,
      networkId,
      address,
      publicKey,
      keySuite: network.keySuite,
      derivationSchema: CASTALIA_CHAIN_ACCOUNT_DERIVATION_SCHEMA,
      derivation: network.derivation,
      accountIndex: 0,
      status: "preview",
    };
  });
  return {
    schema: ZENITH_CHAIN_ACCOUNTS_SCHEMA,
    version: 1,
    ownerMemberKey,
    authority: "descriptor-only",
    recovery: "castalia.wallet-custody.v1",
    accounts,
  };
}

export function parseCastawayContents(value: unknown): CastawayContentsV1 {
  const contents = record(value);
  exactKeys(contents, ["schema", "version", "sections"]);
  if (contents.schema !== CASTAWAY_CONTENTS_SCHEMA || contents.version !== 1)
    throw new Error("Castaway contents schema is unsupported");
  const sections = record(contents.sections);
  exactKeys(sections, [
    "identity",
    ...["memberships", "scopedMemberships", "chainAccounts"].filter((key) =>
      Object.hasOwn(sections, key),
    ),
  ]);
  const identity = parseIdentity(sections.identity);
  return {
    schema: CASTAWAY_CONTENTS_SCHEMA,
    version: 1,
    sections: {
      identity,
      ...(Object.hasOwn(sections, "chainAccounts")
        ? {
            chainAccounts: parseCastawayChainAccounts(
              sections.chainAccounts,
              identity.subject.memberKey,
            ),
          }
        : {}),
      ...(Object.hasOwn(sections, "scopedMemberships")
        ? {
            scopedMemberships: parseCastawayScopedMemberships(
              sections.scopedMemberships,
              identity.subject.memberKey,
            ),
          }
        : {}),
      ...(Object.hasOwn(sections, "memberships")
        ? {
            memberships: parseCastawayMemberships(
              sections.memberships,
              identity.subject.memberKey,
            ),
          }
        : {}),
    },
  };
}

// Structural validation only. Applications must also verify issuer signatures
// against their pinned trust policy before preserving or using these proofs.
export function parseCastawayMemberships(
  value: unknown,
  ownerPublicKey: string,
): ZenithMembershipCredentialV3[] {
  if (!Array.isArray(value) || value.length > 16)
    throw new Error("Castaway memberships must contain at most 16 proofs");
  const memberships = value.map(parseZenithMembershipCredential);
  const ids = new Set<string>();
  for (const membership of memberships) {
    if (membership.ownerPublicKey !== ownerPublicKey)
      throw new Error("Castaway membership belongs to a different Member Key");
    if (ids.has(membership.membershipId))
      throw new Error("Castaway memberships contain duplicate proofs");
    ids.add(membership.membershipId);
  }
  return memberships;
}

// As with v3 proofs, callers must verify issuer authorization and signatures.
export function parseCastawayScopedMemberships(
  value: unknown,
  ownerPublicKey: string,
): ScopedMembershipCredentialV4[] {
  if (!Array.isArray(value) || value.length > 16)
    throw new Error(
      "Castaway scoped memberships must contain at most 16 proofs",
    );
  const memberships = value.map(parseScopedMembershipCredential);
  const ids = new Set<string>();
  const scopes = new Set<string>();
  for (const proof of memberships) {
    if (proof.ownerPublicKey !== ownerPublicKey)
      throw new Error(
        "Castaway scoped membership belongs to a different Member Key",
      );
    if (ids.has(proof.membershipId) || scopes.has(proof.scopeId))
      throw new Error("Castaway scoped memberships contain duplicate proofs");
    ids.add(proof.membershipId);
    scopes.add(proof.scopeId);
  }
  return memberships;
}

export function parseCastawayEnvelope(value: unknown): CastawayEnvelopeV1 {
  const envelope = record(value);
  exactKeys(envelope, [
    "schema",
    "contentsSchema",
    "ownerPublicKey",
    "exportedAt",
    "kdf",
    "aead",
    "ciphertext",
  ]);
  if (
    envelope.schema !== CASTAWAY_ENVELOPE_SCHEMA ||
    envelope.contentsSchema !== CASTAWAY_CONTENTS_SCHEMA
  )
    throw new Error("Castaway envelope schema is unsupported");
  const ownerPublicKey = text(envelope.ownerPublicKey, "owner public key", 64);
  if (!HEX_32.test(ownerPublicKey))
    throw new Error("Castaway owner public key is malformed");
  const kdf = record(envelope.kdf);
  exactKeys(kdf, [
    "name",
    "version",
    "salt",
    "memoryKiB",
    "iterations",
    "parallelism",
    "derivedKeyBytes",
  ]);
  const salt = text(kdf.salt, "Castaway salt", 22);
  if (
    kdf.name !== "Argon2id" ||
    kdf.version !== 19 ||
    salt.length !== 22 ||
    !BASE64URL.test(salt) ||
    kdf.memoryKiB !== 65_536 ||
    kdf.iterations !== 3 ||
    kdf.parallelism !== 1 ||
    kdf.derivedKeyBytes !== 32
  )
    throw new Error("Castaway KDF is unsupported");
  const aead = record(envelope.aead);
  exactKeys(aead, ["name", "nonce", "tagBits"]);
  const nonce = text(aead.nonce, "Castaway nonce", 16);
  if (
    aead.name !== "AES-256-GCM" ||
    nonce.length !== 16 ||
    !BASE64URL.test(nonce) ||
    aead.tagBits !== 128
  )
    throw new Error("Castaway encryption is unsupported");
  const ciphertext = text(
    envelope.ciphertext,
    "Castaway ciphertext",
    1_048_576,
  );
  if (ciphertext.length < 22 || !BASE64URL.test(ciphertext))
    throw new Error("Castaway ciphertext is malformed");
  return {
    schema: CASTAWAY_ENVELOPE_SCHEMA,
    contentsSchema: CASTAWAY_CONTENTS_SCHEMA,
    ownerPublicKey,
    exportedAt: timestamp(envelope.exportedAt),
    kdf: {
      name: "Argon2id",
      version: 19,
      salt,
      memoryKiB: 65_536,
      iterations: 3,
      parallelism: 1,
      derivedKeyBytes: 32,
    },
    aead: { name: "AES-256-GCM", nonce, tagBits: 128 },
    ciphertext,
  };
}

const privateClaim = (): ZenithTextClaim => ({
  value: "",
  disclosure: "private",
});

export function createPrivateZenithIdentity(
  memberKey: string,
  updatedAt = Date.now(),
): ZenithIdentitySectionV1 {
  if (!HEX_32.test(memberKey))
    throw new Error("identity member key is malformed");
  return {
    schema: ZENITH_IDENTITY_SCHEMA,
    version: 1,
    subject: {
      type: "Person",
      memberKey,
      fields: {
        displayName: privateClaim(),
        givenName: privateClaim(),
        familyName: privateClaim(),
        headline: privateClaim(),
        biography: privateClaim(),
        website: privateClaim(),
        orcid: privateClaim(),
      },
      roles: [],
      affiliations: [],
      journals: [],
    },
    updatedAt,
  };
}

export function castawayContents(
  identity: ZenithIdentitySectionV1,
  memberships?: readonly ZenithMembershipCredentialV3[],
  scopedMemberships?: readonly ScopedMembershipCredentialV4[],
  chainAccounts?: ZenithChainAccountsSectionV1,
): CastawayContentsV1 {
  return {
    schema: CASTAWAY_CONTENTS_SCHEMA,
    version: 1,
    sections: {
      identity: parseIdentity(identity),
      ...(chainAccounts
        ? {
            chainAccounts: parseCastawayChainAccounts(
              chainAccounts,
              identity.subject.memberKey,
            ),
          }
        : {}),
      ...(scopedMemberships?.length
        ? {
            scopedMemberships: parseCastawayScopedMemberships(
              scopedMemberships,
              identity.subject.memberKey,
            ),
          }
        : {}),
      ...(memberships?.length
        ? {
            memberships: parseCastawayMemberships(
              memberships,
              identity.subject.memberKey,
            ),
          }
        : {}),
    },
  };
}

export function selectedIdentityDisclosure(
  identity: ZenithIdentitySectionV1,
  createdAt = Date.now(),
): ZenithIdentityDisclosureV1 {
  const parsed = parseIdentity(identity);
  const fields: Partial<Record<keyof ZenithIdentityFields, string>> = {};
  for (const name of FIELD_NAMES) {
    const claim = parsed.subject.fields[name];
    if (claim.disclosure === "selected" && claim.value)
      fields[name] = claim.value;
  }
  return {
    schema: ZENITH_IDENTITY_DISCLOSURE_SCHEMA,
    version: 1,
    assurance: "self-asserted",
    subject: { type: "Person", memberKey: parsed.subject.memberKey },
    claims: {
      fields,
      roles: parsed.subject.roles
        .filter(({ disclosure: state }) => state === "selected")
        .map(({ role }) => role),
      affiliations: parsed.subject.affiliations
        .filter(({ disclosure: state }) => state === "selected")
        .map(({ type, name, department, position, identifier, website }) => ({
          type,
          name,
          department,
          position,
          identifier,
          website,
        })),
      journals: parsed.subject.journals
        .filter(({ disclosure: state }) => state === "selected")
        .map(({ type, name, relationship, identifier, website }) => ({
          type,
          name,
          relationship,
          identifier,
          website,
        })),
    },
    createdAt: timestamp(createdAt),
  };
}
