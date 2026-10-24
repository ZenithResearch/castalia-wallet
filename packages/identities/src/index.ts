/** Wallet-owned, data-only records. No signing authority or OAuth tokens belong here. */
// Must remain compatible with browser custody's MAX_CASTAWAY_BYTES. These are
// UTF-8 byte limits, not JS string lengths; the envelope includes AEAD + base64.
export const MAX_IDENTITY_PLAINTEXT_BYTES = 1_048_576;
export const MAX_IDENTITY_ENVELOPE_BYTES = 1_048_576;
function boundedUtf8(value: string, limit: number, error: string): void {
  if (new TextEncoder().encode(value).byteLength > limit)
    throw new Error(error);
}
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(stableJson).join(",") + "]";
  if (value !== null && typeof value === "object")
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map(
          (k) =>
            JSON.stringify(k) +
            ":" +
            stableJson((value as Record<string, unknown>)[k]),
        )
        .join(",") +
      "}"
    );
  return JSON.stringify(value);
}
export type Identity = { id: string; publicKey: string };
export type ProviderAccount = {
  id: string;
  identityId: string;
  provider: "x" | "github";
  subjectId: string;
  displayName: string;
  linkedAt: number;
  disconnectedAt?: number;
};
export type Resource = {
  id: string;
  provider: "github";
  kind: "repository";
  providerResourceId: string;
  displayName: string;
};
export type Relationship = {
  id: string;
  accountId: string;
  resourceId: string;
  relationship: "personal_owner";
  observedAt: number;
};
export type Attestation = {
  id: string;
  accountId: string;
  relationshipId: string | null;
  issuer: string;
  evidenceDigest: string;
  issuedAt: number;
  expiresAt: number;
};
export type ClaimReceipt = {
  id: string;
  accountId: string;
  offerId: string;
  network: string;
  authorizationDigest: string;
  dreggReceiptHash: string;
  transaction: string;
  status: "submitted" | "confirmed" | "finalized" | "failed";
  observedAt: number;
};
export type ReceiptReference = {
  schema: "wallet.reward-receipt-reference.v1";
  kind: "dregg-native" | "service-v1";
  digest: string;
};
export type ReferencedClaimReceipt = Omit<ClaimReceipt, "dreggReceiptHash"> & {
  receiptReference: ReceiptReference;
};
export type IdentityRecords = {
  schema: "castalia.identity-database.v1" | "castalia.identity-database.v2";
  version: 1 | 2;
  ownerPublicKey: string;
  identities: Identity[];
  accounts: ProviderAccount[];
  resources: Resource[];
  relationships: Relationship[];
  attestations: Attestation[];
  receipts: (ClaimReceipt | ReferencedClaimReceipt)[];
};
export type IdentityRecordsV2 = Omit<
  IdentityRecords,
  "schema" | "version" | "receipts"
> & {
  schema: "castalia.identity-database.v2";
  version: 2;
  receipts: ReferencedClaimReceipt[];
};
const tables = [
  "identities",
  "accounts",
  "resources",
  "relationships",
  "attestations",
  "receipts",
] as const;
function row(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("invalid_record");
  return value as Record<string, unknown>;
}
function keys(r: Record<string, unknown>, names: string[]) {
  if (Object.keys(r).sort().join(",") !== names.sort().join(","))
    throw new Error("unknown_or_missing_fields");
}
function str(v: unknown, max = 256): asserts v is string {
  if (
    typeof v !== "string" ||
    !v.length ||
    v.length > max ||
    /[\x00-\x1f]/.test(v)
  )
    throw new Error("invalid_text");
}
function hex(v: unknown) {
  if (typeof v !== "string" || !/^[a-f0-9]{64}$/.test(v))
    throw new Error("invalid_digest");
}
function time(v: unknown) {
  if (!Number.isSafeInteger(v) || (v as number) < 0)
    throw new Error("invalid_time");
}
function numeric(v: unknown) {
  if (typeof v !== "string" || !/^[1-9][0-9]{0,39}$/.test(v))
    throw new Error("invalid_provider_id");
}
function foreign(ids: Set<unknown>, id: unknown) {
  if (!ids.has(id)) throw new Error("foreign_key");
}
// Validated records can include a closed receipt-reference object; order is not data.
function sameRecord(left: unknown, right: unknown): boolean {
  return stableJson(row(left)) === stableJson(row(right));
}
export function emptyIdentityDatabase(ownerPublicKey: string): IdentityRecords {
  hex(ownerPublicKey);
  return {
    schema: "castalia.identity-database.v1",
    version: 1,
    ownerPublicKey,
    identities: [{ id: ownerPublicKey, publicKey: ownerPublicKey }],
    accounts: [],
    resources: [],
    relationships: [],
    attestations: [],
    receipts: [],
  };
}
/** Strict parsing is data validation, NOT verification of attestation signatures or chain finality. */
export function parseIdentityDatabase(
  value: unknown,
  ownerPublicKey: string,
): IdentityRecords {
  const db = row(value);
  keys(db, ["schema", "version", "ownerPublicKey", ...tables]);
  hex(ownerPublicKey);
  if (
    !(
      (db.schema === "castalia.identity-database.v1" && db.version === 1) ||
      (db.schema === "castalia.identity-database.v2" && db.version === 2)
    )
  )
    throw new Error("unsupported_schema");
  if (db.ownerPublicKey !== ownerPublicKey) throw new Error("owner_mismatch");
  const sets = new Map<string, Set<unknown>>();
  for (const table of tables) {
    const rows = db[table];
    if (!Array.isArray(rows) || rows.length > 1000)
      throw new Error("invalid_table");
    const ids = new Set();
    for (const item of rows) {
      const r = row(item);
      str(r.id);
      if (ids.has(r.id)) throw new Error("duplicate_id");
      ids.add(r.id);
    }
    sets.set(table, ids);
  }
  const ids = sets.get("identities")!,
    accounts = sets.get("accounts")!,
    resources = sets.get("resources")!,
    relationships = sets.get("relationships")!;
  const typed = db as unknown as IdentityRecords;
  if (typed.identities.length !== 1) throw new Error("invalid_identity");
  for (const x of typed.identities) {
    keys(row(x), ["id", "publicKey"]);
    if (x.id !== ownerPublicKey || x.publicKey !== ownerPublicKey)
      throw new Error("owner_mismatch");
  }
  const subjects = new Set<string>();
  for (const x of typed.accounts) {
    keys(row(x), [
      "id",
      "identityId",
      "provider",
      "subjectId",
      "displayName",
      "linkedAt",
      ...("disconnectedAt" in x ? ["disconnectedAt"] : []),
    ]);
    foreign(ids, x.identityId);
    if (x.provider !== "x" && x.provider !== "github")
      throw new Error("unsupported_provider");
    numeric(x.subjectId);
    str(x.displayName);
    time(x.linkedAt);
    if ("disconnectedAt" in x) time(x.disconnectedAt);
    const key = x.provider + ":" + x.subjectId;
    if (subjects.has(key)) throw new Error("duplicate_subject");
    subjects.add(key);
  }
  const resourceKeys = new Set<string>();
  for (const x of typed.resources) {
    keys(row(x), [
      "id",
      "provider",
      "kind",
      "providerResourceId",
      "displayName",
    ]);
    if (x.provider !== "github" || x.kind !== "repository")
      throw new Error("unsupported_resource");
    numeric(x.providerResourceId);
    str(x.displayName);
    const key = x.provider + ":" + x.providerResourceId;
    if (resourceKeys.has(key)) throw new Error("duplicate_resource");
    resourceKeys.add(key);
  }
  for (const x of typed.relationships) {
    keys(row(x), [
      "id",
      "accountId",
      "resourceId",
      "relationship",
      "observedAt",
    ]);
    foreign(accounts, x.accountId);
    foreign(resources, x.resourceId);
    if (
      x.relationship !== "personal_owner" ||
      typed.accounts.find((a) => a.id === x.accountId)?.provider !== "github"
    )
      throw new Error("unsupported_relationship");
    time(x.observedAt);
  }
  for (const x of typed.attestations) {
    keys(row(x), [
      "id",
      "accountId",
      "relationshipId",
      "issuer",
      "evidenceDigest",
      "issuedAt",
      "expiresAt",
    ]);
    foreign(accounts, x.accountId);
    if (x.relationshipId !== null) {
      foreign(relationships, x.relationshipId);
      if (
        typed.relationships.find((r) => r.id === x.relationshipId)
          ?.accountId !== x.accountId
      )
        throw new Error("foreign_key");
    }
    hex(x.issuer);
    hex(x.evidenceDigest);
    time(x.issuedAt);
    time(x.expiresAt);
    if (x.expiresAt <= x.issuedAt) throw new Error("invalid_expiry");
  }
  for (const x of typed.receipts) {
    keys(row(x), [
      "id",
      "accountId",
      "offerId",
      "network",
      "authorizationDigest",
      ...(db.version === 1 ? ["dreggReceiptHash"] : ["receiptReference"]),
      "transaction",
      "status",
      "observedAt",
    ]);
    foreign(accounts, x.accountId);
    hex(x.offerId);
    hex(x.authorizationDigest);
    if (db.version === 1) hex(row(x).dreggReceiptHash);
    else {
      const ref = row(row(x).receiptReference);
      keys(ref, ["schema", "kind", "digest"]);
      if (
        ref.schema !== "wallet.reward-receipt-reference.v1" ||
        (ref.kind !== "dregg-native" && ref.kind !== "service-v1")
      )
        throw new Error("unsupported_receipt_reference");
      hex(ref.digest);
    }
    str(x.network);
    str(x.transaction);
    time(x.observedAt);
    if (!["submitted", "confirmed", "finalized", "failed"].includes(x.status))
      throw new Error("invalid_status");
  }
  boundedUtf8(
    JSON.stringify(typed),
    MAX_IDENTITY_PLAINTEXT_BYTES,
    "identity_plaintext_too_large",
  );
  return structuredClone(typed);
}

/** Explicit data migration only; neither historical nor service references grant authority.
 * No Castaway writer is enabled here. Encryption and recovery formats are unchanged.
 */
export function migrateIdentityReceiptReferences(
  value: unknown,
  ownerPublicKey: string,
): IdentityRecordsV2 {
  const db = parseIdentityDatabase(value, ownerPublicKey);
  if (db.version === 2) return db as IdentityRecordsV2;
  return parseIdentityDatabase(
    {
      ...db,
      schema: "castalia.identity-database.v2",
      version: 2,
      receipts: db.receipts.map((receipt) => {
        const { dreggReceiptHash, ...rest } = receipt as ClaimReceipt;
        return {
          ...rest,
          receiptReference: {
            schema: "wallet.reward-receipt-reference.v1",
            kind: "dregg-native",
            digest: dreggReceiptHash,
          },
        };
      }),
    },
    ownerPublicKey,
  ) as IdentityRecordsV2;
}

/** Implemented by the existing Wallet custody Worker; this package never handles a key. */
export interface IdentityCipher {
  sealIdentitySection(value: string): Promise<string>;
  openIdentitySection(value: string): Promise<string>;
}
export type EncryptedSnapshot = {
  schema: "castalia.identity-storage.v1";
  ownerPublicKey: string;
  revision: number;
  ciphertext: string;
};
export interface SnapshotStore {
  read(): Promise<EncryptedSnapshot | null>;
  compareAndSwap(
    expectedRevision: number,
    next: EncryptedSnapshot,
  ): Promise<void>;
}

export class IdentityDatabase {
  private current: IdentityRecords | null = null;
  private revision = 0;
  private generation = 0;
  constructor(
    private owner: string,
    private store: SnapshotStore,
    private cipher: IdentityCipher,
  ) {
    hex(owner);
  }
  async unlock(): Promise<void> {
    this.lock();
    const generation = this.generation,
      saved = await this.store.read();
    let value = emptyIdentityDatabase(this.owner),
      revision = 0;
    if (saved) {
      keys(row(saved), ["schema", "ownerPublicKey", "revision", "ciphertext"]);
      if (
        saved.schema !== "castalia.identity-storage.v1" ||
        saved.ownerPublicKey !== this.owner
      )
        throw new Error("owner_mismatch");
      time(saved.revision);
      if (saved.revision < 1) throw new Error("invalid_revision");
      value = await this.openSnapshot(saved.ciphertext, saved.revision);
      revision = saved.revision;
    }
    this.checkGeneration(generation);
    this.current = value;
    this.revision = revision;
  }
  lock(): void {
    this.generation++;
    this.current = null;
    this.revision = 0;
  }
  snapshot(): IdentityRecords {
    if (!this.current) throw new Error("wallet_locked");
    return structuredClone(this.current);
  }
  async update(change: (draft: IdentityRecords) => void): Promise<void> {
    const generation = this.generation,
      expected = this.revision,
      draft = this.snapshot();
    change(draft);
    const records = parseIdentityDatabase(draft, this.owner),
      revision = expected + 1;
    time(revision);
    const plaintext = JSON.stringify({
      schema: "castalia.identity-snapshot.v1",
      revision,
      records,
    });
    boundedUtf8(
      plaintext,
      MAX_IDENTITY_PLAINTEXT_BYTES,
      "identity_plaintext_too_large",
    );
    const ciphertext = await this.cipher.sealIdentitySection(plaintext);
    this.checkGeneration(generation);
    // Authenticate and parse the exact envelope BEFORE replacing any durable data.
    const reopened = await this.openSnapshot(ciphertext, revision);
    if (stableJson(reopened) !== stableJson(records))
      throw new Error("identity_roundtrip_mismatch");
    this.checkGeneration(generation);
    await this.store.compareAndSwap(expected, {
      schema: "castalia.identity-storage.v1",
      ownerPublicKey: this.owner,
      revision,
      ciphertext,
    });
    this.checkGeneration(generation);
    this.current = records;
    this.revision = revision;
  }
  async import(value: unknown): Promise<void> {
    const incoming = parseIdentityDatabase(value, this.owner);
    await this.update((draft) => {
      if (incoming.version === 2 && draft.version === 1)
        Object.assign(
          draft,
          migrateIdentityReceiptReferences(draft, this.owner),
        );
      const source =
        draft.version === 2 && incoming.version === 1
          ? migrateIdentityReceiptReferences(incoming, this.owner)
          : incoming;
      for (const table of tables)
        for (const record of source[table]) {
          const existing = draft[table].find((r) => r.id === record.id);
          if (existing && !sameRecord(existing, record))
            throw new Error("import_conflict");
          if (!existing)
            (draft[table] as Array<{ id: string }>).push(
              structuredClone(record),
            );
        }
    });
  }
  async disconnect(accountId: string, at: number): Promise<void> {
    time(at);
    await this.update((draft) => {
      const account = draft.accounts.find((a) => a.id === accountId);
      if (!account) throw new Error("unknown_account");
      account.disconnectedAt = at;
    });
  }
  private checkGeneration(generation: number) {
    if (this.generation !== generation) throw new Error("wallet_locked");
  }
  private async openSnapshot(
    ciphertext: string,
    revision: number,
  ): Promise<IdentityRecords> {
    boundedUtf8(
      ciphertext,
      MAX_IDENTITY_ENVELOPE_BYTES,
      "identity_envelope_too_large",
    );
    str(ciphertext, MAX_IDENTITY_ENVELOPE_BYTES);
    const opened = await this.cipher.openIdentitySection(ciphertext);
    boundedUtf8(
      opened,
      MAX_IDENTITY_PLAINTEXT_BYTES,
      "identity_plaintext_too_large",
    );
    const plaintext = row(JSON.parse(opened));
    keys(plaintext, ["schema", "revision", "records"]);
    if (
      plaintext.schema !== "castalia.identity-snapshot.v1" ||
      plaintext.revision !== revision
    )
      throw new Error("snapshot_binding_mismatch");
    return parseIdentityDatabase(plaintext.records, this.owner);
  }
}

export function indexedDbIdentityStore(
  ownerPublicKey: string,
  factory: IDBFactory = indexedDB,
): SnapshotStore {
  hex(ownerPublicKey);
  function open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      let rejected = false;
      const request = factory.open("castalia-wallet-identities", 1);
      request.onupgradeneeded = () =>
        request.result.createObjectStore("snapshots");
      request.onsuccess = () => {
        if (rejected) request.result.close();
        else resolve(request.result);
      };
      request.onerror = () => reject(new Error("identity_storage_unavailable"));
      request.onblocked = () => {
        rejected = true;
        reject(new Error("identity_storage_blocked"));
      };
    });
  }
  return {
    async read() {
      const db = await open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("snapshots", "readonly"),
          request = tx.objectStore("snapshots").get(ownerPublicKey);
        tx.oncomplete = () => {
          db.close();
          resolve(request.result ?? null);
        };
        tx.onabort = tx.onerror = () => {
          db.close();
          reject(new Error("identity_read_failed"));
        };
      });
    },
    async compareAndSwap(expectedRevision, next) {
      if (
        next.ownerPublicKey !== ownerPublicKey ||
        next.revision !== expectedRevision + 1
      )
        throw new Error("snapshot_binding_mismatch");
      const db = await open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("snapshots", "readwrite"),
          store = tx.objectStore("snapshots"),
          request = store.get(ownerPublicKey);
        let conflict = false;
        request.onsuccess = () => {
          if ((request.result?.revision ?? 0) !== expectedRevision) {
            conflict = true;
            tx.abort();
          } else store.put(next, ownerPublicKey);
        };
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onabort = tx.onerror = () => {
          db.close();
          reject(
            new Error(conflict ? "revision_conflict" : "identity_write_failed"),
          );
        };
      });
    },
  };
}
