/** Encrypted Wallet data. Provider callers cannot enumerate or export this store. */
type D = {
    storage: {
        get(key: string): Promise<Record<string, any>>;
        set(v: Record<string, unknown>): Promise<void>;
    };
    owner(): string;
    now(): number;
    seal(raw: string): string;
    open(raw: string): string;
    review(grant: unknown, origin: string, installation: string): Promise<any>;
    reviewDerivation(stored: unknown, permissions: unknown, installation: string, expires: number): any;
    derive(stored: unknown, permissions: unknown, installation: string, expires: number): any;
    present(stored: unknown, credential: unknown, call: unknown): any;
    validateBackup(raw: string): string;
};
export function createHolderGrantsStore(d: D) {
    const key = () => `castalia-holder-grants-v1:${d.owner()}`;
    async function load() {
        const saved = (await d.storage.get(key()))[key()];
        if (saved === undefined)
            return { revision: 0, grants: {} as Record<string, any> };
        if (!saved || saved.schema !== 'castalia.holder-grant-storage.v1' || !Number.isSafeInteger(saved.revision) || saved.revision < 1 || typeof saved.ciphertext !== 'string' || Object.keys(saved).sort().join(',') !== 'ciphertext,revision,schema')
            throw Error('invalid_grant_storage');
        const backup = d.open(saved.ciphertext);
        return { revision: saved.revision, grants: JSON.parse(d.validateBackup(backup)) as Record<string, any> };
    }
    async function persist(grants: Record<string, any>, revision: number) { if (Object.keys(grants).length > 128 || !Number.isSafeInteger(revision + 1))
        throw Error('grant_capacity'); const raw = JSON.stringify({ schema: 'castalia.holder-grant-backup.v1', owner_public_key: d.owner(), grants }); d.validateBackup(raw); const ciphertext = d.seal(raw); await d.storage.set({ [key()]: { schema: 'castalia.holder-grant-storage.v1', revision: revision + 1, ciphertext } }); }
    return {
        async reviewForget(service: string) {
            if (typeof service !== 'string' || !service || service.length > 256) throw Error('invalid_service');
            const owner=d.owner(),saved=await load();
            if(!Object.hasOwn(saved.grants,service))throw Error('grant_not_saved');
            const stored=saved.grants[service];
            return {owner,service,revision:saved.revision,record:JSON.stringify(stored),grant:structuredClone(stored.grant.claims)};
        },
        /** Wallet-owned confirmation only; caller holds the shared custody FIFO.
         * Keep an encrypted empty collection and advance revision to prevent ABA. */
        async forget(prepared: {owner:string;service:string;revision:number;record:string}) {
            if(prepared.owner!==d.owner())throw Error('grant_storage_changed');
            const saved=await load();
            if(prepared.owner!==d.owner()||saved.revision!==prepared.revision||!Object.hasOwn(saved.grants,prepared.service)||JSON.stringify(saved.grants[prepared.service])!==prepared.record)throw Error('grant_storage_changed');
            delete saved.grants[prepared.service];
            await persist(saved.grants,saved.revision);
        },
        async prepare(grant: unknown, service: string, origin: string, installation: string, permissions: unknown = null) {
            const saved = await load();
            let reviewed: any;
            if (grant !== undefined)
                reviewed = await d.review(grant, origin, installation);
            else {
                const stored = saved.grants[service];
                if (!stored)
                    throw Error('grant_not_saved');
                reviewed = await d.review(stored.grant, origin, installation);
            }
            const stored = reviewed.stored;
            if (stored.pin.service !== service)
                throw Error('wrong_service');
            const expires = Math.min(d.now() + stored.grant.claims.max_credential_lifetime_seconds, stored.grant.claims.validity.not_after ?? Number.MAX_SAFE_INTEGER);
            const summary = d.reviewDerivation(stored, permissions, installation, expires);
            return { stored, permissions, expires, revision: saved.revision, summary };
        },
        async activate(prepared: any, save: boolean, installation: string) {
            const saved = await load();
            if (saved.revision !== prepared.revision)
                throw Error('grant_storage_changed');
            // Derivation revalidates signature, ownership, subset and clock after consent.
            const credential = d.derive(prepared.stored, prepared.permissions, installation, prepared.expires);
            if (save) {
                saved.grants[prepared.stored.pin.service] = prepared.stored;
                await persist(saved.grants, saved.revision);
            }
            return { credential, stored: prepared.stored, expires_at: credential.claims.expires_at };
        },
        present(stored: unknown, credential: unknown, call: unknown) { return d.present(stored, credential, call); },
        async assertRevision(revision: number) { if ((await load()).revision !== revision) throw Error('grant_storage_changed'); },
        async exportBackup() { const saved = (await d.storage.get(key()))[key()]; if (!saved)
            throw Error('grant_not_saved'); return saved.ciphertext as string; },
        async reviewBackup(file: string) { const incoming = JSON.parse(d.validateBackup(d.open(file))), saved = await load(); return { revision: saved.revision, grants: Object.values(incoming).map((g: any) => g.grant.claims) }; },
        async importBackup(file: string, expectedRevision: number) { const raw = d.open(file), incoming = JSON.parse(d.validateBackup(raw)), saved = await load(); if (saved.revision !== expectedRevision)
            throw Error("grant_storage_changed"); for (const [service, g] of Object.entries(incoming)) {
            if (saved.grants[service] && JSON.stringify(saved.grants[service]) !== JSON.stringify(g))
                throw Error('grant_backup_conflict');
            saved.grants[service] = g;
        } await persist(saved.grants, saved.revision); },
        async list() { const saved = await load(); return Object.values(saved.grants).map((g: any) => ({ service: g.pin.service, grant: g.grant.claims })); },
    };
}
