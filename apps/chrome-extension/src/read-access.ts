/** Generic, document-bound read connections. Custody never enters the application. */
export type ReadContext = {
  origin: string;
  documentId: string;
  tabId: number;
  current(): boolean;
  verify?(): Promise<void>;
};
export type ReadHandle = {
  summary(): any;
  approve(): any;
  accept(credential: unknown): any;
  present(call: unknown, origin: string): any;
  dispose(): void;
};
type State = { memberKey: string; approvedOrigins: ReadonlySet<string> };
type Dependencies = {
  run<T>(f: () => Promise<T>): Promise<T>;
  state(): Promise<State | null>;
  epoch(): number;
  installation(): Promise<string>;
  memberships(origin: string): Promise<any[]>;
  membership(
    origin: string,
    holder: string,
    profileId?: string,
  ): Promise<unknown>;
  prepare(
    challenge: unknown,
    origin: string,
    installation: string,
  ): Promise<ReadHandle>;
  prepareRequest?(challenge: unknown, origin: string, installation: string): Promise<Pick<ReadHandle, "summary" | "approve" | "dispose">>;
  confirm(summary: any, context: ReadContext): Promise<boolean>;
  randomId(): string;
  now(): number;
  holderGrants?: ReturnType<typeof import("./holder-grants-store.js").createHolderGrantsStore>;
  setupStatus?(profile: unknown, origin: string): Promise<unknown>;
};
type Entry = {
  handle: ReadHandle;
  origin: string;
  documentId: string;
  tabId: number;
  epoch: number;
  profileId?: string;
  accepted: boolean;
  graphV2: boolean;
  expires: number;
};
const object = (v: unknown): v is Record<string, any> =>
  !!v &&
  typeof v === "object" &&
  !Array.isArray(v) &&
  Object.getPrototypeOf(v) === Object.prototype;
export function createReadAccessController(deps: Dependencies) {
  const entries = new Map<string, Entry>();
  const grants = new Map<string, {context:ReadContext;epoch:number;expires:number;stored:unknown;credential:unknown}>();
  const forget = (id: string) => {
    const e = entries.get(id);
    if (e) {
      entries.delete(id);
      e.handle.dispose();
    }
  };
  const invalidate = (tabId?: number) => {
    const affected = new Map<string, { tabId: number; documentId: string }>();
    for (const [id, e] of entries)
      if (tabId === undefined || e.tabId === tabId) {
        affected.set(e.documentId, {
          tabId: e.tabId,
          documentId: e.documentId,
        });
        forget(id);
      }
    for(const [id,e] of grants)if(tabId===undefined||e.context.tabId===tabId){affected.set(e.context.documentId,e.context);grants.delete(id)}
    return [...affected.values()];
  };
  async function state(context: ReadContext, epoch: number) {
    if (!context.current() || deps.epoch() !== epoch)
      throw new Error("read_context_changed");
    await context.verify?.();
    const current = await deps.state();
    await context.verify?.();
    if (!context.current() || deps.epoch() !== epoch)
      throw new Error("read_context_changed");
    if (!current) throw new Error("wallet_locked");
    if (!current.approvedOrigins.has(context.origin))
      throw new Error("origin_not_approved");
    return current;
  }
  async function handle(input: unknown, context: ReadContext): Promise<any> {
    if (
      !object(input) ||
      typeof input.operation !== "string" ||
      new TextEncoder().encode(JSON.stringify(input)).length > 131072
    )
      throw new Error("invalid_read_request");
    const fields: Record<string, string[]> = {
      save_grant:["operation","service","grant","permissions"],
      use_grant:["operation","service","permissions"],
      present_grant:["operation","accessId","call"],
      setup_status: ["operation", "profile"],
      identity: ["operation"],
      approve: ["operation", "challenge", "profileId"],
      approve_graph_v2: ["operation", "challenge", "profileId"],
      request: ["operation", "challenge", "profileId"],
      accept: ["operation", "accessId", "credential"],
      accept_graph_v2: ["operation", "accessId", "credential"],
      present: ["operation", "accessId", "call"],
      present_graph_v2: ["operation", "accessId", "call"],
      disconnect: ["operation", "accessId"],
    };
    if (
      !fields[input.operation] ||
      Object.keys(input).some((k) => !fields[input.operation].includes(k))
    )
      throw new Error("invalid_read_request");
    for (const [id, e] of entries) if (e.expires <= deps.now()) forget(id);
    for(const [id,e]of grants)if(e.expires<=deps.now())grants.delete(id);
    if(input.operation==='save_grant'||input.operation==='use_grant'){
      if(!deps.holderGrants||typeof input.service!=='string'||input.service.length>256||!input.service||input.operation==='save_grant'&&!object(input.grant)||input.permissions!==undefined&&!Array.isArray(input.permissions))throw Error('invalid_read_request');
      if(entries.size+grants.size>=128)throw Error('read_capacity');
      const epoch=deps.epoch(),save=input.operation==='save_grant';
      const prepared=await deps.run(async()=>{await state(context,epoch);const installation=await deps.installation();const p=await deps.holderGrants!.prepare(save?input.grant:undefined,input.service,context.origin,installation,input.permissions??null);await state(context,epoch);return p});
      const approvalExpires=Math.min(deps.now()+120,prepared.expires);
      if(!await deps.confirm({...prepared.summary,kind:'holder_grant',save,origin:context.origin,receiver:input.service,approval_expires_at:approvalExpires},context))throw Error('approval_denied');
      return deps.run(async()=>{await state(context,epoch);if(deps.now()>=approvalExpires)throw Error('read_approval_expired');const result=await deps.holderGrants!.activate(prepared,save,await deps.installation());await state(context,epoch);const accessId=deps.randomId();grants.set(accessId,{context,epoch,expires:result.expires_at,stored:result.stored,credential:result.credential});return {accessId,service:input.service,expires_at:result.expires_at,state:save?'saved':'ready'}});
    }
    if(input.operation==='present_grant')return deps.run(async()=>{
      const e=typeof input.accessId==='string'?grants.get(input.accessId):undefined;
      if(!e||!deps.holderGrants||e.context.origin!==context.origin||e.context.documentId!==context.documentId||e.context.tabId!==context.tabId||!object(input.call))throw Error('read_access_required');
      await state(context,e.epoch);if(deps.now()>=e.expires){grants.delete(input.accessId);throw Error('read_access_expired')}
      return deps.holderGrants.present(e.stored,e.credential,input.call);
    });
    if (input.operation === "setup_status") return deps.run(async () => {
      if (!deps.setupStatus || !object(input.profile)) throw new Error("invalid_read_request");
      const epoch = deps.epoch();
      const check = async () => {
        if (!context.current() || deps.epoch() !== epoch) throw new Error("read_context_changed");
        await context.verify?.();
        if (!context.current() || deps.epoch() !== epoch) throw new Error("read_context_changed");
      };
      await check();
      const result = await deps.setupStatus(input.profile, context.origin);
      await check();
      return result;
    });
    if (input.operation === "identity")
      return deps.run(async () => {
        const epoch = deps.epoch(),
          s = await state(context, epoch),
          installation_id = await deps.installation(),
          memberships = await deps.memberships(context.origin);
        await state(context, epoch);
        return {
          subject_public_key: s.memberKey,
          installation_id,
          memberships,
        };
      });
    if (input.operation === "request") {
      if (!object(input.challenge) || (input.profileId !== undefined && typeof input.profileId !== "string")) throw new Error("invalid_read_request");
      if (!deps.prepareRequest) throw new Error("wallet_upgrade_required");
      const epoch = deps.epoch();
      let prepared: Pick<ReadHandle, "summary" | "approve" | "dispose"> | undefined;
      try {
        const summary = await deps.run(async () => {
          const current = await state(context, epoch);
          const installation = await deps.installation();
          if(input.profileId!==undefined)await deps.membership(context.origin, current.memberKey, input.profileId);
          await state(context, epoch);
          prepared = await deps.prepareRequest!(input.challenge, context.origin, installation);
          await state(context, epoch);
          return {...prepared.summary(),membershipIncluded:input.profileId!==undefined};
        });
        if (!(await deps.confirm(summary, context))) throw new Error("approval_denied");
        return await deps.run(async () => {
          const current = await state(context, epoch);
          const proof = input.profileId!==undefined?await deps.membership(context.origin, current.memberKey, input.profileId):{};
          await state(context, epoch);
          return {approval: {...prepared!.approve(), proof}};
        });
      } finally { prepared?.dispose(); }
    }
    if (input.operation === "approve" || input.operation === "approve_graph_v2") {
      const graphV2 = input.operation === "approve_graph_v2";
      if (
        !object(input.challenge) ||
        (input.profileId !== undefined && typeof input.profileId !== "string")
      )
        throw new Error("invalid_read_request");
      if (entries.size >= 128) throw new Error("read_capacity");
      const epoch = deps.epoch();
      let prepared: ReadHandle | undefined;
      try {
        const initial = await deps.run(async () => {
          const s = await state(context, epoch),
            installation = await deps.installation();
          await state(context, epoch);
          // Legacy read access retains its membership gate. V2 is explicit:
          // empty proof is permitted only when no membership was selected;
          // receiver resource policy still decides whether that is sufficient.
          const proof = graphV2 && input.profileId === undefined ? {} : await deps.membership(
            context.origin,
            s.memberKey,
            input.profileId,
          );
          await state(context, epoch);
          prepared = await deps.prepare(
            input.challenge,
            context.origin,
            installation,
          );
          await state(context, epoch);
          return { proof, summary: { ...prepared.summary(), membershipIncluded: !graphV2 || input.profileId !== undefined } };
        });
        if (!context.current() || deps.epoch() !== epoch)
          throw new Error("read_context_changed");
        if (!(await deps.confirm(initial.summary, context)))
          throw new Error("approval_denied");
        return await deps.run(async () => {
          const s = await state(context, epoch);
          // Legacy read access retains its membership gate. V2 is explicit:
          // empty proof is permitted only when no membership was selected;
          // receiver resource policy still decides whether that is sufficient.
          const proof = graphV2 && input.profileId === undefined ? {} : await deps.membership(
            context.origin,
            s.memberKey,
            input.profileId,
          );
          await state(context, epoch);
          const approval = prepared!.approve(),
            accessId = deps.randomId();
          entries.set(accessId, {
            handle: prepared!,
            origin: context.origin,
            documentId: context.documentId,
            tabId: context.tabId,
            epoch,
            profileId: input.profileId,
            accepted: false,
            graphV2,
            expires: initial.summary.approval_expires_at,
          });
          prepared = undefined;
          return { accessId, enrollment: { ...approval, proof } };
        });
      } finally {
        prepared?.dispose();
      }
    }
    if(input.operation==='disconnect'&&typeof input.accessId==='string'&&grants.has(input.accessId)){
      const e=grants.get(input.accessId)!;if(e.context.origin!==context.origin||e.context.documentId!==context.documentId||e.context.tabId!==context.tabId)throw Error('read_access_required');grants.delete(input.accessId);return {state:'disconnected'};
    }
    if (typeof input.accessId !== "string")
      throw new Error("invalid_read_request");
    const e = entries.get(input.accessId);
    if (
      !e ||
      e.origin !== context.origin ||
      e.documentId !== context.documentId ||
      e.tabId !== context.tabId
    )
      throw new Error("read_access_required");
    if (input.operation === "disconnect") {
      forget(input.accessId);
      return { state: "disconnected" };
    }
    const graphV2 = input.operation === "accept_graph_v2" || input.operation === "present_graph_v2";
    if (graphV2 !== e.graphV2) throw new Error("read_protocol_mismatch");
    try {
      return await deps.run(async () => {
        const s = await state(context, e.epoch);
        if (deps.now() >= e.expires) throw new Error("read_access_expired");
        if (!e.graphV2 || e.profileId !== undefined) await deps.membership(context.origin, s.memberKey, e.profileId);
        await state(context, e.epoch);
        if (input.operation === "accept" || input.operation === "accept_graph_v2") {
          if (e.accepted || !object(input.credential))
            throw new Error("invalid_read_request");
          const result = e.handle.accept(input.credential);
          e.accepted = true;
          e.expires = result.expires_at;
          return { accessId: input.accessId, ...result };
        }
        if (!e.accepted) throw new Error("read_access_required");
        if (!object(input.call)) throw new Error("invalid_read_request");
        return e.handle.present(input.call, context.origin);
      });
    } catch (error) {
      if (e.accepted || input.operation === "accept") forget(input.accessId);
      throw error;
    }
  }
  return { handle, invalidate };
}
