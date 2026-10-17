export type CredentialSummary = {
  issuer: string; holder_public_key: string; credential_digest_sha256: string;
  disclosure: {title: string; statements: string[]}; expires_at: number;
  [key: string]: unknown;
}
export type PreparedCredential = { summary(): CredentialSummary; approve(): unknown; dispose(): void }
type State = { memberKey: string; approvedOrigins: ReadonlySet<string> }
type Dependencies = {
  run<T>(operation: () => Promise<T>): Promise<T>; state(): Promise<State | null>; epoch(): number;
  current(): boolean; currentOrigin(): Promise<string>;
  prepare(raw: Uint8Array, caller: {kind:'browser';id:string}): PreparedCredential | Promise<PreparedCredential>;
  reserve(digest: string, expiresAt: number): Promise<void>;
  confirm(summary: CredentialSummary & {expiresAt:number}): Promise<boolean>;
}
/** Verified custody preparation remains owned until approval or disposal; never hold the queue over human input. */
export function createCredentialPresentationHandler(deps: Dependencies) {
  return async (payload: unknown, origin: string) => {
    const raw = new TextEncoder().encode(JSON.stringify(payload))
    if (raw.length > 262144) throw new Error('request_too_large')
    let prepared: PreparedCredential | undefined
    const assertCurrent = (epoch?: number) => {
      if (!deps.current() || epoch !== undefined && deps.epoch() !== epoch) throw new Error('presentation_context_changed')
    }
    try {
      const initial = await deps.run(async () => {
        assertCurrent()
        const epoch = deps.epoch()
        const currentOrigin = await deps.currentOrigin()
        assertCurrent(epoch)
        if (currentOrigin !== origin) throw new Error('presentation_context_changed')
        const state = await deps.state()
        assertCurrent(epoch)
        if (!state || !state.approvedOrigins.has(origin)) throw new Error('origin_not_approved')
        prepared = await deps.prepare(raw, {kind:'browser',id:origin})
        assertCurrent(epoch)
        const summary = prepared.summary()
        if (summary.holder_public_key !== state.memberKey) throw new Error('holder_mismatch')
        await deps.reserve(summary.credential_digest_sha256, summary.expires_at)
        assertCurrent(epoch)
        return { memberKey: state.memberKey, epoch, summary }
      })
      // A disconnected owner cannot create a new popup after cancellation ran.
      assertCurrent(initial.epoch)
      const approved = await deps.confirm({...initial.summary,expiresAt:initial.summary.expires_at})
      if (!approved) return {state:'denied' as const,reason:'approval_denied'}
      return await deps.run(async () => {
        assertCurrent(initial.epoch)
        const state = await deps.state()
        assertCurrent(initial.epoch)
        if (!state || !state.approvedOrigins.has(origin)) throw new Error('origin_not_approved')
        if (state.memberKey !== initial.memberKey) throw new Error('presentation_context_changed')
        // Read the initiating document after the state read, then check liveness
        // again. No await may separate the final check from custody approval.
        const currentOrigin = await deps.currentOrigin()
        assertCurrent(initial.epoch)
        if (currentOrigin !== origin) throw new Error('presentation_context_changed')
        return {state:'approved' as const,presentation:prepared!.approve()}
      })
    } finally { prepared?.dispose() }
  }
}
