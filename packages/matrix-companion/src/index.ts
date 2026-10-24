export const MATRIX_COMPANION_CAPABILITY = 'matrix_companion_v1' as const
export const MATRIX_COMPANION_APPROVAL_WINDOW_MS = 120_000

export type MatrixRoomSummary = {
  room_id: string
  kind: 'room' | 'space'
  name: string | null
  canonical_alias: string | null
  topic: string | null
  avatar_url: string | null
  /** Explicit Matrix Space parents. Empty for a root Space or unrelated room. */
  parent_space_ids: string[]
}

export type MatrixConnectionSummary = {
  schema: 'castalia.matrix-connection.v1'
  connection_handle: string
  homeserver: string
  user_id: string
}

export type MatrixDelivery = {
  schema: 'castalia.matrix-delivery.v1'
  delivery_handle: string
  transaction_id: string
  state: 'sent' | 'unknown' | 'failed'
  event_id: string | null
}

export type MatrixApprovalStatus = {
  schema: 'castalia.matrix-approval-status.v1'
  state: 'pending' | 'approved' | 'denied' | 'expired'
  result: MatrixConnectionSummary | MatrixDelivery | null
}

export type MatrixTransport = {
  restore(sealedState: Uint8Array): Promise<void>
  snapshot(): Promise<Uint8Array>
  connections(): Promise<MatrixConnectionSummary[]>
  connect(input: {connection_handle: string; homeserver: string; user_id: string}): Promise<MatrixConnectionSummary>
  listRooms(input: {connection_handle: string}): Promise<MatrixRoomSummary[]>
  send(input: {connection_handle: string; room_id: string; body: string; transaction_id: string}): Promise<{state: 'sent' | 'unknown' | 'failed'; event_id: string | null}>
  reconcile(input: {delivery_handle: string; transaction_id: string}): Promise<{state: 'sent' | 'unknown' | 'failed'; event_id: string | null}>
  logout(input: {connection_handle: string}): Promise<void>
}

export type ProtectedStateStore = {
  load(): Promise<{revision: number; sealed_state: Uint8Array} | null>
  compareAndSwap(expectedRevision: number | null, sealedState: Uint8Array): Promise<number>
}

type Approval = {
  kind: 'connect' | 'send'
  expiresAt: number
  payload: Record<string, string>
}

type Dependencies = {
  now(): number
  randomId(): string
  store: ProtectedStateStore
  transport: MatrixTransport
}

export type MatrixCompanion = {
  getCapabilities(): Promise<readonly string[]>
  getStatus(): Promise<{schema: 'castalia.matrix-status.v1'; state: 'connected' | 'disconnected'; connections: MatrixConnectionSummary[]}>
  prepareConnection(input: unknown): Promise<{schema: 'castalia.matrix-connection-approval.v1'; approval_id: string; expires_at: number; homeserver: string; user_id: string}>
  getApprovalStatus(input: unknown): Promise<MatrixApprovalStatus>
  listRooms(input: unknown): Promise<{schema: 'castalia.matrix-room-page.v1'; rooms: MatrixRoomSummary[]; next_cursor: string | null}>
  prepareSend(input: unknown): Promise<{schema: 'castalia.matrix-send-approval.v1'; approval_id: string; expires_at: number; transaction_id: string; preview: {room_id: string; body: string}}>
  reconcileDelivery(input: unknown): Promise<MatrixDelivery>
  logout(input: unknown): Promise<{schema: 'castalia.matrix-logout-result.v1'; state: 'logged_out'}>
}

export type MatrixCompanionReadClient = Pick<MatrixCompanion, 'getCapabilities' | 'getStatus' | 'listRooms'>

export type MatrixCompanionApprovals = {
  /** Trusted Wallet UI only. Never expose this controller to an application origin. */
  approve(input: unknown): Promise<MatrixConnectionSummary | MatrixDelivery>
  deny(input: unknown): Promise<{schema: 'castalia.matrix-approval-result.v1'; state: 'denied'}>
}

export type MatrixCompanionHost = {
  /** Application-facing API. */
  client: MatrixCompanion
  /** Wallet-owned UI/controller boundary. */
  approvals: MatrixCompanionApprovals
}

function exact(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw new Error('invalid_shape')
}
function text(value: unknown, max: number): asserts value is string {
  if (typeof value !== 'string' || value.length < 1 || value.length > max || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value)) throw new Error('invalid_text')
}
function handle(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9._:-]{1,200}$/.test(value)) throw new Error('invalid_handle')
}
function homeserver(value: unknown): asserts value is string {
  text(value, 300)
  const url = new URL(value)
  if (url.origin !== value || url.protocol !== 'https:' || url.username || url.password) throw new Error('invalid_homeserver')
}
function userId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^@[A-Za-z0-9._=\-/]+:[A-Za-z0-9.-]+$/.test(value) || value.length > 255) throw new Error('invalid_user_id')
}
function nullableText(value: unknown, max: number): asserts value is string | null {
  if (value !== null) text(value, max)
}
function parseConnectionSummary(value: unknown): MatrixConnectionSummary {
  exact(value, ['schema', 'connection_handle', 'homeserver', 'user_id'])
  if (value.schema !== 'castalia.matrix-connection.v1') throw new Error('unsupported_version')
  handle(value.connection_handle); homeserver(value.homeserver); userId(value.user_id)
  return {...value} as MatrixConnectionSummary
}
function parseRoomSummary(value: unknown): MatrixRoomSummary {
  exact(value, ['room_id', 'kind', 'name', 'canonical_alias', 'topic', 'avatar_url', 'parent_space_ids'])
  text(value.room_id, 255)
  if (!(value.room_id as string).startsWith('!') || !['room', 'space'].includes(value.kind as string)) throw new Error('invalid_room')
  nullableText(value.name, 255); nullableText(value.topic, 4096); nullableText(value.canonical_alias, 255); nullableText(value.avatar_url, 2048)
  if (value.canonical_alias !== null && !(value.canonical_alias as string).startsWith('#')) throw new Error('invalid_room_alias')
  if (value.avatar_url !== null && !/^mxc:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_-]+$/.test(value.avatar_url as string)) throw new Error('invalid_avatar_url')
  if (!Array.isArray(value.parent_space_ids) || value.parent_space_ids.length > 64) throw new Error('invalid_space_parents')
  const parents = new Set<string>()
  for (const parent of value.parent_space_ids) {
    text(parent, 255)
    if (!parent.startsWith('!') || parents.has(parent)) throw new Error('invalid_space_parents')
    parents.add(parent)
  }
  return {...value} as MatrixRoomSummary
}
function parseTransportDelivery(value: unknown): {state: 'sent' | 'unknown' | 'failed'; event_id: string | null} {
  exact(value, ['state', 'event_id'])
  if (!['sent', 'unknown', 'failed'].includes(value.state as string)) throw new Error('invalid_delivery_state')
  if (value.event_id !== null) {
    text(value.event_id, 255)
    if (!(value.event_id as string).startsWith('$')) throw new Error('invalid_event_id')
  }
  return {...value} as {state: 'sent' | 'unknown' | 'failed'; event_id: string | null}
}

export function parseListRoomsRequest(value: unknown): {schema: 'castalia.matrix-list-rooms-request.v1'; connection_handle: string; limit: number; cursor: string | null} {
  exact(value, ['schema', 'connection_handle', 'limit', 'cursor'])
  if (value.schema !== 'castalia.matrix-list-rooms-request.v1') throw new Error('unsupported_version')
  handle(value.connection_handle)
  if (!Number.isSafeInteger(value.limit) || (value.limit as number) < 1 || (value.limit as number) > 100) throw new Error('invalid_limit')
  if (value.cursor !== null) handle(value.cursor)
  return value as ReturnType<typeof parseListRoomsRequest>
}

function parseConnectionRequest(value: unknown) {
  exact(value, ['schema', 'homeserver', 'user_id'])
  if (value.schema !== 'castalia.matrix-connection-request.v1') throw new Error('unsupported_version')
  homeserver(value.homeserver); userId(value.user_id)
  return value as {schema: 'castalia.matrix-connection-request.v1'; homeserver: string; user_id: string}
}
function parseTrustedApproval(value: unknown) {
  exact(value, ['schema', 'approval_id'])
  if (value.schema !== 'castalia.matrix-trusted-approval.v1') throw new Error('unsupported_version')
  handle(value.approval_id)
  return value as {schema: 'castalia.matrix-trusted-approval.v1'; approval_id: string}
}
function parseSendRequest(value: unknown) {
  exact(value, ['schema', 'connection_handle', 'room_id', 'body', 'client_request_id'])
  if (value.schema !== 'castalia.matrix-send-request.v1') throw new Error('unsupported_version')
  handle(value.connection_handle); text(value.room_id, 255); text(value.body, 65_536); handle(value.client_request_id)
  if (!(value.room_id as string).startsWith('!')) throw new Error('invalid_room_id')
  return value as {schema: 'castalia.matrix-send-request.v1'; connection_handle: string; room_id: string; body: string; client_request_id: string}
}
function parseReconcileRequest(value: unknown) {
  exact(value, ['schema', 'delivery_handle'])
  if (value.schema !== 'castalia.matrix-reconcile-request.v1') throw new Error('unsupported_version')
  handle(value.delivery_handle)
  return value as {schema: 'castalia.matrix-reconcile-request.v1'; delivery_handle: string}
}
function parseLogoutRequest(value: unknown) {
  exact(value, ['schema', 'connection_handle'])
  if (value.schema !== 'castalia.matrix-logout-request.v1') throw new Error('unsupported_version')
  handle(value.connection_handle)
  return value as {schema: 'castalia.matrix-logout-request.v1'; connection_handle: string}
}
function parseApprovalStatusRequest(value: unknown) {
  exact(value, ['schema', 'approval_id'])
  if (value.schema !== 'castalia.matrix-approval-status-request.v1') throw new Error('unsupported_version')
  handle(value.approval_id)
  return value as {schema: 'castalia.matrix-approval-status-request.v1'; approval_id: string}
}

export async function createMatrixCompanion(deps: Dependencies): Promise<MatrixCompanionHost> {
  let storeRevision: number | null = null
  const stored = await deps.store.load()
  if (stored) {
    if (!Number.isSafeInteger(stored.revision) || stored.revision < 1) throw new Error('invalid_store_revision')
    await deps.transport.restore(stored.sealed_state)
    storeRevision = stored.revision
  }
  const approvals = new Map<string, Approval>()
  const approvalOutcomes = new Map<string, MatrixApprovalStatus>()
  const transactions = new Map<string, {fingerprint: string; transactionId: string}>()
  const deliveries = new Map<string, MatrixDelivery>()

  const persist = async () => {
    storeRevision = await deps.store.compareAndSwap(storeRevision, await deps.transport.snapshot())
  }
  const connections = async () => (await deps.transport.connections()).map(parseConnectionSummary)
  const requireConnection = async (connectionHandle: string) => {
    if (!(await connections()).some(item => item.connection_handle === connectionHandle)) throw new Error('connection_unavailable')
  }
  const issueApproval = (kind: Approval['kind'], payload: Approval['payload']) => {
    const approvalId = `approval-${deps.randomId()}`
    const expiresAt = deps.now() + MATRIX_COMPANION_APPROVAL_WINDOW_MS
    approvals.set(approvalId, {kind, expiresAt, payload})
    return {approvalId, expiresAt}
  }
  const consumeApproval = (input: ReturnType<typeof parseTrustedApproval>) => {
    const approval = approvals.get(input.approval_id)
    approvals.delete(input.approval_id)
    if (!approval) throw new Error('approval_unavailable')
    if (deps.now() > approval.expiresAt) {
      approvalOutcomes.set(input.approval_id, {schema: 'castalia.matrix-approval-status.v1', state: 'expired', result: null})
      throw new Error('approval_expired')
    }
    return approval
  }

  const client: MatrixCompanion = {
    async getCapabilities() { return [MATRIX_COMPANION_CAPABILITY] },
    async getStatus() {
      const current = await connections()
      return {schema: 'castalia.matrix-status.v1', state: current.length ? 'connected' : 'disconnected', connections: current}
    },
    async prepareConnection(input) {
      const request = parseConnectionRequest(input)
      const approval = issueApproval('connect', {homeserver: request.homeserver, user_id: request.user_id})
      return {schema: 'castalia.matrix-connection-approval.v1', approval_id: approval.approvalId, expires_at: approval.expiresAt, homeserver: request.homeserver, user_id: request.user_id}
    },
    async getApprovalStatus(input) {
      const request = parseApprovalStatusRequest(input)
      const outcome = approvalOutcomes.get(request.approval_id)
      if (outcome) return {...outcome, result: outcome.result && {...outcome.result}}
      const approval = approvals.get(request.approval_id)
      if (!approval) throw new Error('approval_unavailable')
      if (deps.now() > approval.expiresAt) {
        approvals.delete(request.approval_id)
        const expired: MatrixApprovalStatus = {schema: 'castalia.matrix-approval-status.v1', state: 'expired', result: null}
        approvalOutcomes.set(request.approval_id, expired)
        return expired
      }
      return {schema: 'castalia.matrix-approval-status.v1', state: 'pending', result: null}
    },
    async listRooms(input) {
      const request = parseListRoomsRequest(input)
      await requireConnection(request.connection_handle)
      let offset = 0
      if (request.cursor !== null) {
        const match = /^matrix-page-([0-9]+)$/.exec(request.cursor)
        if (!match) throw new Error('invalid_cursor')
        offset = Number(match[1])
      }
      const rooms = (await deps.transport.listRooms({connection_handle: request.connection_handle})).map(parseRoomSummary)
      const page = rooms.slice(offset, offset + request.limit)
      const next = offset + page.length < rooms.length ? `matrix-page-${offset + page.length}` : null
      return {schema: 'castalia.matrix-room-page.v1', rooms: page, next_cursor: next}
    },
    async prepareSend(input) {
      const request = parseSendRequest(input)
      await requireConnection(request.connection_handle)
      const fingerprint = JSON.stringify([request.connection_handle, request.room_id, request.body])
      const old = transactions.get(request.client_request_id)
      if (old && old.fingerprint !== fingerprint) throw new Error('client_request_conflict')
      const transactionId = old?.transactionId ?? `matrix-txn-${deps.randomId()}`
      transactions.set(request.client_request_id, {fingerprint, transactionId})
      const approval = issueApproval('send', {connection_handle: request.connection_handle, room_id: request.room_id, body: request.body, transaction_id: transactionId})
      return {schema: 'castalia.matrix-send-approval.v1', approval_id: approval.approvalId, expires_at: approval.expiresAt, transaction_id: transactionId, preview: {room_id: request.room_id, body: request.body}}
    },
    async reconcileDelivery(input) {
      const request = parseReconcileRequest(input)
      const delivery = deliveries.get(request.delivery_handle)
      if (!delivery) throw new Error('delivery_unavailable')
      const result = parseTransportDelivery(await deps.transport.reconcile({delivery_handle: delivery.delivery_handle, transaction_id: delivery.transaction_id}))
      const reconciled = {...delivery, state: result.state, event_id: result.event_id}
      deliveries.set(delivery.delivery_handle, reconciled)
      await persist()
      return reconciled
    },
    async logout(input) {
      const request = parseLogoutRequest(input)
      await requireConnection(request.connection_handle)
      await deps.transport.logout({connection_handle: request.connection_handle})
      await persist()
      return {schema: 'castalia.matrix-logout-result.v1', state: 'logged_out'}
    },
  }

  const trustedApprovals: MatrixCompanionApprovals = {
    async approve(input) {
      const approval = consumeApproval(parseTrustedApproval(input))
      const payload = approval.payload
      if (approval.kind === 'connect') {
        const connection = parseConnectionSummary(await deps.transport.connect({connection_handle: `matrix-connection-${deps.randomId()}`, homeserver: payload.homeserver!, user_id: payload.user_id!}))
        await persist()
        approvalOutcomes.set((input as {approval_id: string}).approval_id, {schema: 'castalia.matrix-approval-status.v1', state: 'approved', result: connection})
        return connection
      }
      await requireConnection(payload.connection_handle!)
      const result = parseTransportDelivery(await deps.transport.send({connection_handle: payload.connection_handle!, room_id: payload.room_id!, body: payload.body!, transaction_id: payload.transaction_id!}))
      const delivery: MatrixDelivery = {schema: 'castalia.matrix-delivery.v1', delivery_handle: `matrix-delivery-${deps.randomId()}`, transaction_id: payload.transaction_id!, state: result.state, event_id: result.event_id}
      deliveries.set(delivery.delivery_handle, delivery)
      await persist()
      approvalOutcomes.set((input as {approval_id: string}).approval_id, {schema: 'castalia.matrix-approval-status.v1', state: 'approved', result: delivery})
      return delivery
    },
    async deny(input) {
      const parsed = parseTrustedApproval(input)
      if (!approvals.delete(parsed.approval_id)) throw new Error('approval_unavailable')
      approvalOutcomes.set(parsed.approval_id, {schema: 'castalia.matrix-approval-status.v1', state: 'denied', result: null})
      return {schema: 'castalia.matrix-approval-result.v1', state: 'denied'}
    },
  }
  return {client, approvals: trustedApprovals}
}

export function createMemoryProtectedStore(): ProtectedStateStore & {inspectFixtureBytes(): Uint8Array | null} {
  let value: {revision: number; sealed_state: Uint8Array} | null = null
  return {
    async load() { return value && {revision: value.revision, sealed_state: value.sealed_state.slice()} },
    async compareAndSwap(expectedRevision, sealedState) {
      if ((value?.revision ?? null) !== expectedRevision) throw new Error('stale_store_revision')
      const revision = (value?.revision ?? 0) + 1
      value = {revision, sealed_state: sealedState.slice()}
      return revision
    },
    inspectFixtureBytes() { return value?.sealed_state.slice() ?? null },
  }
}

export function createFixtureMatrixTransport(options: {sendState?: 'sent' | 'unknown'} = {}): MatrixTransport {
  type PrivateState = {connections: Array<MatrixConnectionSummary & {access_token: string}>}
  let state: PrivateState = {connections: []}
  const rooms: MatrixRoomSummary[] = [
    {room_id: '!anima-space:example', kind: 'space', name: 'Anima', canonical_alias: '#anima:example', topic: 'Fixture Space metadata', avatar_url: null, parent_space_ids: []},
    {room_id: '!requests:example', kind: 'room', name: 'Requests', canonical_alias: '#requests:example', topic: 'Fixture request transport', avatar_url: 'mxc://example/fixture', parent_space_ids: ['!anima-space:example']},
  ]
  const knownTransactions = new Map<string, {state: 'sent' | 'unknown' | 'failed'; event_id: string | null}>()
  return {
    async restore(bytes) {
      const parsed = JSON.parse(new TextDecoder().decode(bytes)) as PrivateState
      state = {connections: parsed.connections.map(item => ({...item}))}
    },
    async snapshot() { return new TextEncoder().encode(JSON.stringify(state)) },
    async connections() { return state.connections.map(({access_token: _token, ...summary}) => ({...summary})) },
    async connect(input) {
      const connection: MatrixConnectionSummary & {access_token: string} = {schema: 'castalia.matrix-connection.v1', ...input, access_token: 'fixture-access-token-private'}
      state.connections.push(connection)
      const {access_token: _token, ...summary} = connection
      return summary
    },
    async listRooms(input) {
      if (!state.connections.some(item => item.connection_handle === input.connection_handle)) throw new Error('connection_unavailable')
      return rooms.map(room => ({...room}))
    },
    async send(input) {
      const old = knownTransactions.get(input.transaction_id)
      if (old) return old
      const result = options.sendState === 'unknown' ? {state: 'unknown' as const, event_id: null} : {state: 'sent' as const, event_id: `$fixture-${input.transaction_id}`}
      knownTransactions.set(input.transaction_id, result)
      return result
    },
    async reconcile(input) {
      const old = knownTransactions.get(input.transaction_id)
      if (!old) return {state: 'failed', event_id: null}
      if (old.state === 'unknown') {
        const resolved = {state: 'sent' as const, event_id: `$fixture-${input.transaction_id}`}
        knownTransactions.set(input.transaction_id, resolved)
        return resolved
      }
      return old
    },
    async logout(input) { state.connections = state.connections.filter(item => item.connection_handle !== input.connection_handle) },
  }
}

/** App-safe read fixture. It intentionally withholds connection/send preparation and trusted approvals. */
export async function createFixtureMatrixReadClient(deps: {now(): number; randomId(): string}): Promise<MatrixCompanionReadClient> {
  const host = await createMatrixCompanion({
    ...deps,
    store: createMemoryProtectedStore(),
    transport: createFixtureMatrixTransport(),
  })
  const prepared = await host.client.prepareConnection({schema: 'castalia.matrix-connection-request.v1', homeserver: 'https://matrix.example', user_id: '@anima:example'})
  await host.approvals.approve({schema: 'castalia.matrix-trusted-approval.v1', approval_id: prepared.approval_id})
  return {
    getCapabilities: host.client.getCapabilities,
    getStatus: host.client.getStatus,
    listRooms: host.client.listRooms,
  }
}
