import {
  createProviderProfileStore,
  parseProviderProfile,
  profileOrigin,
  providerProfileBytes,
  PROVIDER_PROFILE_CAPABILITIES,
  type ProviderProfileV1,
} from '@castalia-wallet/provider-types'
import {
  issueZenithMembership,
  verifyZenithMembershipCredential,
  zenithMembershipJoinTranscript,
} from '@castalia-wallet/zenith-membership'
import { createOperationConfirmationBroker } from './operation-confirmation-broker.js'

type State = { memberKey: string; approvedOrigins: ReadonlySet<string> }
type Dependencies = {
  run<T>(f: () => Promise<T>): Promise<T>
  state(): Promise<State | null>
  epoch(): number
  onChange(f: () => void): () => void
  invalidate(): void
  approveOrigin(origin: string): Promise<void>
  sign(bytes: Uint8Array): string
  legacyCredential(): Promise<unknown>
}
const STORAGE_KEY = 'castalia-provider-profiles-v1'
export const NEUTRAL_CAPABILITIES = [...PROVIDER_PROFILE_CAPABILITIES, 'credential_presentation_v2', 'read_access_v1', 'access_request_v1', 'graph_access_v2', 'read_setup_status_v1', 'holder_grant_v1']
function base64url(s: string) {
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function digest(s: string) {
  return crypto.subtle
    .digest('SHA-256', new TextEncoder().encode(s))
    .then((b) => Array.from(new Uint8Array(b), (n) => n.toString(16).padStart(2, '0')).join(''))
}
type Summary = {
  approvalKey: string
  operation: string
  origin: string
  profile?: ProviderProfileV1
  profileId?: string
  revision?: number
  memberKey?: string
  expiresAt: number
}

export function installProviderProfilesRuntime(chrome: any, deps: Dependencies) {
  // Fail closed if this Chrome cannot restrict extension storage to trusted contexts.
  const ready = chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })
  const store = createProviderProfileStore({
    read: async () => {
      await ready
      return (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY]
    },
    write: async (value) => {
      await ready
      await chrome.storage.local.set({ [STORAGE_KEY]: value })
    },
    randomId: () => crypto.randomUUID(),
    digest,
    verifyMembership: (credential, roots, holder) =>
      verifyZenithMembershipCredential(
        credential,
        { schema: 'castalia.zenith-membership-trust-policy.v1', version: 1, roots },
        holder,
      ),
  })
  store.subscribe(deps.invalidate)
  const settingsUrl = chrome.runtime.getURL('src/provider-settings.html')
  const active = new Set<{ tabId: number; cancel(): void }>()
  const invalidate = () => {
    for (const owner of [...active]) owner.cancel()
  }
  deps.onChange(invalidate)
  const broker = createOperationConfirmationBroker<Summary>({
    confirmationUrl: (id) => `${settingsUrl}?request=${encodeURIComponent(id)}`,
    createWindow: async (url) => {
      const w = await chrome.windows.create({
        url,
        type: 'popup',
        width: 650,
        height: 800,
        focused: true,
      })
      if (typeof w?.id !== 'number') throw new Error('approval_unavailable')
      return w.id
    },
    closeWindow: (id) => chrome.windows.remove(id),
    addWindowRemovedListener: (f) => chrome.windows.onRemoved.addListener(f),
    removeWindowRemovedListener: (f) => chrome.windows.onRemoved.removeListener(f),
    setTimeout: (f, ms) => globalThis.setTimeout(f, ms),
    clearTimeout: (t) => globalThis.clearTimeout(t as ReturnType<typeof setTimeout>),
    nowMs: Date.now,
    randomId: () => crypto.randomUUID(),
  })
  const decisions = new Map<string, { membership: boolean; presentations: boolean }>()
  let claimed: { requestId: string; summary: Summary } | undefined
  function trusted(sender: any, requestId?: string) {
    if (
      sender?.id !== chrome.runtime.id ||
      sender?.url !==
        (requestId ? `${settingsUrl}?request=${encodeURIComponent(requestId)}` : settingsUrl)
    )
      throw new Error('invalid_settings_sender')
  }
  async function unlocked() {
    const s = await deps.state()
    if (!s) throw new Error('wallet_unlock_required')
    return s
  }
  async function permission(profile: ProviderProfileV1) {
    if (
      profile.membership &&
      !(await chrome.permissions.contains({ origins: [profile.membership.issuer_origin + '/*'] }))
    )
      throw new Error('issuer_host_permission_required')
  }
  const selectedPurposes = (profile: ProviderProfileV1, p: any) =>
    parseProviderProfile({
      ...profile,
      membership: p?.membership === true ? profile.membership : null,
      presentations: p?.presentations === true ? profile.presentations : [],
    })

  chrome.runtime.onMessage.addListener(
    (message: any, sender: any, respond: (r: unknown) => void) => {
      if (
        ![
          'PROFILE_SETTINGS_GET',
          'PROFILE_SETTINGS_SAVE',
          'PROFILE_SETTINGS_REMOVE',
          'PROFILE_SETTINGS_BIND_LEGACY',
          'GET_PROVIDER_APPROVAL',
          'RESOLVE_PROVIDER_APPROVAL',
        ].includes(message?.type)
      )
        return false
      void (async () => {
        if (
          message.type === 'GET_PROVIDER_APPROVAL' ||
          message.type === 'RESOLVE_PROVIDER_APPROVAL'
        ) {
          trusted(sender, message.requestId)
          if (message.type === 'GET_PROVIDER_APPROVAL') {
            const p = broker.claimPending(message.requestId)
            if (!p) throw new Error('approval_unavailable')
            claimed = { requestId: message.requestId, summary: p.summary }
            return { summary: p.summary }
          }
          if (!claimed || claimed.requestId !== message.requestId)
            throw new Error('approval_unavailable')
          const key = claimed.summary.approvalKey
          decisions.set(key, {
            membership: message.purposes?.membership === true,
            presentations: message.purposes?.presentations === true,
          })
          claimed = undefined
          if (!broker.resolve(message.requestId, message.approved === true)) {
            decisions.delete(key)
            throw new Error('approval_unavailable')
          }
          return {}
        }
        trusted(sender)
        return deps.run(async () => {
          await unlocked()
          if (message.type === 'PROFILE_SETTINGS_GET') {
            const snapshot = await store.snapshot()
            return { profiles: snapshot.profiles, legacy: snapshot.legacy }
          }
          if (message.type === 'PROFILE_SETTINGS_SAVE') {
            const profile = selectedPurposes(
              parseProviderProfile(message.profile),
              message.purposes,
            )
            await permission(profile)
            return { profile: await store.approve(profile, message.edit) }
          }
          if (message.type === 'PROFILE_SETTINGS_REMOVE')
            return store.remove(message.profileId, message.expectedRevision)
          return store.bindLegacy(message.origin, message.profileId, message.expectedRevision)
        })
      })().then(
        (result) => respond({ ok: true, ...result }),
        (error) =>
          respond({
            ok: false,
            error: error instanceof Error ? error.message : 'profile_operation_failed',
          }),
      )
      return true
    },
  )
  chrome.tabs.onUpdated.addListener((id: number, c: any) => {
    if (c.url !== undefined || c.status === 'loading')
      for (const o of [...active]) if (o.tabId === id) o.cancel()
  })
  chrome.tabs.onRemoved.addListener((id: number) => {
    for (const o of [...active]) if (o.tabId === id) o.cancel()
  })
  chrome.permissions.onRemoved.addListener(() => {
    deps.invalidate()
    void deps
      .run(async () => {
        deps.invalidate()
        for (const p of (await store.snapshot()).profiles.filter(
          (p) => p.active && p.profile.membership,
        ))
          if (
            !(await chrome.permissions.contains({
              origins: [p.profile.membership!.issuer_origin + '/*'],
            }))
          )
            await store.remove(p.id, p.revision)
      })
      .catch(() => deps.invalidate())
  })

  chrome.runtime.onConnect.addListener((port: any) => {
    if (port.name !== 'castalia-provider-profiles-v1') return
    const sender = port.sender,
      tabId = sender?.tab?.id,
      documentUrl = sender?.url
    let live = true,
      used = false
    const controller = new AbortController()
    const owner = {
      tabId,
      cancel() {
        if (!live) return
        live = false
        controller.abort()
        broker.cancelForOwner(owner)
        active.delete(owner)
        clearTimeout(timer)
        try {
          port.disconnect()
        } catch {}
      },
    }
    const timer = setTimeout(() => owner.cancel(), 125000)
    const finish = (response: unknown) => {
      try {
        if (live) port.postMessage(response)
      } finally {
        owner.cancel()
      }
    }
    let origin: string
    try {
      if (
        sender?.id !== chrome.runtime.id ||
        sender.frameId !== 0 ||
        !Number.isInteger(tabId) ||
        typeof sender.documentId !== 'string' ||
        (sender.documentLifecycle && sender.documentLifecycle !== 'active') ||
        documentUrl !== sender.tab.url ||
        active.size >= 32
      )
        throw new Error('invalid_document')
      origin = profileOrigin(documentUrl ? new URL(documentUrl).origin : undefined)
    } catch (error) {
      finish({ ok: false, error: error instanceof Error ? error.message : 'invalid_document' })
      return
    }
    active.add(owner)
    port.onDisconnect.addListener(() => owner.cancel())
    async function current(epoch: number) {
      if (!live || deps.epoch() !== epoch || (await chrome.tabs.get(tabId))?.url !== documentUrl)
        throw new Error('provider_context_changed')
      if (!live || deps.epoch() !== epoch) throw new Error('provider_context_changed')
    }
    port.onMessage.addListener((message: any) => {
      if (used || !live) {
        finish({ ok: false, error: 'request_replay' })
        return
      }
      used = true
      void (async () => {
        if (!message || Object.keys(message).sort().join(',') !== 'operation,payload')
          throw new Error('invalid_request')
        const { operation, payload } = message
        if (
          ![
            'connect',
            'propose',
            'profiles',
            'credential',
            'join',
            'legacyJoin',
            'legacyCredential',
          ].includes(operation)
        )
          throw new Error('unsupported_operation')
        if (
          operation !== 'propose' &&
          (!payload ||
            typeof payload !== 'object' ||
            Array.isArray(payload) ||
            Object.keys(payload).sort().join(',') !==
              (['credential', 'join'].includes(operation) ? 'profileId' : ''))
        )
          throw new Error('invalid_payload')
        const initial = await deps.run(async () => {
          const epoch = deps.epoch()
          await current(epoch)
          const state = await unlocked()
          await current(epoch)
          if (!['connect', 'propose'].includes(operation) && !state.approvedOrigins.has(origin))
            throw new Error('origin_not_approved')
          const p = operation.startsWith('legacy')
            ? await store.legacy(origin)
            : ['join', 'credential'].includes(operation)
              ? await store.get(payload?.profileId, origin)
              : undefined
          let proposal: ProviderProfileV1 | undefined
          if (operation === 'propose') {
            proposal = parseProviderProfile(payload)
            if (proposal.origins.length !== 1 || proposal.origins[0] !== origin)
              throw new Error('proposal_caller_scope')
          }
          await current(epoch)
          return { epoch, state, p, proposal }
        })
        if (operation === 'profiles') {
          const result = await store.list(origin)
          await current(initial.epoch)
          return result
        }
        if (['credential', 'legacyCredential'].includes(operation)) {
          const credential = await store.credential(
            initial.p!.id,
            origin,
            initial.state.memberKey,
            await deps.legacyCredential(),
          )
          await current(initial.epoch)
          return credential
        }
        if (initial.p) await permission(initial.p.profile)
        const summary: Summary = {
          approvalKey: crypto.randomUUID(),
          operation,
          origin,
          expiresAt: Math.floor(Date.now() / 1000) + 120,
          ...(initial.proposal ? { profile: initial.proposal } : {}),
          ...(initial.p
            ? {
                profile: initial.p.profile,
                profileId: initial.p.id,
                revision: initial.p.revision,
                memberKey: initial.state.memberKey,
              }
            : {}),
        }
        await current(initial.epoch)
        let purposes: { membership: boolean; presentations: boolean } | undefined
        let approved = false
        try {
          approved = await broker.confirm({ summary, tabId, owner })
          purposes = decisions.get(summary.approvalKey)
        } finally {
          decisions.delete(summary.approvalKey)
          if (claimed?.summary.approvalKey === summary.approvalKey) claimed = undefined
        }
        if (!approved) {
          if (operation === 'propose') return { state: 'denied' }
          throw new Error('approval_denied')
        }
        const prepared = await deps.run(async () => {
          await current(initial.epoch)
          if (Math.floor(Date.now() / 1000) >= summary.expiresAt)
            throw new Error('approval_expired')
          const state = await unlocked()
          await current(initial.epoch)
          if (state.memberKey !== initial.state.memberKey) throw new Error('holder_changed')
          if (operation === 'connect') {
            await deps.approveOrigin(origin)
            await current(initial.epoch)
            return { result: { state: 'connected' } }
          }
          if (operation === 'propose') {
            const profile = selectedPurposes(initial.proposal!, purposes)
            await permission(profile)
            await current(initial.epoch)
            // Own trust mutation cancels other ceremonies, but can acknowledge this one.
            active.delete(owner)
            await store.approve(profile)
            return { result: { state: 'approved' } }
          }
          const p = await store.get(initial.p!.id, origin)
          if (p.revision !== initial.p!.revision || !p.profile.membership)
            throw new Error('profile_changed')
          await permission(p.profile)
          await current(initial.epoch)
          if (Math.floor(Date.now() / 1000) >= summary.expiresAt)
            throw new Error('approval_expired')
          return {
            profile: p,
            memberKey: state.memberKey,
            signature: base64url(deps.sign(zenithMembershipJoinTranscript(state.memberKey))),
          }
        })
        if ('result' in prepared) return prepared.result
        // Network I/O never holds the custody queue: lock/revocation must interrupt it.
        const p = prepared.profile,
          m = p.profile.membership!
        const credential = await issueZenithMembership({
          issuerUrl: m.issuer_origin,
          ownerPublicKey: prepared.memberKey,
          signature: prepared.signature,
          trustPolicy: {
            schema: 'castalia.zenith-membership-trust-policy.v1',
            version: 1,
            roots: m.roots,
          },
          fetchImpl: (url, options) =>
            fetch(url, {
              ...options,
              credentials: 'omit',
              redirect: 'error',
              signal: controller.signal,
            }),
        })
        return deps.run(async () => {
          await current(initial.epoch)
          const state = await unlocked()
          if (state.memberKey !== prepared.memberKey) throw new Error('holder_changed')
          await permission(p.profile)
          await current(initial.epoch)
          const saved = await store.saveCredential(p.id, p.revision, credential, state.memberKey)
          await current(initial.epoch)
          return operation === 'legacyJoin' ? { state: 'opened' } : saved
        })
      })().then(
        (result) => finish({ ok: true, result }),
        (error) =>
          finish({ ok: false, error: error instanceof Error ? error.message : 'provider_failed' }),
      )
    })
  })
  return {
    store,
    ready,
    async setupStatus(input: unknown, origin: string) {
      const profile = parseProviderProfile(input)
      if (profile.origins.length !== 1 || profile.origins[0] !== profileOrigin(origin))
        throw new Error('proposal_caller_scope')
      const state = await deps.state()
      // Unknown origins learn no installed trust, identity or membership data.
      // Locked and unconnected Wallets are indistinguishable to discovery.
      if (!state?.approvedOrigins.has(origin)) return {
        schema: 'castalia.read-setup-status.v1', connection_approved: false, profile_approved: false,
      }
      const bytes = providerProfileBytes(profile)
      const approved = (await store.snapshot()).profiles.some(p =>
        p.active && providerProfileBytes(p.profile) === bytes)
      return { schema: 'castalia.read-setup-status.v1', connection_approved: true, profile_approved: approved }
    },
    async memberships(origin:string) {await ready;return store.list(origin)},
    async readMembership(origin:string,holder:string,profileId?:string) {
      await ready
      if (!profileId) {
        const profiles=await store.list(origin)
        if(profiles.length!==1)throw new Error('membership_selection_required')
        profileId=profiles[0].profileId
      }
      return store.credential(profileId,origin,holder,await deps.legacyCredential())
    },
    async pins() {
      await ready
      return store.presentationPins()
    },
    async legacy(origin: string, holder: string) {
      const p = await store.legacy(origin)
      return {
        profile: p,
        credential: await store.credential(p.id, origin, holder, await deps.legacyCredential()),
      }
    },
  }
}
