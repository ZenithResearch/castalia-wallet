type TimerHandle = unknown

type OperationConfirmationPlatform = {
  confirmationUrl(requestId: string): string
  createWindow(url: string): Promise<number>
  closeWindow(windowId: number): Promise<void>
  addWindowRemovedListener(listener: (windowId: number) => void): void
  removeWindowRemovedListener(listener: (windowId: number) => void): void
  setTimeout(callback: () => void, delayMs: number): TimerHandle
  clearTimeout(handle: TimerHandle): void
  randomId(): string
  nowMs(): number
}

type Pending<Summary> = {
  requestId: string
  summary: Summary
  tabId: number
  owner?: object
  windowId: number | null
  timer: TimerHandle | null
  removed: ((windowId: number) => void) | null
  resolve: (approved: boolean) => void
  claimed: boolean
  createdAtMs: number
  deadlineMs: number
}

export function createOperationConfirmationBroker<Summary extends { expiresAt: number }>(platform: OperationConfirmationPlatform) {
  // Approval is intentionally memory-only and one-shot. Worker suspension,
  // popup closure, timeout, or a second claimant all deny the signing request.
  let pending: Pending<Summary> | null = null

  function currentTime(current: Pending<Summary>): number | null {
    const now = platform.nowMs()
    return Number.isSafeInteger(now) && now >= current.createdAtMs && now < current.deadlineMs ? now : null
  }

  function finish(requestId: string, approved: boolean, closeWindow: boolean): boolean {
    if (!pending || pending.requestId !== requestId) return false
    const current = pending
    pending = null
    if (current.timer !== null) platform.clearTimeout(current.timer)
    if (current.removed) platform.removeWindowRemovedListener(current.removed)
    if (closeWindow && current.windowId !== null) {
      void platform.closeWindow(current.windowId).catch(() => undefined)
    }
    current.resolve(approved)
    return true
  }

  return {
    confirm(input: {
      summary: Summary
      tabId: number
      owner?: object
      onOpenFailure?(): void
    }): Promise<boolean> {
      if (pending) return Promise.reject(new Error('A operation confirmation is already pending'))
      const nowMs = platform.nowMs()
      const expiresAtMs = input.summary.expiresAt * 1_000
      if (!Number.isSafeInteger(input.summary.expiresAt) || !Number.isSafeInteger(expiresAtMs)
        || !Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > Number.MAX_SAFE_INTEGER - 120_000
        || expiresAtMs <= nowMs) {
        return Promise.reject(new Error('operation confirmation is expired'))
      }
      const deadlineMs = Math.min(expiresAtMs, nowMs + 120_000)
      const requestId = platform.randomId()
      return new Promise<boolean>(resolve => {
        pending = {
          requestId,
          summary: structuredClone(input.summary),
          tabId: input.tabId,
          owner: input.owner,
          windowId: null,
          timer: null,
          removed: null,
          resolve,
          claimed: false,
          createdAtMs: nowMs,
          deadlineMs,
        }
        pending.timer = platform.setTimeout(() => finish(requestId, false, true), deadlineMs - nowMs)
        void (async () => {
          try {
            const windowId = await platform.createWindow(platform.confirmationUrl(requestId))
            if (!pending || pending.requestId !== requestId) {
              await platform.closeWindow(windowId).catch(() => undefined)
              return
            }
            pending.windowId = windowId
            const openedAtMs = currentTime(pending)
            if (openedAtMs === null) {
              finish(requestId, false, true)
              return
            }
            const removed = (removedWindowId: number) => {
              if (removedWindowId === windowId) finish(requestId, false, false)
            }
            pending.removed = removed
            platform.addWindowRemovedListener(removed)
            if (pending.timer !== null) platform.clearTimeout(pending.timer)
            pending.timer = platform.setTimeout(
              () => finish(requestId, false, true),
              pending.deadlineMs - openedAtMs,
            )
          } catch {
            try { input.onOpenFailure?.() } catch {}
            finish(requestId, false, false)
          }
        })()
      })
    },

    claimPending(requestId: string): {
      summary: Summary
      tabId: number
    } | null {
      if (!pending || pending.requestId !== requestId || pending.claimed) return null
      if (currentTime(pending) === null) {
        finish(requestId, false, true)
        return null
      }
      pending.claimed = true
      return {
        summary: structuredClone(pending.summary),
        tabId: pending.tabId,
      }
    },

    cancelForOwner(owner: object): void {
      if (pending?.owner === owner) finish(pending.requestId, false, true)
    },

    cancelForTab(tabId: number): void {
      if (pending?.tabId === tabId) finish(pending.requestId, false, true)
    },

    resolve(requestId: string, approved: boolean): boolean {
      if (!pending || pending.requestId !== requestId) return false
      if (approved && !pending.claimed) return false
      return finish(requestId, approved && currentTime(pending) !== null, true)
    },
  }
}
