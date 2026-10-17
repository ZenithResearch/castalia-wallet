import type { MembershipPresentationConfirmationSummary } from './service-worker.js'

type TimerHandle = unknown

type ConfirmationBrokerPlatform = {
  confirmationUrl(requestId: string): string
  createWindow(url: string): Promise<number>
  closeWindow(windowId: number): Promise<void>
  addWindowRemovedListener(listener: (windowId: number) => void): void
  removeWindowRemovedListener(listener: (windowId: number) => void): void
  setTimeout(callback: () => void, delayMs: number): TimerHandle
  clearTimeout(handle: TimerHandle): void
  randomId(): string
}

type Pending = {
  requestId: string
  summary: MembershipPresentationConfirmationSummary
  windowId: number | null
  timer: TimerHandle | null
  removed: ((windowId: number) => void) | null
  resolve: (approved: boolean) => void
  claimed: boolean
}

export function createMembershipConfirmationBroker(platform: ConfirmationBrokerPlatform) {
  // Deliberately memory-only: MV3 suspension/reload loses the pending request and therefore
  // denies signing. Persisting approval state would make stale/replayed confirmations possible.
  let pending: Pending | null = null

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
    confirm(summary: MembershipPresentationConfirmationSummary): Promise<boolean> {
      if (pending) return Promise.reject(new Error('A membership confirmation is already pending'))
      const requestId = platform.randomId()
      return new Promise<boolean>(resolve => {
        pending = {
          requestId,
          summary: structuredClone(summary),
          windowId: null,
          timer: null,
          removed: null,
          resolve,
          claimed: false,
        }
        void (async () => {
          try {
            const windowId = await platform.createWindow(platform.confirmationUrl(requestId))
            if (!pending || pending.requestId !== requestId) {
              await platform.closeWindow(windowId).catch(() => undefined)
              return
            }
            const removed = (removedWindowId: number) => {
              if (removedWindowId === windowId) finish(requestId, false, false)
            }
            pending.windowId = windowId
            pending.removed = removed
            platform.addWindowRemovedListener(removed)
            pending.timer = platform.setTimeout(() => finish(requestId, false, true), 120_000)
          } catch {
            finish(requestId, false, false)
          }
        })()
      })
    },
    claimPendingSummary(requestId: string): MembershipPresentationConfirmationSummary | null {
      if (!pending || pending.requestId !== requestId || pending.claimed) return null
      pending.claimed = true
      return structuredClone(pending.summary)
    },
    resolve(requestId: string, approved: boolean): boolean {
      return finish(requestId, approved, true)
    },
  }
}
