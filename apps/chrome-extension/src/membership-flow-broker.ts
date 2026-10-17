type TimerHandle = unknown

export type MembershipFlowContext = {
  requestId: string
  origin: string
  tabId: number
}

type MembershipFlowBrokerPlatform = {
  flowUrl(requestId: string): string
  createWindow(url: string): Promise<number>
  closeWindow(windowId: number): Promise<void>
  addWindowRemovedListener(listener: (windowId: number) => void): void
  removeWindowRemovedListener(listener: (windowId: number) => void): void
  setTimeout(callback: () => void, delayMs: number): TimerHandle
  clearTimeout(handle: TimerHandle): void
  randomId(): string
}

type Pending = MembershipFlowContext & {
  windowId: number | null
  timer: TimerHandle | null
  removed: ((windowId: number) => void) | null
}

export function createMembershipFlowBroker(platform: MembershipFlowBrokerPlatform) {
  // Memory-only by design: service-worker suspension, window close, and timeout all
  // invalidate the ceremony instead of leaving reusable approval state.
  let pending: Pending | null = null

  function finish(requestId: string, closeWindow: boolean): boolean {
    if (!pending || pending.requestId !== requestId) return false
    const current = pending
    pending = null
    if (current.timer !== null) platform.clearTimeout(current.timer)
    if (current.removed) platform.removeWindowRemovedListener(current.removed)
    if (closeWindow && current.windowId !== null) {
      void platform.closeWindow(current.windowId).catch(() => undefined)
    }
    return true
  }

  return {
    async open(input: { origin: string; tabId: number }): Promise<MembershipFlowContext> {
      if (pending) throw new Error('A membership flow is already open')
      const requestId = platform.randomId()
      pending = {
        requestId,
        origin: input.origin,
        tabId: input.tabId,
        windowId: null,
        timer: null,
        removed: null,
      }
      try {
        const windowId = await platform.createWindow(platform.flowUrl(requestId))
        if (!pending || pending.requestId !== requestId) {
          await platform.closeWindow(windowId).catch(() => undefined)
          throw new Error('Membership flow is no longer active')
        }
        const removed = (removedWindowId: number) => {
          if (removedWindowId === windowId) finish(requestId, false)
        }
        pending.windowId = windowId
        pending.removed = removed
        platform.addWindowRemovedListener(removed)
        pending.timer = platform.setTimeout(() => finish(requestId, true), 120_000)
        return { requestId, origin: input.origin, tabId: input.tabId }
      } catch (error) {
        finish(requestId, false)
        throw error
      }
    },

    get(requestId: string): MembershipFlowContext | null {
      if (!pending || pending.requestId !== requestId) return null
      const { origin, tabId } = pending
      return { requestId, origin, tabId }
    },

    complete(requestId: string): boolean {
      return finish(requestId, false)
    },
  }
}
