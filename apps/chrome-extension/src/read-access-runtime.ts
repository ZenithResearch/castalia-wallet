import { createReadAccessController, type ReadContext } from "./read-access.js";
import { createOperationConfirmationBroker } from "./operation-confirmation-broker.js";
export function installReadAccessRuntime(chrome: any, deps: any) {
  const page = chrome.runtime.getURL("src/read-access-confirmation.html");
  const broker = createOperationConfirmationBroker<any>({
    confirmationUrl: (id) => `${page}?request=${encodeURIComponent(id)}`,
    createWindow: async (url) => {
      const w = await chrome.windows.create({
        url,
        type: "popup",
        width: 580,
        height: 720,
        focused: true,
      });
      if (typeof w?.id !== "number") throw new Error("approval_unavailable");
      return w.id;
    },
    closeWindow: (id) => chrome.windows.remove(id),
    addWindowRemovedListener: (f) => chrome.windows.onRemoved.addListener(f),
    removeWindowRemovedListener: (f) =>
      chrome.windows.onRemoved.removeListener(f),
    setTimeout: (f, ms) => setTimeout(f, ms),
    clearTimeout: (t) => clearTimeout(t as ReturnType<typeof setTimeout>),
    randomId: () => crypto.randomUUID(),
    nowMs: Date.now,
  });
  const controller = createReadAccessController({
    ...deps,
    now: () => Math.floor(Date.now() / 1000),
    randomId: () => crypto.randomUUID(),
    confirm: async (summary: any, context: ReadContext) => {
      let unavailable = false;
      try {
        const approved = await broker.confirm({
          // The shared broker accepts epoch seconds and converts to milliseconds.
          summary: { ...summary, expiresAt: summary.approval_expires_at },
          tabId: context.tabId,
          owner: context,
          onOpenFailure: () => { unavailable = true; },
        });
        if (unavailable) throw new Error("approval_unavailable");
        return approved;
      } catch (error) {
        if (error instanceof Error && error.message === "A operation confirmation is already pending")
          throw new Error("approval_pending");
        if (error instanceof Error && error.message === "operation confirmation is expired")
          throw new Error("read_approval_expired");
        throw error;
      }
    },
  });
  const active = new Set<{ context: ReadContext; cancel(): void }>();
  const invalidate = (tabId?: number) => {
    for (const doc of controller.invalidate(tabId)) {
      void chrome.tabs
        .sendMessage(
          doc.tabId,
          { type: "CASTALIA_READ_ACCESS_INVALIDATED" },
          { documentId: doc.documentId },
        )
        .catch(() => {});
    }
    for (const owner of [...active])
      if (tabId === undefined || owner.context.tabId === tabId) owner.cancel();
  };
  deps.onChange(() => invalidate());
  chrome.tabs.onUpdated.addListener((id: number, c: any) => {
    if (c.url !== undefined || c.status === "loading") invalidate(id);
  });
  chrome.tabs.onRemoved.addListener((id: number) => invalidate(id));
  chrome.runtime.onMessage.addListener(
    (message: any, sender: any, respond: (value: any) => void) => {
      if (
        ![
          "GET_READ_ACCESS_CONFIRMATION",
          "RESOLVE_READ_ACCESS_CONFIRMATION",
        ].includes(message?.type)
      )
        return false;
      try {
        if (
          sender?.id !== chrome.runtime.id ||
          typeof message.requestId !== "string" ||
          sender?.url !==
            `${page}?request=${encodeURIComponent(message.requestId)}`
        )
          throw new Error("invalid_confirmation_sender");
        if (message.type === "GET_READ_ACCESS_CONFIRMATION") {
          const p = broker.claimPending(message.requestId);
          if (!p) throw new Error("approval_unavailable");
          respond({ ok: true, summary: p.summary });
        } else {
          if (!broker.resolve(message.requestId, message.approved === true))
            throw new Error("approval_unavailable");
          respond({ ok: true });
        }
      } catch (e) {
        respond({
          ok: false,
          error: e instanceof Error ? e.message : "approval_unavailable",
        });
      }
      return false;
    },
  );
  chrome.runtime.onConnect.addListener((port: any) => {
    if (port.name !== "castalia-read-access-v1") return;
    const sender = port.sender,
      tabId = sender?.tab?.id,
      documentUrl = sender?.url;
    let live = true,
      used = false,
      timer: ReturnType<typeof setTimeout> | undefined;
    const context: ReadContext & { verify?(): Promise<void> } = {
      origin: "",
      documentId: sender?.documentId,
      tabId,
      current: () => live,
      verify: async () => {
        if (!live || (await chrome.tabs.get(tabId))?.url !== documentUrl)
          throw new Error("read_context_changed");
      },
    };
    const owner = {
      context,
      cancel() {
        if (!live) return;
        live = false;
        clearTimeout(timer);
        broker.cancelForOwner(context);
        active.delete(owner);
        try {
          port.disconnect();
        } catch {}
      },
    };
    const finish = (value: unknown) => {
      try {
        if (live) port.postMessage(value);
      } finally {
        owner.cancel();
      }
    };
    try {
      if (
        active.size >= 32 ||
        sender?.id !== chrome.runtime.id ||
        sender.frameId !== 0 ||
        !Number.isInteger(tabId) ||
        typeof context.documentId !== "string" ||
        (sender.documentLifecycle && sender.documentLifecycle !== "active") ||
        documentUrl !== sender.tab.url
      )
        throw new Error("invalid_document");
      const u = new URL(documentUrl);
      if (
        u.protocol !== "https:" &&
        !(
          u.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)
        )
      )
        throw new Error("invalid_origin");
      context.origin = u.origin;
    } catch (e) {
      finish({ ok: false, error: "invalid_document" });
      return;
    }
    active.add(owner);
    timer = setTimeout(() => owner.cancel(), 125000);
    port.onDisconnect.addListener(() => owner.cancel());
    port.onMessage.addListener((payload: unknown) => {
      if (used || !live) {
        finish({ ok: false, error: "invalid_read_request" });
        return;
      }
      used = true;
      void controller.handle(payload, context).then(
        (result) => finish({ ok: true, result }),
        (e) =>
          finish({
            ok: false,
            error: e instanceof Error ? e.message : "read_access_failed",
          }),
      );
    });
  });
  return { invalidate };
}
