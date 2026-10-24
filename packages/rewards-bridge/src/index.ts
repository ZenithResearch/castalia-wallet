/** Public, per-request connection only. This protocol grants no signing authority. */
export const REQUEST_SCHEMA = "wallet.rewards.request.v1";
export const RESPONSE_SCHEMA = "wallet.rewards.response.v1";
export const READY_SCHEMA = "wallet.rewards.ready.v1";
export const MAX_SECONDS = 300;
export type Launch = { id: string; origin: string };
export type Request = {
  schema: typeof REQUEST_SCHEMA;
  id: string;
  operation: "connect";
  issuedAt: number;
  expiresAt: number;
};
export type PublicAccount = {
  walletPublicKey: string;
  solanaAddress: string;
  solanaPublicKey: string;
};
export type ErrorCode = "denied" | "expired" | "wallet_unavailable";
export type Response = {
  schema: typeof RESPONSE_SCHEMA;
  id: string;
  operation: "connect";
} & ({ result: PublicAccount } | { error: ErrorCode });
const nowSeconds = () => Math.floor(Date.now() / 1000);
const nonce = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{32}$/.test(v);
const key = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
function record(v: unknown): Record<string, unknown> {
  if (
    !v ||
    typeof v !== "object" ||
    Array.isArray(v) ||
    Object.getPrototypeOf(v) !== Object.prototype
  )
    throw new Error("invalid_message");
  if (new TextEncoder().encode(JSON.stringify(v)).length > 2048)
    throw new Error("message_too_large");
  return v as Record<string, unknown>;
}
function exact(v: Record<string, unknown>, keys: string[]) {
  if (Object.keys(v).sort().join(",") !== keys.sort().join(","))
    throw new Error("unexpected_fields");
}
export function canonicalOrigin(input: string): string {
  const url = new URL(input);
  if (
    url.origin !== input ||
    url.username ||
    url.password ||
    (url.protocol !== "https:" &&
      !(
        url.protocol === "http:" &&
        ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
      ))
  )
    throw new Error("invalid_origin");
  return url.origin;
}
export function parseLaunch(
  fragment: string,
  allowedOrigins: readonly string[],
): Launch {
  if (fragment.length > 2048) throw new Error("launch_too_large");
  const query = new URLSearchParams(fragment.replace(/^#/, ""));
  if ([...query.keys()].sort().join(",") !== "origin,request")
    throw new Error("invalid_launch");
  const id = query.get("request");
  const origin = canonicalOrigin(query.get("origin") ?? "");
  if (!nonce(id) || !allowedOrigins.includes(origin))
    throw new Error("origin_not_allowed");
  return { id, origin };
}
export function parseRequest(value: unknown, now = nowSeconds()): Request {
  const v = record(value);
  exact(v, ["schema", "id", "operation", "issuedAt", "expiresAt"]);
  if (
    v.schema !== REQUEST_SCHEMA ||
    v.operation !== "connect" ||
    !nonce(v.id) ||
    !Number.isSafeInteger(v.issuedAt) ||
    !Number.isSafeInteger(v.expiresAt) ||
    (v.issuedAt as number) < 0 ||
    (v.issuedAt as number) > now ||
    (v.expiresAt as number) <= now ||
    (v.expiresAt as number) - (v.issuedAt as number) > MAX_SECONDS
  )
    throw new Error("invalid_request");
  return v as Request;
}
export function parseResponse(value: unknown, id: string): Response {
  const v = record(value);
  exact(v, ["schema", "id", "operation", "result" in v ? "result" : "error"]);
  if (
    v.schema !== RESPONSE_SCHEMA ||
    v.id !== id ||
    v.operation !== "connect" ||
    !nonce(id)
  )
    throw new Error("invalid_response");
  if ("result" in v) {
    const r = record(v.result);
    exact(r, ["walletPublicKey", "solanaAddress", "solanaPublicKey"]);
    if (
      !key(r.walletPublicKey) ||
      !key(r.solanaPublicKey) ||
      typeof r.solanaAddress !== "string" ||
      !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(r.solanaAddress)
    )
      throw new Error("invalid_account");
  } else if (
    !["denied", "expired", "wallet_unavailable"].includes(v.error as string)
  )
    throw new Error("invalid_error");
  return v as Response;
}
export function createRequestGate(launch: Launch, opener: unknown) {
  let consumed = false;
  return {
    take(
      event: { source: unknown; origin: string; data: unknown },
      now = nowSeconds(),
    ): Request | null {
      if (
        !opener ||
        consumed ||
        event.source !== opener ||
        event.origin !== launch.origin
      )
        return null;
      try {
        const request = parseRequest(event.data, now);
        if (request.id !== launch.id) return null;
        consumed = true;
        return request;
      } catch {
        return null;
      }
    },
  };
}

/** Must run inside a user click. Never accepts a caller-supplied return URL. */
export function connectWallet(
  walletUrl: string,
  timeoutMs = 300_000,
): Promise<PublicAccount> {
  const url = new URL(walletUrl);
  canonicalOrigin(url.origin);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/wallet/rewards"
  )
    return Promise.reject(new Error("invalid_wallet_url"));
  const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) =>
    n.toString(16).padStart(2, "0"),
  ).join("");
  const issuedAt = nowSeconds();
  const request: Request = {
    schema: REQUEST_SCHEMA,
    id,
    operation: "connect",
    issuedAt,
    expiresAt: issuedAt + MAX_SECONDS,
  };
  url.hash = new URLSearchParams({
    request: id,
    origin: canonicalOrigin(window.location.origin),
  }).toString();
  // A live opener is required for the pinned-source handshake. No navigation is performed by the Wallet.
  const popup = window.open(
    url.toString(),
    `wallet-rewards-${id}`,
    "popup,width=560,height=820",
  );
  if (!popup) return Promise.reject(new Error("popup_blocked"));
  return new Promise((resolve, reject) => {
    let sent = false;
    const finish = (error?: Error, result?: PublicAccount) => {
      window.removeEventListener("message", receive);
      clearTimeout(timeout);
      clearInterval(closed);
      if (!popup.closed) popup.close();
      if (error) reject(error);
      else resolve(result!);
    };
    const receive = (event: MessageEvent) => {
      if (event.source !== popup || event.origin !== url.origin) return;
      try {
        if (
          !sent &&
          event.data?.schema === READY_SCHEMA &&
          event.data?.id === id &&
          Object.keys(event.data).length === 2
        ) {
          sent = true;
          popup.postMessage(request, url.origin);
          return;
        }
        if (!sent) return;
        const response = parseResponse(event.data, id);
        if (nowSeconds() >= request.expiresAt)
          return finish(new Error("expired"));
        if ("error" in response) finish(new Error(response.error));
        else finish(undefined, response.result);
      } catch {
        /* Ignore malformed or unrelated traffic; never extend the deadline. */
      }
    };
    const timeout = setTimeout(
      () => finish(new Error("wallet_timeout")),
      Math.min(Math.max(timeoutMs, 1000), MAX_SECONDS * 1000),
    );
    const closed = setInterval(() => {
      if (popup.closed) finish(new Error("wallet_closed"));
    }, 500);
    window.addEventListener("message", receive);
  });
}
