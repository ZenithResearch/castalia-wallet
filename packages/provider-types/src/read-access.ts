/** Additive application-neutral read access. No recovery, key export or write RPC. */
export const ACCESS_REQUEST_CAPABILITY = "access_request_v1" as const;
export const GRAPH_ACCESS_CAPABILITY = "graph_access_v2" as const;
export const READ_ACCESS_CAPABILITY = "read_access_v1" as const;
export type ReadAccessRequest =
  | { operation: "identity" }
  | { operation: "request"; challenge: unknown; profileId?: string }
  | { operation: "approve_graph_v2"; challenge: unknown; profileId?: string }
  | { operation: "accept_graph_v2"; accessId: string; credential: unknown }
  | { operation: "present_graph_v2"; accessId: string; call: unknown }
  | { operation: "approve"; challenge: unknown; profileId?: string }
  | { operation: "accept"; accessId: string; credential: unknown }
  | { operation: "present"; accessId: string; call: unknown }
  | { operation: "disconnect"; accessId: string };
export type ReadAccessProvider = {
  readAccess?(request: ReadAccessRequest): Promise<unknown>;
};
