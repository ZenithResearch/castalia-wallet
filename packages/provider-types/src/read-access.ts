/** Additive application-neutral read access. No recovery, key export or write RPC. */
export const ACCESS_REQUEST_CAPABILITY = "access_request_v1" as const;
export const GRAPH_ACCESS_CAPABILITY = "graph_access_v2" as const;
export const READ_ACCESS_CAPABILITY = "read_access_v1" as const;
export const READ_SETUP_STATUS_CAPABILITY = "read_setup_status_v1" as const;
export const SCOPED_HOLDER_GRANT_CAPABILITY = "holder_grant_v2" as const;
export const HOLDER_GRANT_CAPABILITY = "holder_grant_v1" as const;
/** Candidate: advertise only with a qualified session exchange implementation. */
export const HOLDER_SESSION_EXCHANGE_CAPABILITY = "holder_session_exchange_v1" as const;
export type ReadAccessRequest =
  | { operation: "prepare_holder_session"; service: string; session_public_key: string; session_installation_id: string; requested_ttl_seconds: number; permissions?: unknown[]; service_access_point?: unknown }
  | { operation: "open_holder_session"; preparationId: string; challenge: unknown; session_signature: string }
  | { operation: "save_grant"; service: string; grant: unknown; permissions?: unknown[] }
  | { operation: "use_grant"; service: string; permissions?: unknown[] }
  | { operation: "present_grant"; accessId: string; call: unknown }
  | { operation: "setup_status"; profile: unknown }
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
