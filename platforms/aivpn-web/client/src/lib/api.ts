import { authStore } from './stores/auth.svelte';
import { goto } from '$app/navigation';

// ─── Refresh coalescing ───────────────────────────────────────────────────────
// The refresh endpoint ROTATES the httpOnly refresh cookie. If several
// parallel requests hit 401 at once (dashboard fires 4+ queries on mount)
// and each starts its own POST /web/auth/refresh, the second refresh runs
// with the just-invalidated old cookie and logs the user out. Coalesce:
// only the first 401-caller starts a refresh; everyone else awaits the same
// in-flight promise. Reset on settle so a later 401 can refresh again.
let refreshPromise: Promise<string> | null = null;

/**
 * Mint a fresh access token from the httpOnly refresh cookie.
 * Concurrent callers share a single in-flight request.
 * Rejects if the refresh cookie is missing/expired/rotated away.
 */
export function refreshAccessToken(): Promise<string> {
  if (!refreshPromise) {
    refreshPromise = (async () => {
      const refreshRes = await fetch('/web/auth/refresh', { method: 'POST' });
      if (!refreshRes.ok) {
        throw new Error(`refresh failed: HTTP ${refreshRes.status}`);
      }
      const data = await refreshRes.json() as { access_token: string };
      authStore.setToken(data.access_token);
      return data.access_token;
    })().finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

/** True when the body must be sent as-is (browser sets/derives Content-Type). */
function isRawBody(body: BodyInit | null | undefined): boolean {
  return (
    body instanceof Blob || // includes File
    body instanceof FormData ||
    body instanceof URLSearchParams ||
    body instanceof ArrayBuffer ||
    ArrayBuffer.isView(body as ArrayBufferView)
  );
}

async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  // Default to JSON only for string bodies (and body-less requests) — a
  // File/Blob/FormData upload must NOT be labeled application/json, and
  // FormData needs the browser-generated multipart boundary.
  const headers: Record<string, string> = {
    ...(isRawBody(options.body) ? {} : { 'Content-Type': 'application/json' }),
    ...(options.headers as Record<string, string> || {}),
  };

  if (authStore.accessToken) {
    headers['Authorization'] = `Bearer ${authStore.accessToken}`;
  }

  let res = await fetch(path, { ...options, headers });

  if (res.status === 401) {
    // Try refresh (coalesced across concurrent 401s)
    let newToken: string;
    try {
      newToken = await refreshAccessToken();
    } catch {
      authStore.clearToken();
      goto('/login');
      return res;
    }
    headers['Authorization'] = `Bearer ${newToken}`;
    res = await fetch(path, { ...options, headers });
    if (res.status === 401) {
      authStore.clearToken();
      goto('/login');
    }
  }

  return res;
}

async function apiJson<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await apiFetch(path, options);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export interface ClientQos {
  bandwidth_limit_up?: number;
  bandwidth_limit_down?: number;
  dscp_class?: string;
}

/** Per-client role in the pool/admin control-channel (NOT the web-panel login
 *  role, which is only 'admin' | 'viewer' — see server/src/db/schema.ts). This
 *  is the client's role field set via PATCH /api/v1/clients/:id and is only
 *  assignable through the web/CLI, never over the tunnel. */
export type ClientRole = 'user' | 'viewer' | 'admin';

export interface Client {
  id: string;
  name: string;
  enabled: boolean;
  one_time: boolean;
  device_bound: boolean;
  vpn_ip: string;
  created_at: string;
  expires_at?: string | null;
  qos?: ClientQos;
  /** Optional for backward compatibility with older daemon builds that
   *  predate role assignment — treat a missing value as 'user' in the UI. */
  role?: ClientRole;
  /** Per-client exit-node override (`host:port`), settable via
   *  `PATCH /api/v1/clients/:id` with `{"exit_node": "..."}` or
   *  `{"exit_node": null}` to clear it back to the pool's global default
   *  (`pool.exit_node` in server.json). Unlike the global default, this
   *  takes effect live — no server restart required. Optional for backward
   *  compatibility with older daemon builds that predate this field. */
  exit_node?: string | null;
  stats: {
    bytes_in: number;
    bytes_out: number;
    last_connected: string | null;
    total_connections: number;
    last_handshake: string | null;
  };
}

/** One line of the management daemon's audit log (audit_log.rs AuditEntry).
 *  `result` values actually emitted by the server: "ok", "fail", "accepted",
 *  "rejected", "denied" — there is no id/detail field. */
export interface AuditLogEntry {
  ts: string;
  actor: 'cli' | 'api' | 'system';
  action: string;
  target: string;
  result: string;
}

/** True when an audit result string represents a successful outcome. */
export function isAuditResultOk(result: string): boolean {
  return result === 'ok' || result === 'accepted';
}

export interface Mask {
  id: string;
  file: string;
  size_bytes: number;
  modified: string | null;
  /** True when auto-generated by mask_gen from a recording (shown as "(auto)"). */
  generated: boolean;
}

export interface Metrics {
  cpu_percent: number;
  ram_used_mb: number;
  ram_total_mb: number;
  load_avg: number;
}

/** GET /api/v1/status (management_api.rs StatusResponse). NOTE: there is no
 *  connected-clients field here — live connection counts come from the SSE
 *  `state` event (`clients_connected`). */
export interface ServerStatus {
  version: string;
  uptime_secs: number;
  clients_total: number;
  clients_enabled: number;
  kernel_module: boolean;
}

/** GET /api/v1/kernel (management_api.rs KernelResponse). */
export interface KernelStatus {
  loaded: boolean;
  device: string;
}

export const auth = {
  async login(username: string, password: string): Promise<{ access_token?: string; totp_required?: boolean }> {
    return apiJson('/web/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  },
  async loginTotp(username: string, password: string, totp_token: string): Promise<{ access_token: string }> {
    return apiJson('/web/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, totp_token }),
    });
  },
  async logout(): Promise<void> {
    await apiFetch('/web/auth/logout', { method: 'POST' });
  },
  async me(): Promise<{ id: number; username: string; role: string; totp_enabled: boolean; passkey_only: boolean }> {
    return apiJson('/web/auth/me');
  },
  // The mutating security endpoints below revoke ALL sessions on success and
  // respond { ok: true, logout: true } — callers must honour the flag by
  // clearing local auth state and returning to /login (the access token dies
  // at the next session_version check anyway; ignoring the flag leaves a
  // dead session that fails on every subsequent request).
  async changePassword(current_password: string, new_password: string): Promise<{ ok: boolean; logout?: boolean }> {
    return apiJson('/web/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password, new_password }),
    });
  },
  async totpSetup(): Promise<{ secret: string; otpauth_url: string; qr_data_url: string }> {
    return apiJson('/web/auth/totp/setup');
  },
  async totpVerify(token: string): Promise<{ ok: boolean; logout?: boolean }> {
    return apiJson('/web/auth/totp/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  },
  async totpDelete(): Promise<{ ok: boolean; logout?: boolean }> {
    return apiJson('/web/auth/totp', { method: 'DELETE' });
  },
  async passkeyRegistrationOptions(): Promise<unknown> {
    return apiJson('/web/auth/passkey/registration-options');
  },
  async passkeyRegister(response: unknown, name: string): Promise<{ ok: boolean; logout?: boolean }> {
    return apiJson('/web/auth/passkey/register', {
      method: 'POST',
      body: JSON.stringify({ response, name }),
    });
  },
  async passkeyAuthOptions(username?: string): Promise<unknown> {
    const q = username ? `?username=${encodeURIComponent(username)}` : '';
    return apiJson(`/web/auth/passkey/authentication-options${q}`);
  },
  async passkeyAuthenticate(response: unknown): Promise<{ access_token: string }> {
    return apiJson('/web/auth/passkey/authenticate', {
      method: 'POST',
      body: JSON.stringify({ response }),
    });
  },
  async passkeys(): Promise<Array<{ id: string; name: string; created_at: string; last_used_at: string | null }>> {
    return apiJson('/web/auth/passkeys');
  },
  async passkeyDelete(id: string): Promise<{ ok: boolean; logout?: boolean }> {
    return apiJson(`/web/auth/passkeys/${id}`, { method: 'DELETE' });
  },
  async sessions(): Promise<Array<{ id: string; ip: string | null; ua: string | null; created_at: string; expires_at: string; current: boolean }>> {
    return apiJson('/web/auth/sessions');
  },
  async sessionDelete(id: string): Promise<void> {
    await apiFetch(`/web/auth/sessions/${id}`, { method: 'DELETE' });
  },
  async sessionsDeleteAll(): Promise<void> {
    await apiFetch('/web/auth/sessions', { method: 'DELETE' });
  },
};

export const metrics = {
  async get(): Promise<Metrics> {
    return apiJson('/web/metrics');
  },
};

export const status = {
  async get(): Promise<ServerStatus> {
    return apiJson('/api/v1/status');
  },
};

export const clients = {
  async list(params?: { search?: string; enabled?: boolean; page?: number; limit?: number }): Promise<{ items: Client[]; total: number }> {
    // GET /api/v1/clients returns the FULL plain array and ignores every query
    // parameter (management_api.rs list_clients takes none) — so search, the
    // enabled filter and pagination are applied HERE, client-side. Client
    // counts are small (single-node VPN), so fetching the full list is fine.
    const raw = await apiJson<Client[]>('/api/v1/clients');
    let items = Array.isArray(raw) ? raw : [];
    if (params?.search) {
      const needle = params.search.toLowerCase();
      items = items.filter((c) =>
        c.name.toLowerCase().includes(needle)
        || c.id.toLowerCase().includes(needle)
        || c.vpn_ip.toLowerCase().includes(needle));
    }
    if (params?.enabled !== undefined) {
      items = items.filter((c) => c.enabled === params.enabled);
    }
    const total = items.length;
    if (params?.limit !== undefined) {
      const page = params.page ?? 0;
      items = items.slice(page * params.limit, (page + 1) * params.limit);
    }
    return { items, total };
  },
  async get(id: string): Promise<Client> {
    return apiJson(`/api/v1/clients/${id}`);
  },
  async create(data: { name: string; one_time?: boolean; expires_at?: string | null; qos?: ClientQos }): Promise<Client> {
    return apiJson('/api/v1/clients', { method: 'POST', body: JSON.stringify(data) });
  },
  async update(id: string, data: { name?: string; enabled?: boolean; one_time?: boolean; expires_at?: string | null; qos?: ClientQos | null; role?: ClientRole; exit_node?: string | null }): Promise<Client> {
    return apiJson(`/api/v1/clients/${id}`, { method: 'PATCH', body: JSON.stringify(data) });
  },
  async delete(id: string): Promise<void> {
    await apiFetch(`/api/v1/clients/${id}`, { method: 'DELETE' });
  },
  /** Admin-only: tombstone the client and force-disconnect any active
   *  session. Distinct from delete() — the daemon retains a revocation
   *  record instead of removing the client outright. Irreversible. */
  async revoke(id: string): Promise<void> {
    const res = await apiFetch(`/api/v1/clients/${id}/revoke`, { method: 'POST' });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || `HTTP ${res.status}`);
    }
  },
  async connectionKey(id: string): Promise<{ connection_key: string }> {
    return apiJson(`/api/v1/clients/${id}/connection-key`);
  },
  async resetDevice(id: string): Promise<void> {
    await apiFetch(`/api/v1/clients/${id}/reset-device`, { method: 'POST' });
  },
};

/** Response of `POST /api/v1/config/apply` (management_api.rs ApplyConfigResponse).
 *  `token` must be passed to `config.confirm()` within the daemon's rollback
 *  window or the write auto-reverts; `applied` reports whether the write
 *  actually landed on disk (apply-with-rollback, not a dry-run). */
export interface ApplyConfigResponse {
  token: string;
  applied: boolean;
}

export const config = {
  async get(): Promise<Record<string, unknown>> {
    return apiJson('/api/v1/config');
  },
  async update(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    return apiJson('/api/v1/config', { method: 'PUT', body: JSON.stringify(data) });
  },
  /**
   * Admin-only: stage the pool-wide default exit node (`pool.exit_node` in
   * server.json) via apply-with-rollback. Pass `addr` as `host:port` to set
   * it, or `null` to disable/clear it. Unlike the per-client override, this
   * does NOT take effect live — it requires a server restart. The returned
   * `token` MUST be confirmed with `config.confirm()` or the daemon
   * auto-reverts the write after its rollback window.
   */
  async applyExit(addr: string | null): Promise<ApplyConfigResponse> {
    return apiJson('/api/v1/config/apply', {
      method: 'POST',
      body: JSON.stringify({ exit_node: addr }),
    });
  },
  /** Confirm a pending apply-with-rollback write (e.g. from `applyExit()`),
   *  making it permanent instead of letting it auto-revert. */
  async confirm(token: string): Promise<void> {
    await apiFetch('/api/v1/config/confirm', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  },
};

export const masks = {
  async list(): Promise<Mask[]> {
    return apiJson('/api/v1/masks');
  },
  async upload(name: string, content: string): Promise<void> {
    await apiFetch(`/api/v1/masks?name=${encodeURIComponent(name)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: content,
    });
  },
  async delete(name: string): Promise<void> {
    await apiFetch(`/api/v1/masks/${encodeURIComponent(name)}`, { method: 'DELETE' });
  },
  /** POST /api/v1/masks/active (management_api.rs set_active_mask / CLI --set-mask
   *  equivalent). `client` accepts either the client's id or its name — the
   *  server resolves by name first, falling back to id. Writes a per-client
   *  override file; the mask must already exist on disk or be a built-in preset. */
  async setActive(client: string, mask: string): Promise<{ ok: boolean; client: string; mask: string }> {
    return apiJson('/api/v1/masks/active', {
      method: 'POST',
      body: JSON.stringify({ client, mask }),
    });
  },
};

/** GET /api/v1/audit-log?verify=1 response shape: the hash-chain is walked
 *  server-side and `verified` reports whether every entry's hash correctly
 *  links to the previous one. `broken_at` is the (0-based) index of the first
 *  entry where the chain no longer verifies, or null when `verified` is true. */
export interface AuditVerifyResponse {
  entries: AuditLogEntry[];
  verified: boolean;
  broken_at: number | null;
}

// Overloads: passing `verify: true` switches the return shape to the
// hash-chain verification envelope; everything else (bare limit, or params
// without verify) keeps the plain-array shape callers already rely on.
// (Overload signatures are only valid on a standalone function/class member —
// not on an object-literal method — hence this is declared outside `auditLog`
// and assigned in below.)
function auditLogList(params: { limit?: number; verify: true }): Promise<AuditVerifyResponse>;
function auditLogList(params?: number | { limit?: number; verify?: false }): Promise<AuditLogEntry[]>;
async function auditLogList(
  params?: number | { limit?: number; verify?: boolean },
): Promise<AuditLogEntry[] | AuditVerifyResponse> {
  const opts = typeof params === 'number' ? { limit: params } : (params ?? {});
  const limit = opts.limit ?? 200;
  const qs = new URLSearchParams({ limit: String(limit) });
  if (opts.verify) qs.set('verify', '1');
  return apiJson(`/api/v1/audit-log?${qs.toString()}`);
}

export const auditLog = {
  list: auditLogList,
};

export const kernel = {
  async get(): Promise<KernelStatus> {
    return apiJson('/api/v1/kernel');
  },
};

export const reload = {
  async trigger(): Promise<void> {
    await apiFetch('/api/v1/reload', { method: 'POST' });
  },
};

/** GET /api/v1/pool/nodes entry (mgmt_service.rs PoolNodeInfo). `verified`
 *  reflects a durable TOFU/pinned Ed25519 binding in NodeRegistry; `connected`
 *  is only ever true for this node's own configured dial-set peers (an
 *  inbound-only peer that dials US has no live-session entry here). */
export interface PoolNodeInfo {
  node_id: string;
  address: string | null;
  verified: boolean;
  revoked: boolean;
  connected: boolean;
  last_seen_unix: number | null;
}

/** GET /api/v1/pool/links entry (mgmt_service.rs PoolLinkInfo). */
export interface PoolLinkInfo {
  peer: string;
  connected: boolean;
  converged: boolean;
  last_converged_unix: number | null;
}

/** GET /api/v1/pool/health (mgmt_service.rs PoolHealth). `transport` is
 *  "masked" (live PoolDialer, real link state below), "legacy" (pool sync
 *  configured but running the mask-independent PeerSyncer — no link state),
 *  or "none" (pool sync isn't configured on this node at all). */
export interface PoolHealth {
  transport: 'masked' | 'legacy' | 'none';
  total_nodes: number;
  connected_peers: number;
  converged_peers: number;
  diverged: boolean;
}

export const pool = {
  async nodes(): Promise<PoolNodeInfo[]> {
    return apiJson('/api/v1/pool/nodes');
  },
  async links(): Promise<PoolLinkInfo[]> {
    return apiJson('/api/v1/pool/links');
  },
  async health(): Promise<PoolHealth> {
    return apiJson('/api/v1/pool/health');
  },
};

export const events = {
  /**
   * Mint a short-lived single-use SSE ticket via an authenticated POST.
   * EventSource cannot set an Authorization header, so the ticket (NOT the
   * general access token) is what goes into the /web/events URL. Each ticket
   * is consumed on connect — mint a fresh one for every (re)connect.
   */
  async ticket(): Promise<string> {
    const data = await apiJson<{ ticket: string }>('/web/events/ticket', { method: 'POST' });
    return data.ticket;
  },
};

export { apiFetch };
