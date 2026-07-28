package com.aivpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * Result of one [AdminApi] call. [status] is 0 when the underlying
 * [AivpnJni.mgmtRequest] call did not complete at all (no active tunnel
 * session, or a timeout) — distinguish that from a real HTTP status by
 * checking [notConnected] before treating [status] as an HTTP code.
 */
data class MgmtResult(val status: Int, val body: String) {
    val ok: Boolean get() = status in 200..299
    val notConnected: Boolean get() = status == 0

    fun bodyObject(): JSONObject? = try { JSONObject(body) } catch (_: Exception) { null }
    fun bodyArray(): JSONArray? = try { JSONArray(body) } catch (_: Exception) { null }
}

/**
 * Thin Kotlin wrapper over the curated management API exposed via
 * [AivpnJni.mgmtRequest]. Every call blocks the calling thread for up to
 * ~10s inside the Rust core, so every method here is a `suspend fun` that
 * hops to [Dispatchers.IO] — never call these from the main thread directly.
 *
 * Mirrors the curated paths documented on [AivpnJni.mgmtRequest]:
 * clients CRUD + revoke + reset-device + connection-key, plus status /
 * audit-log. Role assignment is intentionally NOT exposed here — the
 * server rejects it over the tunnel (see [AivpnJni.getRole]).
 */
object AdminApi {

    private const val METHOD_GET = 0
    private const val METHOD_POST = 1
    private const val METHOD_PATCH = 2
    private const val METHOD_DELETE = 3

    private suspend fun request(method: Int, path: String, body: ByteArray = ByteArray(0)): MgmtResult =
        withContext(Dispatchers.IO) {
            if (!AivpnJni.isAvailable) return@withContext MgmtResult(0, "")
            val raw = try {
                AivpnJni.mgmtRequest(method, path, body)
            } catch (t: Throwable) {
                android.util.Log.e("AdminApi", "mgmtRequest($path) threw", t)
                return@withContext MgmtResult(0, "")
            }
            // `raw` is nullable (the Rust side returns a null jbyteArray instead
            // of panicking across the FFI boundary) and this check sits OUTSIDE
            // the try above — an NPE here would escape withContext, not be
            // reported as "not connected".
            if (raw == null || raw.size < 2) return@withContext MgmtResult(0, "")
            val status = ((raw[0].toInt() and 0xFF) shl 8) or (raw[1].toInt() and 0xFF)
            val bodyBytes = if (raw.size > 2) raw.copyOfRange(2, raw.size) else ByteArray(0)
            MgmtResult(status, String(bodyBytes, Charsets.UTF_8))
        }

    suspend fun listClients(): MgmtResult = request(METHOD_GET, "/api/v1/clients")

    suspend fun addClient(name: String, oneTime: Boolean?, expiresAt: String?): MgmtResult {
        val json = JSONObject().apply {
            put("name", name)
            if (oneTime != null) put("one_time", oneTime)
            if (!expiresAt.isNullOrBlank()) put("expires_at", expiresAt)
        }
        return request(METHOD_POST, "/api/v1/clients", json.toString().toByteArray(Charsets.UTF_8))
    }

    suspend fun getClient(id: String): MgmtResult =
        request(METHOD_GET, "/api/v1/clients/${encode(id)}")

    /**
     * [exitNode] set with [clearExitNode] `false` writes that value as this
     * client's per-client exit-node override (`host:port`). [clearExitNode]
     * `true` sends an explicit JSON `null` for `exit_node`, which clears the
     * override so the client falls back to the server's global default —
     * see `TunnelPatchClientRequest::exit_node`'s doc comment on the server
     * for the double-Option wire semantics this mirrors (omit key = leave
     * unchanged, `null` = clear, string = set).
     *
     * [expiresAt]/[clearExpiresAt] follow the SAME double-Option contract
     * (`TunnelPatchClientRequest::expires_at`): a blank [expiresAt] is
     * OMITTED, never sent as `""` — the server deserializes the value as a
     * `DateTime` and an empty (or "null") string fails that parse, 400-ing
     * the whole PATCH including every other field in it.
     */
    suspend fun patchClient(
        id: String,
        name: String? = null,
        enabled: Boolean? = null,
        oneTime: Boolean? = null,
        expiresAt: String? = null,
        clearExpiresAt: Boolean = false,
        exitNode: String? = null,
        clearExitNode: Boolean = false,
    ): MgmtResult {
        val json = JSONObject().apply {
            if (name != null) put("name", name)
            if (enabled != null) put("enabled", enabled)
            if (oneTime != null) put("one_time", oneTime)
            if (clearExpiresAt) {
                put("expires_at", JSONObject.NULL)
            } else if (!expiresAt.isNullOrBlank()) {
                put("expires_at", expiresAt)
            }
            if (clearExitNode) {
                put("exit_node", JSONObject.NULL)
            } else if (!exitNode.isNullOrBlank()) {
                put("exit_node", exitNode)
            }
        }
        return request(METHOD_PATCH, "/api/v1/clients/${encode(id)}", json.toString().toByteArray(Charsets.UTF_8))
    }

    suspend fun deleteClient(id: String): MgmtResult =
        request(METHOD_DELETE, "/api/v1/clients/${encode(id)}")

    suspend fun revoke(id: String): MgmtResult =
        request(METHOD_POST, "/api/v1/clients/${encode(id)}/revoke")

    suspend fun resetDevice(id: String): MgmtResult =
        request(METHOD_POST, "/api/v1/clients/${encode(id)}/reset-device")

    suspend fun connectionKey(id: String): MgmtResult =
        request(METHOD_GET, "/api/v1/clients/${encode(id)}/connection-key")

    suspend fun status(): MgmtResult = request(METHOD_GET, "/api/v1/status")

    /**
     * `?verify=1` requests the hash-chain-verified shape
     * (`{"entries":[...],"verified":bool,"broken_at":usize|null}`, mirrors
     * server-side `mgmt_service::AuditVerifyView`) instead of the bare
     * entries array — see [AuditLogActivity]. GET-only, so allowed for
     * Viewer and Admin alike (same as [poolNodes]/[poolHealth]).
     */
    suspend fun auditLog(): MgmtResult = request(METHOD_GET, "/api/v1/audit-log?verify=1")

    // ──────────── Pool topology (Wave B3) ────────────
    // Read-only, available to both Viewer and Admin roles — see PoolActivity.

    suspend fun poolNodes(): MgmtResult = request(METHOD_GET, "/api/v1/pool/nodes")

    suspend fun poolHealth(): MgmtResult = request(METHOD_GET, "/api/v1/pool/health")

    suspend fun poolLinks(): MgmtResult = request(METHOD_GET, "/api/v1/pool/links")

    // ──────────── Server settings apply-with-rollback (G-A3) ────────────
    //
    // Both actions below go through the SAME server-side "commit confirmed"
    // flow (mgmt_service::apply_heavy / confirm_config, pending_config.rs):
    // apply writes the new value immediately and returns a one-time token;
    // unless confirmConfig(token) is called within
    // pending_config::PENDING_CONFIG_TIMEOUT (~120s) of the apply, the
    // server's own background sweep rolls the change back automatically.
    // See [ServerSettingsActivity] for the shared apply→countdown→confirm UI.

    /**
     * `POST /api/v1/config/apply` with `{"client":"<id>","mask":"<mask_id>"}`
     * — sets the given client's ACTIVE mask override, which takes effect
     * immediately (no server restart) for that client's new/reconnecting
     * sessions. The active mask is strictly PER-CLIENT: the server writes
     * `.overrides/{client}.mask` and `resolve_heavy_setting`'s `ActiveMask`
     * arm REJECTS an empty `client` with 400 ("fields 'client' and 'mask'
     * are required") — there is no server-wide sentinel. [clientId] may be a
     * client id or name (the server resolves `find_by_name` then
     * `find_by_id`), but must be non-empty.
     */
    suspend fun applyActiveMask(clientId: String, maskId: String): MgmtResult {
        val json = JSONObject().apply {
            put("client", clientId)
            put("mask", maskId)
        }
        return request(METHOD_POST, "/api/v1/config/apply", json.toString().toByteArray(Charsets.UTF_8))
    }

    /**
     * `POST /api/v1/config/apply` with `{"exit_node": addr|null}` — sets the
     * server's GLOBAL default exit node (`pool.exit_node` in `server.json`).
     * Unlike a per-client override ([patchClient]'s `exitNode`, which is
     * live), this global default only takes effect after the server process
     * restarts — see `server_settings_exit_caption`.
     *
     * @param addr `host:port`, or `null` to clear the global default. Always
     *   sends the `exit_node` key (even when `null`) — the server's
     *   `TunnelApplyRequest::exit_node` uses KEY PRESENCE (not the value) to
     *   pick this branch over [applyActiveMask]'s `client`/`mask` shape.
     */
    suspend fun applyGlobalExitNode(addr: String?): MgmtResult {
        val json = JSONObject().apply {
            put("exit_node", if (addr.isNullOrBlank()) JSONObject.NULL else addr)
        }
        return request(METHOD_POST, "/api/v1/config/apply", json.toString().toByteArray(Charsets.UTF_8))
    }

    /**
     * `POST /api/v1/config/confirm` — confirms a pending change from
     * [applyActiveMask] / [applyGlobalExitNode] before its confirm window
     * expires, making it permanent. A non-`ok` result (404/409: unknown or
     * already-expired-and-swept token) means the window already closed and
     * the server already rolled the change back on its own — the caller
     * should treat that the same as a timeout, not retry.
     */
    suspend fun confirmConfig(token: String): MgmtResult {
        val json = JSONObject().apply { put("token", token) }
        return request(METHOD_POST, "/api/v1/config/confirm", json.toString().toByteArray(Charsets.UTF_8))
    }

    /**
     * `GET /api/v1/masks` — lists mask profiles on disk as
     * `[{"id","file","size_bytes","modified","generated"},...]`
     * (`management_api.rs`'s `MaskInfo`).
     *
     * CAVEAT verified against `mgmt_service.rs::classify_route`: this route
     * is NOT in the tunnel's curated allowlist (only `management_api.rs`'s
     * REST/Unix-socket surface exposes it) — over [AivpnJni.mgmtRequest] this
     * call currently always 404s. Kept here as a correct, forward-compatible
     * wrapper of the documented contract (a future server-side allowlist
     * addition needs no Android change to start working); until then,
     * [ServerSettingsActivity] falls back to the mask list the server
     * already pushes to every session — [AivpnJni.getMaskCatalogJson] — the
     * same source [MainActivity]'s mask picker uses.
     */
    suspend fun listMasks(): MgmtResult = request(METHOD_GET, "/api/v1/masks")

    private fun encode(id: String): String =
        java.net.URLEncoder.encode(id, "UTF-8")
}
