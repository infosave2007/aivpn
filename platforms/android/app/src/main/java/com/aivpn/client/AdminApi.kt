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
            if (raw.size < 2) return@withContext MgmtResult(0, "")
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
     */
    suspend fun patchClient(
        id: String,
        name: String? = null,
        enabled: Boolean? = null,
        oneTime: Boolean? = null,
        expiresAt: String? = null,
        exitNode: String? = null,
        clearExitNode: Boolean = false,
    ): MgmtResult {
        val json = JSONObject().apply {
            if (name != null) put("name", name)
            if (enabled != null) put("enabled", enabled)
            if (oneTime != null) put("one_time", oneTime)
            if (expiresAt != null) put("expires_at", expiresAt)
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

    suspend fun auditLog(): MgmtResult = request(METHOD_GET, "/api/v1/audit-log")

    // ──────────── Pool topology (Wave B3) ────────────
    // Read-only, available to both Viewer and Admin roles — see PoolActivity.

    suspend fun poolNodes(): MgmtResult = request(METHOD_GET, "/api/v1/pool/nodes")

    suspend fun poolHealth(): MgmtResult = request(METHOD_GET, "/api/v1/pool/health")

    suspend fun poolLinks(): MgmtResult = request(METHOD_GET, "/api/v1/pool/links")

    // ──────────── Backup export/import (Migration wizard, C3) ────────────
    //
    // `export_backup` returns `application/gzip` bytes (a tar.gz archive —
    // see `aivpn-server/src/backup.rs`), NOT UTF-8 text, so these two go
    // straight to raw `AivpnJni.mgmtRequest` bytes rather than through
    // [request]/[MgmtResult] above, which lossily decodes the body as a
    // UTF-8 `String` (fine for the JSON bodies every other curated route
    // returns, but would corrupt a binary archive).
    //
    // IMPORTANT: as of this writing, `/api/v1/backup/export` and
    // `/api/v1/backup/import` are NOT in the server's curated in-tunnel
    // allowlist (`mgmt_service.rs::classify_route` — see its doc comment:
    // "no `backup/import`... off the tunnel", by design, on both routes).
    // These calls are real (not mocked) and will reach the gateway, but
    // `authorize`/`classify_route` currently reject them for every role,
    // so expect a non-2xx/empty result until the server-side dispatch
    // table is extended to cover backup export/import. [MigrationActivity]
    // surfaces whatever the server actually returns rather than assuming
    // success.

    private const val PATH_BACKUP_EXPORT = "/api/v1/backup/export"
    private const val PATH_BACKUP_IMPORT = "/api/v1/backup/import"

    /**
     * @return `(status, bodyBytes)`. `status` is `0` when [AivpnJni.mgmtRequest]
     *         did not complete at all (no active tunnel / timeout / throw) —
     *         same convention as [MgmtResult.notConnected].
     */
    suspend fun exportBackupRaw(): Pair<Int, ByteArray> = rawRequest(METHOD_GET, PATH_BACKUP_EXPORT, ByteArray(0))

    /** @return `(status, bodyBytes)` — see [exportBackupRaw]. */
    suspend fun importBackupRaw(archiveBytes: ByteArray): Pair<Int, ByteArray> =
        rawRequest(METHOD_POST, PATH_BACKUP_IMPORT, archiveBytes)

    private suspend fun rawRequest(method: Int, path: String, body: ByteArray): Pair<Int, ByteArray> =
        withContext(Dispatchers.IO) {
            if (!AivpnJni.isAvailable) return@withContext 0 to ByteArray(0)
            val raw = try {
                AivpnJni.mgmtRequest(method, path, body)
            } catch (t: Throwable) {
                android.util.Log.e("AdminApi", "mgmtRequest($path) threw", t)
                return@withContext 0 to ByteArray(0)
            }
            if (raw.size < 2) return@withContext 0 to ByteArray(0)
            val status = ((raw[0].toInt() and 0xFF) shl 8) or (raw[1].toInt() and 0xFF)
            val bodyBytes = if (raw.size > 2) raw.copyOfRange(2, raw.size) else ByteArray(0)
            status to bodyBytes
        }

    private fun encode(id: String): String =
        java.net.URLEncoder.encode(id, "UTF-8")
}
