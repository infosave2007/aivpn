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

    suspend fun patchClient(
        id: String,
        name: String? = null,
        enabled: Boolean? = null,
        oneTime: Boolean? = null,
        expiresAt: String? = null,
    ): MgmtResult {
        val json = JSONObject().apply {
            if (name != null) put("name", name)
            if (enabled != null) put("enabled", enabled)
            if (oneTime != null) put("one_time", oneTime)
            if (expiresAt != null) put("expires_at", expiresAt)
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

    private fun encode(id: String): String =
        java.net.URLEncoder.encode(id, "UTF-8")
}
