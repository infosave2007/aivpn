package com.aivpn.client

import org.json.JSONObject

data class AdminError(val kind: Kind, val detail: String? = null, val retryAfterSeconds: Long? = null) {
    enum class Kind {
        PUBLIC_ENDPOINT_NOT_CONFIGURED, SERVER_KEY_NOT_CONFIGURED, INVALID_REQUEST,
        FORBIDDEN, NOT_FOUND, CONFLICT, RATE_LIMITED, INTERNAL_ERROR, SERVICE_UNAVAILABLE,
        UNREACHABLE, TIMEOUT, INVALID_RESPONSE, UNKNOWN,
        CLIENT_DATABASE_UNAVAILABLE,
    }

    companion object {
        fun from(result: MgmtResult): AdminError {
            if (result.ok) return AdminError(Kind.INVALID_RESPONSE)
            val body = result.bodyObject()
            val kind = when (body?.text("code")) {
                "public_endpoint_not_configured" -> Kind.PUBLIC_ENDPOINT_NOT_CONFIGURED
                "server_key_not_configured" -> Kind.SERVER_KEY_NOT_CONFIGURED
                "invalid_request" -> Kind.INVALID_REQUEST
                "forbidden" -> Kind.FORBIDDEN
                "not_found" -> Kind.NOT_FOUND
                "conflict" -> Kind.CONFLICT
                "rate_limited" -> Kind.RATE_LIMITED
                "internal_error" -> Kind.INTERNAL_ERROR
                "service_unavailable" -> Kind.SERVICE_UNAVAILABLE
                "client_database_unavailable" -> Kind.CLIENT_DATABASE_UNAVAILABLE
                "timeout", "request_timeout" -> Kind.TIMEOUT
                else -> null
            }
            val detail = if (kind == null || kind == Kind.INVALID_REQUEST || kind == Kind.CONFLICT) {
                body?.text("message") ?: body?.text("reason") ?: body?.text("error")
            } else null
            val fallback = when (result.status) {
                0 -> Kind.UNREACHABLE
                400 -> Kind.INVALID_REQUEST
                403 -> Kind.FORBIDDEN
                404 -> Kind.NOT_FOUND
                408, 504 -> Kind.TIMEOUT
                409 -> Kind.CONFLICT
                429 -> Kind.RATE_LIMITED
                500 -> Kind.INTERNAL_ERROR
                503 -> Kind.SERVICE_UNAVAILABLE
                else -> Kind.UNKNOWN
            }
            val resolved = kind ?: if (detail != null) Kind.UNKNOWN else fallback
            val retryMs = (body?.opt("retry_after_ms") as? Number)
                ?.takeIf { it is Int || it is Long }
                ?.toLong()?.takeIf { it > 0 }
            val retrySeconds = if (resolved == Kind.RATE_LIMITED && retryMs != null) {
                retryMs / 1000 + if (retryMs % 1000 > 0) 1 else 0
            } else null
            return AdminError(resolved, detail, retrySeconds)
        }

        private fun JSONObject.text(key: String): String? =
            (opt(key) as? String)?.filterNot { it.isISOControl() }?.trim()
                ?.takeIf { it.isNotEmpty() }?.take(400)
    }
}
