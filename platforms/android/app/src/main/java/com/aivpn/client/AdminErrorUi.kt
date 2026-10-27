package com.aivpn.client

import android.content.Context

fun Context.managementErrorMessage(result: MgmtResult): String {
    val error = AdminError.from(result)
    val message = when (error.kind) {
        AdminError.Kind.PUBLIC_ENDPOINT_NOT_CONFIGURED -> getString(R.string.admin_error_public_endpoint)
        AdminError.Kind.SERVER_KEY_NOT_CONFIGURED -> getString(R.string.admin_error_server_key)
        AdminError.Kind.INVALID_REQUEST -> getString(R.string.admin_error_invalid_request)
        AdminError.Kind.FORBIDDEN -> getString(R.string.admin_error_forbidden)
        AdminError.Kind.NOT_FOUND -> getString(R.string.admin_error_not_found)
        AdminError.Kind.CONFLICT -> getString(R.string.admin_error_conflict)
        AdminError.Kind.RATE_LIMITED -> getString(R.string.admin_error_rate_limited)
        AdminError.Kind.INTERNAL_ERROR -> getString(R.string.admin_error_internal)
        AdminError.Kind.SERVICE_UNAVAILABLE -> getString(R.string.admin_error_unavailable)
        AdminError.Kind.CLIENT_DATABASE_UNAVAILABLE -> getString(R.string.admin_error_client_database)
        AdminError.Kind.UNREACHABLE -> getString(R.string.admin_error_unreachable)
        AdminError.Kind.TIMEOUT -> getString(R.string.admin_error_timeout)
        AdminError.Kind.INVALID_RESPONSE -> getString(R.string.admin_error_invalid_response)
        AdminError.Kind.UNKNOWN -> if (error.detail != null) {
            getString(R.string.admin_error_with_reason, result.status, error.detail)
        } else {
            getString(R.string.admin_error_generic, result.status)
        }
    }
    val explained = if (error.detail != null && error.kind in listOf(AdminError.Kind.INVALID_REQUEST, AdminError.Kind.CONFLICT)) {
        getString(R.string.admin_error_retry_message, message, error.detail)
    } else message
    return if (error.retryAfterSeconds != null) {
        getString(R.string.admin_error_retry_message, explained, getString(R.string.admin_error_retry_after, error.retryAfterSeconds))
    } else explained
}
