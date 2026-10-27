package com.aivpn.client

import org.junit.Assert.*
import org.junit.Test

class AdminErrorTest {
    @Test fun knownServerCodesKeepTheirCauseDespiteGenericStatus() {
        val cases = mapOf(
            "public_endpoint_not_configured" to AdminError.Kind.PUBLIC_ENDPOINT_NOT_CONFIGURED,
            "server_key_not_configured" to AdminError.Kind.SERVER_KEY_NOT_CONFIGURED,
            "invalid_request" to AdminError.Kind.INVALID_REQUEST,
            "forbidden" to AdminError.Kind.FORBIDDEN,
            "not_found" to AdminError.Kind.NOT_FOUND,
            "conflict" to AdminError.Kind.CONFLICT,
            "rate_limited" to AdminError.Kind.RATE_LIMITED,
            "internal_error" to AdminError.Kind.INTERNAL_ERROR,
            "service_unavailable" to AdminError.Kind.SERVICE_UNAVAILABLE,
            "client_database_unavailable" to AdminError.Kind.CLIENT_DATABASE_UNAVAILABLE,
        )
        for ((code, expected) in cases) {
            val error = AdminError.from(MgmtResult(500, """{"code":"$code","message":"Server detail"}"""))
            assertEquals(code, expected, error.kind)
            if (expected == AdminError.Kind.INVALID_REQUEST || expected == AdminError.Kind.CONFLICT) {
                assertEquals("Server detail", error.detail)
            } else assertNull(error.detail)
        }
    }

    @Test fun emptyLegacyBodiesUseSpecificHttpFallbacks() {
        val cases = mapOf(
            0 to AdminError.Kind.UNREACHABLE,
            400 to AdminError.Kind.INVALID_REQUEST,
            403 to AdminError.Kind.FORBIDDEN,
            404 to AdminError.Kind.NOT_FOUND,
            408 to AdminError.Kind.TIMEOUT,
            409 to AdminError.Kind.CONFLICT,
            429 to AdminError.Kind.RATE_LIMITED,
            500 to AdminError.Kind.INTERNAL_ERROR,
            503 to AdminError.Kind.SERVICE_UNAVAILABLE,
            504 to AdminError.Kind.TIMEOUT,
        )
        for ((status, expected) in cases) {
            assertEquals("status $status", expected, AdminError.from(MgmtResult(status, "")).kind)
        }
    }

    @Test fun unknownStructuredCodeUsesTopLevelMessage() {
        val error = AdminError.from(MgmtResult(409, """{"code":"new_server_cause","message":"Confirmation window closed"}"""))
        assertEquals(AdminError.Kind.UNKNOWN, error.kind)
        assertEquals("Confirmation window closed", error.detail)
    }

    @Test fun legacyReasonAndErrorRemainReadable() {
        assertEquals("Client is disabled", AdminError.from(MgmtResult(403, """{"reason":"Client is disabled"}""")).detail)
        assertEquals("Duplicate name", AdminError.from(MgmtResult(409, """{"error":"Duplicate name"}""")).detail)
    }

    @Test fun malformedOrNonStringErrorsDoNotExposeBody() {
        for (body in listOf("secret raw body", """{"error":{"connection_key":"secret"},"message":null}""", """{"reason":"","error":42}""")) {
            val error = AdminError.from(MgmtResult(503, body))
            assertEquals(AdminError.Kind.SERVICE_UNAVAILABLE, error.kind)
            assertNull(error.detail)
        }
    }

    @Test fun retryHintRoundsUpWithoutOverflowAndRejectsInvalidValues() {
        assertEquals(2L, AdminError.from(MgmtResult(429, """{"code":"rate_limited","retry_after_ms":1501}""")).retryAfterSeconds)
        assertEquals(9_223_372_036_854_776L, AdminError.from(MgmtResult(429, """{"retry_after_ms":9223372036854775807}""")).retryAfterSeconds)
        for (value in listOf("0", "-1", "null", "\"500\"", "1.5")) {
            assertNull(AdminError.from(MgmtResult(429, """{"retry_after_ms":$value}""")).retryAfterSeconds)
        }
    }

    @Test fun missingSuccessPayloadHasInvalidResponseMessage() {
        val error = AdminError.from(MgmtResult(200, """{"connection_key":"secret"}"""))
        assertEquals(AdminError.Kind.INVALID_RESPONSE, error.kind)
        assertNull(error.detail)
    }

    @Test fun explicitTimeoutCauseIsDistinctFromUnavailableTunnel() {
        assertEquals(AdminError.Kind.TIMEOUT, AdminError.from(MgmtResult(0, """{"code":"timeout","message":"expired"}""")).kind)
    }

    @Test fun unknownMessageIsBoundedAndHasNoControlCharacters() {
        val error = AdminError.from(MgmtResult(500, """{"code":"future_error","message":"\u0001${"x".repeat(600)}"}"""))
        assertEquals("x".repeat(400), error.detail)
    }
}
