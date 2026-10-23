package com.aivpn.client

import java.util.Base64

internal fun decodeOptionalKey(value: String?, field: String): ByteArray? {
    if (value == null) return null
    val decoded = try {
        Base64.getDecoder().decode(value)
    } catch (_: IllegalArgumentException) {
        throw IllegalArgumentException("$field is not valid base64")
    }
    require(decoded.size == 32) { "$field must contain exactly 32 bytes" }
    return decoded
}
