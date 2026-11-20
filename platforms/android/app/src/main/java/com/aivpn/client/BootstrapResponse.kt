package com.aivpn.client

import java.io.InputStream
import java.io.ByteArrayOutputStream
import java.io.IOException

internal object BootstrapResponse {
    const val MAX_BYTES = 4 * 1024 * 1024

    fun read(input: InputStream): String {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer, 0, minOf(buffer.size, MAX_BYTES - output.size() + 1))
            if (count < 0) return output.toString(Charsets.UTF_8.name())
            if (count > MAX_BYTES - output.size()) throw IOException("Bootstrap response too large")
            output.write(buffer, 0, count)
        }
    }
}
