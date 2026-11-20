package com.aivpn.client

import java.io.IOException
import java.io.InputStream
import org.junit.Assert.*
import org.junit.Test

class BootstrapResponseTest {
    @Test fun oversizedUnknownLengthStopsAtTheBoundary() {
        var consumed = 0
        val input = object : InputStream() {
            override fun read(): Int = if (consumed++ < BootstrapResponse.MAX_BYTES * 2) 65 else -1
        }
        assertThrows(IOException::class.java) { BootstrapResponse.read(input) }
        assertTrue(consumed <= BootstrapResponse.MAX_BYTES + 1)
    }

    @Test fun exactLimitAndMultibyteTextArePreserved() {
        val text = "я".repeat(BootstrapResponse.MAX_BYTES / 2)
        assertEquals(text, BootstrapResponse.read(text.byteInputStream()))
        assertEquals("", BootstrapResponse.read(byteArrayOf().inputStream()))
    }

    @Test fun readFailureIsNotPresentedAsCompleteJson() {
        val input = object : InputStream() {
            override fun read(): Int = throw IOException("test")
        }
        assertThrows(IOException::class.java) { BootstrapResponse.read(input) }
    }
}
