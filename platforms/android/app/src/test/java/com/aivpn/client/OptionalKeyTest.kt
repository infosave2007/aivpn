package com.aivpn.client

import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class OptionalKeyTest {
    @Test fun absentIsOptionalButMalformedIsFatal() {
        for (field in listOf("p", "sk", "mop")) {
            assertNull(decodeOptionalKey(null, field))
            assertEquals(32, decodeOptionalKey(Base64.getEncoder().encodeToString(ByteArray(32)), field)!!.size)
            for (bad in listOf("bad!", "", Base64.getEncoder().encodeToString(ByteArray(31)), Base64.getEncoder().encodeToString(ByteArray(33)))) {
                assertTrue("$field must reject malformed material", runCatching { decodeOptionalKey(bad, field) }.isFailure)
            }
        }
    }
}
