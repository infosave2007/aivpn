package com.aivpn.client

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class PoolSnapshotTest {
    @Test fun failedNodesDoNotSendHealthRequest() = runBlocking {
        var healthRequests = 0
        val snapshot = loadPoolSnapshot(
            nodes = { MgmtResult(503, "") },
            health = { healthRequests++; MgmtResult(200, "{}") },
            isCurrent = { true },
        )
        assertEquals(503, snapshot.nodes.status)
        assertNull(snapshot.health)
        assertEquals(0, healthRequests)
    }

    @Test fun failedHealthRemainsAvailableAlongsideLoadedNodes() = runBlocking {
        val snapshot = loadPoolSnapshot(
            nodes = { MgmtResult(200, "[]") },
            health = { MgmtResult(429, """{"code":"rate_limited","retry_after_ms":200}""") },
            isCurrent = { true },
        )
        assertEquals("[]", snapshot.nodes.body)
        assertEquals(429, snapshot.health!!.status)
    }

    @Test fun supersededOrInvalidNodesDoNotSendHealthRequest() = runBlocking {
        var healthRequests = 0
        for ((body, current) in listOf("[]" to false, "{}" to true)) {
            val snapshot = loadPoolSnapshot(
                nodes = { MgmtResult(200, body) },
                health = { healthRequests++; MgmtResult(200, "{}") },
                isCurrent = { current },
            )
            assertNull(snapshot.health)
        }
        assertEquals(0, healthRequests)
    }
}
