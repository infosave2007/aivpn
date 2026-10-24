package com.aivpn.client

import java.math.BigInteger
import java.net.InetAddress
import org.junit.Assert.*
import org.junit.Test

class ExcludedRoutesTest {
    @Test fun dispersedIpv6ExclusionsRemainExactAbove4096Routes() {
        val hosts = (0 until 64).map { index ->
            val raw = ByteArray(16) { offset -> (index * 31 + offset * 17).toByte() }
            raw[0] = (0x20 + index % 32).toByte()
            raw[1] = (index * 4).toByte()
            InetAddress.getByAddress(raw)
        }
        val routes = routesAroundExcludedAddresses(hosts, 128)
        assertTrue(routes.size > 4096)
        assertTrue(routes.size <= 64 * 128)
        for (host in hosts) {
            assertFalse(routes.any { contains(it, host) })
            val neighbor = host.address.clone().also { it[15] = (it[15].toInt() xor 1).toByte() }
            assertEquals(1, routes.count { contains(it, InetAddress.getByAddress(neighbor)) })
        }
        assertEquals(1, routes.count { contains(it, InetAddress.getByName("::")) })
        assertEquals(1, routes.count { contains(it, InetAddress.getByName("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) })
    }

    @Test fun dualStackDomainsAndLargeDnsAnswersDoNotRejectTheTunnel() {
        val resolved = DomainExclusionResolver.resolve((1..33).map { "$it.example" }) { domain ->
            val index = domain.substringBefore('.').toInt()
            listOf(InetAddress.getByName("192.0.2.$index"), InetAddress.getByName("2001:db8::${index.toString(16)}"))
        }
        val accepted = boundedExcludedAddresses(resolved)
        assertEquals(66, accepted.size)
        assertTrue(routesAroundExcludedAddresses(accepted, 32).isNotEmpty())
        assertTrue(routesAroundExcludedAddresses(accepted, 128).isNotEmpty())
        assertEquals(64, boundedExcludedAddresses((1..65).map { InetAddress.getByName("192.0.2.$it") }).size)
    }
    @Test fun slowDnsDoesNotBlockTheTunnelAndReadyRepliesSurviveTheDeadline() {
        val start = System.nanoTime()
        val addresses = DomainExclusionResolver.resolve(listOf("slow.example", "fast.example"), 100) { domain ->
            if (domain.startsWith("slow")) Thread.sleep(2_000)
            listOf(InetAddress.getByName(if (domain.startsWith("slow")) "192.0.2.1" else "192.0.2.2"))
        }
        assertTrue(java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1_000)
        assertEquals(listOf("192.0.2.2"), addresses.map { it.hostAddress })
    }
    private fun contains(route: IncludedRoute, value: InetAddress): Boolean {
        val bits = value.address.size * 8
        val base = BigInteger(1, InetAddress.getByName(route.address).address)
        val address = BigInteger(1, value.address)
        return base.shiftRight(bits - route.prefix) == address.shiftRight(bits - route.prefix)
    }

    @Test fun complementExcludesOnlySelectedHostsInBothFamilies() {
        for ((bits, excluded, neighbors) in listOf(
            Triple(32, "10.8.0.1", listOf("0.0.0.0", "10.8.0.0", "10.8.0.2", "255.255.255.255")),
            Triple(128, "2001:db8::1", listOf("::", "2001:db8::", "2001:db8::2", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")))) {
            val host = InetAddress.getByName(excluded)
            val routes = routesAroundExcludedAddresses(listOf(host, host), bits)
            assertFalse(routes.any { contains(it, host) })
            for (neighbor in neighbors) assertEquals(1, routes.count { contains(it, InetAddress.getByName(neighbor)) })
            assertEquals(bits, routes.size)
        }
    }

    @Test fun noExclusionsKeepTheDefaultRouteAndAdjacentExclusionsStayExcluded() {
        assertEquals(listOf(IncludedRoute("0.0.0.0", 0)), routesAroundExcludedAddresses(emptyList(), 32))
        val hosts = listOf("10.8.0.0", "10.8.0.1", "10.8.0.2").map { InetAddress.getByName(it) }
        val routes = routesAroundExcludedAddresses(hosts, 32)
        for (host in hosts) assertFalse(routes.any { contains(it, host) })
        assertEquals(1, routes.count { contains(it, InetAddress.getByName("10.8.0.3")) })
    }
}
